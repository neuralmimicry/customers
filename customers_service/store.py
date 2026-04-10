from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from werkzeug.security import check_password_hash, generate_password_hash

UTC = dt.timezone.utc
DEFAULT_ACCESS_TOKEN_TTL_SECONDS = int(
    os.getenv("CUSTOMERS_ACCESS_TOKEN_TTL")
    or os.getenv("REFINER_ACCESS_TOKEN_TTL")
    or "43200"
)
DEFAULT_SSO_TOKEN_TTL_SECONDS = int(
    os.getenv("CUSTOMERS_SSO_TTL")
    or os.getenv("REFINER_SSO_TTL")
    or "300"
)

SCHEMA_STATEMENTS: Sequence[str] = (
    """
    CREATE TABLE IF NOT EXISTS nm_users (
        username TEXT PRIMARY KEY,
        password_hash TEXT,
        role TEXT NOT NULL DEFAULT 'user',
        email TEXT,
        external BOOLEAN NOT NULL DEFAULT FALSE,
        provider TEXT,
        subject TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_users_provider_subject_idx
        ON nm_users (provider, subject)
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_auth_tokens (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL REFERENCES nm_users(username) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        token_hint TEXT,
        label TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ,
        last_used_at TIMESTAMPTZ,
        disabled BOOLEAN NOT NULL DEFAULT FALSE,
        one_time BOOLEAN NOT NULL DEFAULT FALSE,
        meta JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_auth_tokens_kind_user_idx
        ON nm_auth_tokens (kind, username)
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_auth_tokens_kind_expires_idx
        ON nm_auth_tokens (kind, expires_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_token_accounts (
        scope TEXT NOT NULL,
        account_id TEXT NOT NULL,
        balance INTEGER NOT NULL DEFAULT 0,
        paid_balance INTEGER NOT NULL DEFAULT 0,
        free_balance INTEGER NOT NULL DEFAULT 0,
        last_topup_tokens INTEGER NOT NULL DEFAULT 0,
        last_topup_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ,
        spent_total BIGINT NOT NULL DEFAULT 0,
        cashout_total BIGINT NOT NULL DEFAULT 0,
        shortfall_total BIGINT NOT NULL DEFAULT 0,
        free_grant_total BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (scope, account_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_token_ledger_entries (
        id BIGSERIAL PRIMARY KEY,
        scope TEXT NOT NULL,
        account_id TEXT NOT NULL,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        entry_type TEXT NOT NULL,
        delta INTEGER NOT NULL,
        balance_after INTEGER NOT NULL,
        meta JSONB NOT NULL DEFAULT '{}'::jsonb,
        request_id TEXT
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS nm_token_ledger_request_idx
        ON nm_token_ledger_entries (scope, account_id, request_id)
        WHERE request_id IS NOT NULL
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_token_ledger_lookup_idx
        ON nm_token_ledger_entries (scope, account_id, ts DESC, id DESC)
    """,
)


def _timestamp(value: Optional[dt.datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_hint(token: str) -> Optional[str]:
    cleaned = str(token or "").strip()
    if not cleaned:
        return None
    if len(cleaned) <= 8:
        return cleaned
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def _jsonb(value: Optional[Dict[str, Any]] = None) -> Jsonb:
    return Jsonb(value or {})


def _default_account_summary() -> Dict[str, Any]:
    return {
        "version": 1,
        "balance": 0,
        "paid_balance": 0,
        "free_balance": 0,
        "last_topup_tokens": 0,
        "last_topup_at": None,
        "updated_at": None,
        "spent_total": 0,
        "cashout_total": 0,
        "shortfall_total": 0,
        "free_grant_total": 0,
    }


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def _write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass


def central_store_dsn_from_env(prefix: str = "CUSTOMERS_DB") -> str:
    explicit = (
        os.getenv(f"{prefix}_DSN")
        or os.getenv("CUSTOMERS_POSTGRES_DSN")
        or os.getenv("REFINER_AUTH_DB_DSN")
        or os.getenv("REFINER_POSTGRES_DSN")
        or ""
    ).strip()
    if explicit:
        return explicit

    host = (
        os.getenv(f"{prefix}_HOST")
        or os.getenv("CUSTOMERS_POSTGRES_HOST")
        or os.getenv("REFINER_AUTH_DB_HOST")
        or os.getenv("REFINER_POSTGRES_HOST")
        or ""
    ).strip()
    user = (
        os.getenv(f"{prefix}_USER")
        or os.getenv("CUSTOMERS_POSTGRES_USER")
        or os.getenv("REFINER_AUTH_DB_USER")
        or os.getenv("REFINER_POSTGRES_USER")
        or ""
    ).strip()
    password = (
        os.getenv(f"{prefix}_PASSWORD")
        or os.getenv("CUSTOMERS_POSTGRES_PASSWORD")
        or os.getenv("REFINER_AUTH_DB_PASSWORD")
        or os.getenv("REFINER_POSTGRES_PASSWORD")
        or ""
    ).strip()
    dbname = (
        os.getenv(f"{prefix}_NAME")
        or os.getenv(f"{prefix}_DB")
        or os.getenv("CUSTOMERS_POSTGRES_DB")
        or os.getenv("REFINER_AUTH_DB_NAME")
        or os.getenv("REFINER_POSTGRES_DB")
        or ""
    ).strip()
    port = (
        os.getenv(f"{prefix}_PORT")
        or os.getenv("CUSTOMERS_POSTGRES_PORT")
        or os.getenv("REFINER_AUTH_DB_PORT")
        or os.getenv("REFINER_POSTGRES_PORT")
        or "5432"
    ).strip()
    sslmode = (
        os.getenv(f"{prefix}_SSLMODE")
        or os.getenv("CUSTOMERS_POSTGRES_SSLMODE")
        or os.getenv("REFINER_AUTH_DB_SSLMODE")
        or os.getenv("REFINER_POSTGRES_SSLMODE")
        or "disable"
    ).strip()
    connect_timeout = (
        os.getenv(f"{prefix}_CONNECT_TIMEOUT")
        or os.getenv("CUSTOMERS_POSTGRES_CONNECT_TIMEOUT")
        or os.getenv("REFINER_AUTH_DB_CONNECT_TIMEOUT")
        or "5"
    ).strip()
    if not host or not user or not dbname:
        return ""
    parts = [
        f"host={host}",
        f"port={port or '5432'}",
        f"user={user}",
        f"dbname={dbname}",
        f"sslmode={sslmode or 'disable'}",
        f"connect_timeout={connect_timeout or '5'}",
        "application_name=customers",
    ]
    if password:
        parts.append(f"password={password}")
    return " ".join(parts)


class PostgresCentralStore:
    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 4, timeout: float = 10.0):
        self.dsn = dsn
        self.pool = ConnectionPool(
            conninfo=dsn,
            min_size=max(1, int(min_size)),
            max_size=max(1, int(max_size)),
            timeout=max(1.0, float(timeout)),
            kwargs={"row_factory": dict_row},
        )
        self.pool.wait()
        self.ensure_schema()
        self.users = PostgresUserStore(self)
        self.access_tokens = PostgresAccessTokenStore(self)
        self.voice_tokens = PostgresVoiceTokenStore(self)
        self.sso_tokens = PostgresSsoStore(self)
        self.user_ledger = PostgresTokenLedger(self, "user")
        self.team_ledger = PostgresTokenLedger(self, "team")

    def close(self) -> None:
        self.pool.close()

    def ensure_schema(self) -> None:
        with self.pool.connection() as conn:
            with conn.transaction():
                for statement in SCHEMA_STATEMENTS:
                    conn.execute(statement)

    def bootstrap_from_env(self, default_user: str = "") -> None:
        raw = (
            os.getenv("CUSTOMERS_BOOTSTRAP_ACCESS_TOKENS")
            or os.getenv("REFINER_BOOTSTRAP_ACCESS_TOKENS")
            or ""
        ).strip()
        if not raw:
            return
        try:
            payload = json.loads(raw)
        except Exception:
            return
        if not isinstance(payload, list):
            return
        for item in payload:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token") or "").strip()
            username = str(item.get("user") or default_user or "").strip()
            if not token or not username:
                continue
            role = str(item.get("role") or "user").strip() or "user"
            label = str(item.get("label") or "").strip() or None
            ttl_seconds = item.get("ttl_seconds")
            meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
            self.users.ensure_user(username, role=role)
            self.access_tokens.ensure_token(
                username,
                token,
                label=label,
                ttl_seconds=int(ttl_seconds) if ttl_seconds not in (None, "") else None,
                meta=meta,
            )


class PostgresUserStore:
    def __init__(self, store: PostgresCentralStore):
        self.store = store
        self.lock = threading.RLock()

    def count_users(self) -> int:
        with self.store.pool.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM nm_users").fetchone()
        return int((row or {}).get("count") or 0)

    def has_users(self) -> bool:
        return self.count_users() > 0

    def ensure_user(self, username: str, *, role: str = "user", email: Optional[str] = None) -> None:
        username = str(username or "").strip()
        if not username:
            return
        with self.store.pool.connection() as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO nm_users (username, role, email, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (username) DO UPDATE
                    SET role = COALESCE(NULLIF(EXCLUDED.role, ''), nm_users.role),
                        email = COALESCE(EXCLUDED.email, nm_users.email),
                        updated_at = NOW()
                    """,
                    (username, role or "user", email),
                )

    def ensure_admin_from_env(self) -> None:
        admin_user = (os.getenv("CUSTOMERS_ADMIN_USER") or os.getenv("REFINER_ADMIN_USER") or "").strip()
        admin_pass = (
            os.getenv("CUSTOMERS_ADMIN_PASS")
            or os.getenv("CUSTOMERS_ADMIN_PASSWORD")
            or os.getenv("REFINER_ADMIN_PASS")
            or os.getenv("REFINER_ADMIN_PASSWORD")
            or ""
        ).strip()
        admin_email = (
            os.getenv("CUSTOMERS_ADMIN_EMAIL")
            or os.getenv("REFINER_ADMIN_EMAIL")
            or ""
        ).strip() or None
        if not admin_user or not admin_pass:
            return
        if self.has_users():
            return
        self.create_user(admin_user, admin_pass, role="admin", email=admin_email)

    def create_user(self, username: str, password: str, role: str = "user", email: Optional[str] = None) -> None:
        username = str(username or "").strip()
        if not username:
            raise ValueError("username is required")
        password_hash = generate_password_hash(password)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO nm_users (
                        username,
                        password_hash,
                        role,
                        email,
                        external,
                        provider,
                        subject,
                        created_at,
                        updated_at,
                        metadata
                    ) VALUES (%s, %s, %s, %s, FALSE, NULL, NULL, NOW(), NOW(), '{}'::jsonb)
                    ON CONFLICT (username) DO UPDATE
                    SET password_hash = EXCLUDED.password_hash,
                        role = EXCLUDED.role,
                        email = COALESCE(EXCLUDED.email, nm_users.email),
                        external = FALSE,
                        provider = NULL,
                        subject = NULL,
                        updated_at = NOW()
                    """,
                    (username, password_hash, role or "user", email),
                )

    def upsert_external_user(
        self,
        username: str,
        *,
        role: str = "user",
        email: Optional[str] = None,
        provider: str = "oidc",
        subject: Optional[str] = None,
    ) -> None:
        username = str(username or "").strip()
        if not username:
            return
        with self.store.pool.connection() as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO nm_users (
                        username,
                        password_hash,
                        role,
                        email,
                        external,
                        provider,
                        subject,
                        created_at,
                        updated_at,
                        metadata
                    ) VALUES (%s, NULL, %s, %s, TRUE, %s, %s, NOW(), NOW(), '{}'::jsonb)
                    ON CONFLICT (username) DO UPDATE
                    SET role = EXCLUDED.role,
                        email = COALESCE(EXCLUDED.email, nm_users.email),
                        external = TRUE,
                        provider = COALESCE(EXCLUDED.provider, nm_users.provider),
                        subject = COALESCE(EXCLUDED.subject, nm_users.subject),
                        updated_at = NOW()
                    """,
                    (username, role or "user", email, provider or None, subject),
                )

    def set_email(self, username: str, email: Optional[str]) -> bool:
        username = str(username or "").strip()
        if not username:
            return False
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE nm_users
                    SET email = %s,
                        updated_at = NOW()
                    WHERE username = %s
                    RETURNING username
                    """,
                    (email, username),
                ).fetchone()
        return bool(row)

    def get_email(self, username: str) -> Optional[str]:
        username = str(username or "").strip()
        if not username:
            return None
        with self.store.pool.connection() as conn:
            row = conn.execute(
                "SELECT email FROM nm_users WHERE username = %s",
                (username,),
            ).fetchone()
        value = (row or {}).get("email")
        return str(value).strip() if value else None

    def verify(self, username: str, password: str) -> bool:
        username = str(username or "").strip()
        if not username:
            return False
        with self.store.pool.connection() as conn:
            row = conn.execute(
                "SELECT password_hash FROM nm_users WHERE username = %s",
                (username,),
            ).fetchone()
        password_hash = (row or {}).get("password_hash")
        if not password_hash:
            return False
        try:
            return check_password_hash(str(password_hash), password)
        except Exception:
            return False

    def get_role(self, username: str) -> Optional[str]:
        username = str(username or "").strip()
        if not username:
            return None
        with self.store.pool.connection() as conn:
            row = conn.execute(
                "SELECT role FROM nm_users WHERE username = %s",
                (username,),
            ).fetchone()
        value = (row or {}).get("role")
        return str(value).strip() if value else None


class PostgresAccessTokenStore:
    def __init__(self, store: PostgresCentralStore):
        self.store = store

    def _issue(
        self,
        username: str,
        *,
        kind: str,
        label: Optional[str] = None,
        ttl_seconds: Optional[int] = DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        meta: Optional[Dict[str, Any]] = None,
        one_time: bool = False,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        username = str(username or "").strip()
        if not username:
            raise ValueError("username is required")
        raw_token = token or secrets.token_urlsafe(32)
        token_id = uuid.uuid4().hex
        expires_at = None
        if ttl_seconds not in (None, ""):
            ttl_value = max(30, int(ttl_seconds))
            expires_at = dt.datetime.now(UTC) + dt.timedelta(seconds=ttl_value)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO nm_users (username, role, updated_at)
                    VALUES (%s, 'user', NOW())
                    ON CONFLICT (username) DO NOTHING
                    """,
                    (username,),
                )
                row = conn.execute(
                    """
                    INSERT INTO nm_auth_tokens (
                        id,
                        username,
                        kind,
                        token_hash,
                        token_hint,
                        label,
                        created_at,
                        expires_at,
                        last_used_at,
                        disabled,
                        one_time,
                        meta
                    ) VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, NULL, FALSE, %s, %s)
                    ON CONFLICT (token_hash) DO UPDATE
                    SET username = EXCLUDED.username,
                        kind = EXCLUDED.kind,
                        token_hint = EXCLUDED.token_hint,
                        label = COALESCE(EXCLUDED.label, nm_auth_tokens.label),
                        expires_at = COALESCE(EXCLUDED.expires_at, nm_auth_tokens.expires_at),
                        disabled = FALSE,
                        one_time = EXCLUDED.one_time,
                        meta = COALESCE(EXCLUDED.meta, nm_auth_tokens.meta)
                    RETURNING id, username, label, created_at, expires_at, kind
                    """,
                    (
                        token_id,
                        username,
                        kind,
                        _hash_token(raw_token),
                        _token_hint(raw_token),
                        label,
                        expires_at,
                        bool(one_time),
                        _jsonb(meta),
                    ),
                ).fetchone()
        return {
            "token": raw_token,
            "id": (row or {}).get("id") or token_id,
            "user": (row or {}).get("username") or username,
            "label": (row or {}).get("label") or label,
            "created_at": _timestamp((row or {}).get("created_at")) or _timestamp(dt.datetime.now(UTC)),
            "expires_at": _timestamp((row or {}).get("expires_at")) or _timestamp(expires_at),
            "kind": (row or {}).get("kind") or kind,
        }

    def issue(
        self,
        username: str,
        *,
        label: Optional[str] = None,
        ttl_seconds: Optional[int] = DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        meta: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._issue(
            username,
            kind="access",
            label=label,
            ttl_seconds=ttl_seconds,
            meta=meta,
            one_time=False,
            token=token,
        )

    def ensure_token(
        self,
        username: str,
        token: str,
        *,
        label: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._issue(
            username,
            kind="access",
            label=label,
            ttl_seconds=ttl_seconds,
            meta=meta,
            one_time=False,
            token=token,
        )

    def verify(self, token: str) -> Optional[Dict[str, Any]]:
        cleaned = str(token or "").strip()
        if not cleaned:
            return None
        token_hash = _hash_token(cleaned)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE nm_auth_tokens AS t
                    SET last_used_at = NOW()
                    FROM nm_users AS u
                    WHERE t.token_hash = %s
                      AND t.kind = 'access'
                      AND NOT t.disabled
                      AND NOT t.one_time
                      AND (t.expires_at IS NULL OR t.expires_at > NOW())
                      AND u.username = t.username
                    RETURNING t.id, t.username, t.kind, t.label, t.created_at, t.expires_at, t.meta, u.role
                    """,
                    (token_hash,),
                ).fetchone()
        if not row:
            return None
        return {
            "id": row.get("id"),
            "user": row.get("username"),
            "kind": row.get("kind"),
            "label": row.get("label"),
            "role": row.get("role"),
            "created_at": _timestamp(row.get("created_at")),
            "expires_at": _timestamp(row.get("expires_at")),
            "meta": row.get("meta") if isinstance(row.get("meta"), dict) else {},
        }


class PostgresVoiceTokenStore:
    def __init__(self, store: PostgresCentralStore):
        self.store = store

    def issue(self, user: str, label: Optional[str] = None) -> Dict[str, Any]:
        return self.store.access_tokens._issue(
            user,
            kind="voice",
            label=label,
            ttl_seconds=None,
            meta={"purpose": "voice"},
            one_time=False,
        )

    def verify(self, token: str) -> Optional[str]:
        cleaned = str(token or "").strip()
        if not cleaned:
            return None
        token_hash = _hash_token(cleaned)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE nm_auth_tokens
                    SET last_used_at = NOW()
                    WHERE token_hash = %s
                      AND kind = 'voice'
                      AND NOT disabled
                      AND NOT one_time
                      AND (expires_at IS NULL OR expires_at > NOW())
                    RETURNING username
                    """,
                    (token_hash,),
                ).fetchone()
        username = (row or {}).get("username")
        return str(username).strip() if username else None

    def list_tokens(self, user: Optional[str] = None) -> List[Dict[str, Any]]:
        params: List[Any] = []
        sql = """
            SELECT id, username, label, created_at, last_used_at, disabled
            FROM nm_auth_tokens
            WHERE kind = 'voice'
        """
        if user:
            sql += " AND username = %s"
            params.append(user)
        sql += " ORDER BY created_at DESC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": row.get("id"),
                "user": row.get("username"),
                "label": row.get("label"),
                "created_at": _timestamp(row.get("created_at")),
                "last_used_at": _timestamp(row.get("last_used_at")),
                "disabled": bool(row.get("disabled")),
            }
            for row in rows or []
        ]

    def revoke(self, token_id: str) -> bool:
        cleaned = str(token_id or "").strip()
        if not cleaned:
            return False
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE nm_auth_tokens
                    SET disabled = TRUE
                    WHERE id = %s AND kind = 'voice'
                    RETURNING id
                    """,
                    (cleaned,),
                ).fetchone()
        return bool(row)


class PostgresSsoStore:
    type_name = "postgres"

    def __init__(self, store: PostgresCentralStore, ttl_seconds: int = DEFAULT_SSO_TOKEN_TTL_SECONDS):
        self.store = store
        self.ttl_seconds = max(30, int(ttl_seconds))

    def issue(self, user: str) -> str:
        issued = self.store.access_tokens._issue(
            user,
            kind="sso",
            ttl_seconds=self.ttl_seconds,
            meta={"purpose": "sso"},
            one_time=True,
        )
        return str(issued.get("token") or "")

    def consume(self, token: str) -> Optional[str]:
        cleaned = str(token or "").strip()
        if not cleaned:
            return None
        token_hash = _hash_token(cleaned)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    DELETE FROM nm_auth_tokens
                    WHERE token_hash = %s
                      AND kind = 'sso'
                      AND NOT disabled
                      AND one_time
                      AND (expires_at IS NULL OR expires_at > NOW())
                    RETURNING username
                    """,
                    (token_hash,),
                ).fetchone()
        username = (row or {}).get("username")
        return str(username).strip() if username else None

    def health(self) -> Dict[str, Any]:
        try:
            with self.store.pool.connection() as conn:
                conn.execute("SELECT 1")
            return {"type": self.type_name, "ok": True}
        except Exception as exc:
            return {"type": self.type_name, "ok": False, "error": str(exc)}


class PostgresTokenLedger:
    def __init__(self, store: PostgresCentralStore, scope: str):
        self.store = store
        self.scope = scope

    def _account_summary(self, row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        summary = _default_account_summary()
        if not row:
            return summary
        summary.update(
            {
                "balance": int(row.get("balance") or 0),
                "paid_balance": int(row.get("paid_balance") or 0),
                "free_balance": int(row.get("free_balance") or 0),
                "last_topup_tokens": int(row.get("last_topup_tokens") or 0),
                "last_topup_at": _timestamp(row.get("last_topup_at")),
                "updated_at": _timestamp(row.get("updated_at")),
                "spent_total": int(row.get("spent_total") or 0),
                "cashout_total": int(row.get("cashout_total") or 0),
                "shortfall_total": int(row.get("shortfall_total") or 0),
                "free_grant_total": int(row.get("free_grant_total") or 0),
            }
        )
        return summary

    def get_summary(self, account_id: str) -> Dict[str, Any]:
        cleaned = str(account_id or "").strip()
        if not cleaned:
            return _default_account_summary()
        with self.store.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM nm_token_accounts
                WHERE scope = %s AND account_id = %s
                """,
                (self.scope, cleaned),
            ).fetchone()
        return self._account_summary(row)

    def list_entries(self, account_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        cleaned = str(account_id or "").strip()
        if not cleaned:
            return []
        limit_value = max(1, min(int(limit), 500))
        with self.store.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT ts, entry_type, delta, balance_after, meta
                FROM nm_token_ledger_entries
                WHERE scope = %s AND account_id = %s
                ORDER BY ts DESC, id DESC
                LIMIT %s
                """,
                (self.scope, cleaned, limit_value),
            ).fetchall()
        return [
            {
                "ts": _timestamp(row.get("ts")),
                "type": row.get("entry_type"),
                "user": cleaned,
                "delta": int(row.get("delta") or 0),
                "balance_after": int(row.get("balance_after") or 0),
                "meta": row.get("meta") if isinstance(row.get("meta"), dict) else {},
                "shortfall": int(((row.get("meta") if isinstance(row.get("meta"), dict) else {}) or {}).get("shortfall") or 0),
            }
            for row in rows or []
        ]

    def record(
        self,
        account_id: str,
        entry_type: str,
        delta: int,
        meta: Optional[Dict[str, Any]] = None,
        *,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        cleaned = str(account_id or "").strip()
        if not cleaned:
            raise ValueError("account_id is required")
        meta_dict = dict(meta or {})
        with self.store.pool.connection() as conn:
            with conn.transaction():
                if request_id:
                    existing = conn.execute(
                        """
                        SELECT ts, entry_type, delta, balance_after, meta
                        FROM nm_token_ledger_entries
                        WHERE scope = %s AND account_id = %s AND request_id = %s
                        """,
                        (self.scope, cleaned, request_id),
                    ).fetchone()
                    if existing:
                        existing_meta = existing.get("meta") if isinstance(existing.get("meta"), dict) else {}
                        return {
                            "ts": _timestamp(existing.get("ts")),
                            "type": existing.get("entry_type"),
                            "user": cleaned,
                            "delta": int(existing.get("delta") or 0),
                            "balance_after": int(existing.get("balance_after") or 0),
                            "meta": existing_meta,
                            "shortfall": int((existing_meta or {}).get("shortfall") or 0),
                        }

                conn.execute(
                    """
                    INSERT INTO nm_token_accounts (scope, account_id)
                    VALUES (%s, %s)
                    ON CONFLICT (scope, account_id) DO NOTHING
                    """,
                    (self.scope, cleaned),
                )
                account = conn.execute(
                    """
                    SELECT *
                    FROM nm_token_accounts
                    WHERE scope = %s AND account_id = %s
                    FOR UPDATE
                    """,
                    (self.scope, cleaned),
                ).fetchone()
                summary = self._account_summary(account)
                paid_balance = int(summary.get("paid_balance") or summary.get("balance") or 0)
                free_balance = int(summary.get("free_balance") or 0)
                balance = paid_balance + free_balance
                requested_delta = int(delta or 0)
                new_paid = paid_balance
                new_free = free_balance
                shortfall = 0
                kind = str(entry_type or "adjust").strip().lower() or "adjust"

                if kind == "topup":
                    if requested_delta > 0:
                        new_paid += requested_delta
                    else:
                        requested_delta = 0
                elif kind == "refund":
                    if requested_delta > 0:
                        new_paid += requested_delta
                    else:
                        requested_delta = 0
                elif kind == "grant":
                    if requested_delta > 0:
                        new_free += requested_delta
                    else:
                        requested_delta = 0
                elif kind == "cashout":
                    if requested_delta >= 0:
                        requested_delta = -abs(requested_delta)
                    desired = abs(requested_delta)
                    paid_used = min(new_paid, desired)
                    new_paid -= paid_used
                    shortfall = desired - paid_used
                    if shortfall:
                        meta_dict["shortfall"] = shortfall
                    requested_delta = -paid_used
                    meta_dict["paid_used"] = paid_used
                    meta_dict["free_used"] = 0
                    meta_dict["used_total"] = paid_used
                elif kind == "debit":
                    if requested_delta >= 0:
                        requested_delta = -abs(requested_delta or 0)
                    desired = abs(requested_delta)
                    free_used = min(new_free, desired)
                    new_free -= free_used
                    remaining = desired - free_used
                    paid_used = min(new_paid, remaining)
                    new_paid -= paid_used
                    shortfall = remaining - paid_used
                    if shortfall:
                        meta_dict["shortfall"] = shortfall
                    meta_dict["free_used"] = free_used
                    meta_dict["paid_used"] = paid_used
                    meta_dict["used_total"] = free_used + paid_used
                    requested_delta = -(free_used + paid_used)
                elif kind in {"reserve", "release"}:
                    requested_delta = 0
                elif kind == "sync":
                    target_paid = meta_dict.get("target_paid_balance")
                    target_free = meta_dict.get("target_free_balance")
                    target_balance = meta_dict.get("target_balance")
                    if target_paid is not None or target_free is not None:
                        if target_paid is not None:
                            new_paid = max(0, int(target_paid or 0))
                        if target_free is not None:
                            new_free = max(0, int(target_free or 0))
                    else:
                        if target_balance is None:
                            target_balance = balance + requested_delta
                        try:
                            target_balance = int(float(target_balance))
                        except Exception:
                            target_balance = balance
                        target_balance = max(0, target_balance)
                        if target_balance >= new_free:
                            new_paid = target_balance - new_free
                        else:
                            new_free = target_balance
                            new_paid = 0
                    requested_delta = (new_paid + new_free) - balance

                if requested_delta == 0 and kind not in {"reserve", "release", "sync"}:
                    kind = "adjust"

                new_balance = max(0, new_paid + new_free)
                meta_dict["paid_after"] = new_paid
                meta_dict["free_after"] = new_free

                now = dt.datetime.now(UTC)
                spent_total = int(summary.get("spent_total") or 0)
                cashout_total = int(summary.get("cashout_total") or 0)
                shortfall_total = int(summary.get("shortfall_total") or 0)
                free_grant_total = int(summary.get("free_grant_total") or 0)
                last_topup_tokens = int(summary.get("last_topup_tokens") or 0)
                last_topup_at = account.get("last_topup_at") if account else None

                if kind == "topup":
                    last_topup_tokens = int((meta_dict or {}).get("tokens") or abs(requested_delta) or 0)
                    last_topup_at = now
                if kind == "sync":
                    capacity = meta_dict.get("capacity")
                    if capacity is not None:
                        try:
                            last_topup_tokens = int(capacity or 0)
                            last_topup_at = now
                        except Exception:
                            pass
                if kind == "debit":
                    spent_total += int(meta_dict.get("used_total") or abs(requested_delta) or 0)
                    shortfall_total += int(meta_dict.get("shortfall") or 0)
                if kind == "cashout":
                    cashout_total += abs(requested_delta)
                if kind == "grant":
                    free_grant_total += abs(requested_delta)

                entry_row = conn.execute(
                    """
                    INSERT INTO nm_token_ledger_entries (
                        scope,
                        account_id,
                        ts,
                        entry_type,
                        delta,
                        balance_after,
                        meta,
                        request_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING ts, entry_type, delta, balance_after, meta
                    """,
                    (
                        self.scope,
                        cleaned,
                        now,
                        kind,
                        requested_delta,
                        new_balance,
                        _jsonb(meta_dict),
                        request_id,
                    ),
                ).fetchone()
                conn.execute(
                    """
                    UPDATE nm_token_accounts
                    SET balance = %s,
                        paid_balance = %s,
                        free_balance = %s,
                        last_topup_tokens = %s,
                        last_topup_at = %s,
                        updated_at = %s,
                        spent_total = %s,
                        cashout_total = %s,
                        shortfall_total = %s,
                        free_grant_total = %s
                    WHERE scope = %s AND account_id = %s
                    """,
                    (
                        new_balance,
                        new_paid,
                        new_free,
                        last_topup_tokens,
                        last_topup_at,
                        now,
                        spent_total,
                        cashout_total,
                        shortfall_total,
                        free_grant_total,
                        self.scope,
                        cleaned,
                    ),
                )
        entry_meta = entry_row.get("meta") if isinstance(entry_row.get("meta"), dict) else meta_dict
        return {
            "ts": _timestamp(entry_row.get("ts")),
            "type": entry_row.get("entry_type"),
            "user": cleaned,
            "delta": int(entry_row.get("delta") or 0),
            "balance_after": int(entry_row.get("balance_after") or 0),
            "meta": entry_meta,
            "shortfall": int((entry_meta or {}).get("shortfall") or 0),
        }

class FileUserStore:
    """File-backed user registry for development or recovery-mode bootstraps."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data = _read_json(path, {})
        if not isinstance(self.data, dict):
            self.data = {}

    def _write(self) -> None:
        _write_json_atomic(self.path, self.data)

    def count_users(self) -> int:
        with self.lock:
            return len(self.data)

    def has_users(self) -> bool:
        return self.count_users() > 0

    def ensure_user(self, username: str, *, role: str = "user", email: Optional[str] = None) -> None:
        username = str(username or "").strip()
        if not username:
            return
        with self.lock:
            entry = self.data.get(username, {})
            entry.setdefault("created_at", _timestamp(dt.datetime.now(UTC)))
            entry["role"] = role or entry.get("role") or "user"
            if email is not None:
                entry["email"] = email
            entry["updated_at"] = _timestamp(dt.datetime.now(UTC))
            self.data[username] = entry
            self._write()

    def ensure_admin_from_env(self) -> None:
        admin_user = (os.getenv("CUSTOMERS_ADMIN_USER") or "").strip()
        admin_pass = (
            os.getenv("CUSTOMERS_ADMIN_PASS")
            or os.getenv("CUSTOMERS_ADMIN_PASSWORD")
            or os.getenv("REFINER_ADMIN_PASS")
            or os.getenv("REFINER_ADMIN_PASSWORD")
            or ""
        ).strip()
        admin_email = (
            os.getenv("CUSTOMERS_ADMIN_EMAIL")
            or os.getenv("REFINER_ADMIN_EMAIL")
            or ""
        ).strip() or None
        if not admin_user or not admin_pass or self.has_users():
            return
        self.create_user(admin_user, admin_pass, role="admin", email=admin_email)

    def create_user(self, username: str, password: str, role: str = "user", email: Optional[str] = None) -> None:
        username = str(username or "").strip()
        if not username:
            raise ValueError("username is required")
        now = _timestamp(dt.datetime.now(UTC))
        with self.lock:
            self.data[username] = {
                "password_hash": generate_password_hash(password),
                "role": role or "user",
                "email": email,
                "external": False,
                "provider": None,
                "subject": None,
                "created_at": now,
                "updated_at": now,
            }
            self._write()

    def upsert_external_user(
        self,
        username: str,
        *,
        role: str = "user",
        email: Optional[str] = None,
        provider: str = "oidc",
        subject: Optional[str] = None,
    ) -> None:
        username = str(username or "").strip()
        if not username:
            return
        now = _timestamp(dt.datetime.now(UTC))
        with self.lock:
            entry = self.data.get(username, {})
            entry.setdefault("created_at", now)
            entry["updated_at"] = now
            entry["role"] = role or "user"
            entry["email"] = email
            entry["external"] = True
            entry["provider"] = provider or "oidc"
            entry["subject"] = subject
            self.data[username] = entry
            self._write()

    def set_email(self, username: str, email: Optional[str]) -> bool:
        username = str(username or "").strip()
        if not username:
            return False
        with self.lock:
            entry = self.data.get(username)
            if not isinstance(entry, dict):
                return False
            entry["email"] = email
            entry["updated_at"] = _timestamp(dt.datetime.now(UTC))
            self._write()
            return True

    def get_email(self, username: str) -> Optional[str]:
        with self.lock:
            entry = self.data.get(str(username or "").strip()) or {}
            value = entry.get("email")
        return str(value).strip() if value else None

    def verify(self, username: str, password: str) -> bool:
        username = str(username or "").strip()
        if not username:
            return False
        with self.lock:
            entry = self.data.get(username) or {}
            password_hash = entry.get("password_hash")
        if not password_hash:
            return False
        try:
            return check_password_hash(str(password_hash), password)
        except Exception:
            return False

    def get_role(self, username: str) -> Optional[str]:
        with self.lock:
            entry = self.data.get(str(username or "").strip()) or {}
            value = entry.get("role")
        return str(value).strip() if value else None


class FileTokenStore:
    """JSON-backed auth token store used when PostgreSQL is unavailable."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        payload = _read_json(path, {"tokens": []})
        if not isinstance(payload, dict):
            payload = {"tokens": []}
        tokens = payload.get("tokens")
        if not isinstance(tokens, list):
            payload["tokens"] = []
        self.data = payload

    def _write(self) -> None:
        _write_json_atomic(self.path, self.data)

    def _now(self) -> dt.datetime:
        return dt.datetime.now(UTC)

    def _entry_expired(self, entry: Dict[str, Any], now: Optional[dt.datetime] = None) -> bool:
        raw = entry.get("expires_at")
        if not raw:
            return False
        cleaned = str(raw).strip()
        if not cleaned:
            return False
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            expires_at = dt.datetime.fromisoformat(cleaned)
        except Exception:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at <= (now or self._now())

    def _issue(
        self,
        username: str,
        *,
        kind: str,
        label: Optional[str] = None,
        ttl_seconds: Optional[int] = DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        meta: Optional[Dict[str, Any]] = None,
        one_time: bool = False,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        username = str(username or "").strip()
        if not username:
            raise ValueError("username is required")
        raw_token = token or secrets.token_urlsafe(32)
        token_id = uuid.uuid4().hex
        now = self._now()
        expires_at = None
        if ttl_seconds not in (None, ""):
            expires_at = now + dt.timedelta(seconds=max(30, int(ttl_seconds)))
        entry = {
            "id": token_id,
            "username": username,
            "kind": kind,
            "token_hash": _hash_token(raw_token),
            "token_hint": _token_hint(raw_token),
            "label": label,
            "created_at": _timestamp(now),
            "expires_at": _timestamp(expires_at),
            "last_used_at": None,
            "disabled": False,
            "one_time": bool(one_time),
            "meta": dict(meta or {}),
        }
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
            replaced = False
            for idx, existing in enumerate(tokens):
                if existing.get("token_hash") == entry["token_hash"]:
                    tokens[idx] = entry
                    replaced = True
                    break
            if not replaced:
                tokens.append(entry)
            self.data["tokens"] = tokens
            self._write()
        return {
            "token": raw_token,
            "id": token_id,
            "user": username,
            "label": label,
            "created_at": entry["created_at"],
            "expires_at": entry["expires_at"],
            "kind": kind,
        }

    def issue(
        self,
        username: str,
        *,
        label: Optional[str] = None,
        ttl_seconds: Optional[int] = DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        meta: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._issue(
            username,
            kind="access",
            label=label,
            ttl_seconds=ttl_seconds,
            meta=meta,
            token=token,
        )

    def ensure_token(
        self,
        username: str,
        token: str,
        *,
        label: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._issue(
            username,
            kind="access",
            label=label,
            ttl_seconds=ttl_seconds,
            meta=meta,
            token=token,
        )

    def verify(self, token: str) -> Optional[Dict[str, Any]]:
        cleaned = str(token or "").strip()
        if not cleaned:
            return None
        token_hash = _hash_token(cleaned)
        now = self._now()
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
            for entry in tokens:
                if entry.get("token_hash") != token_hash:
                    continue
                if entry.get("kind") != "access" or entry.get("disabled") or entry.get("one_time"):
                    return None
                if self._entry_expired(entry, now):
                    return None
                entry["last_used_at"] = _timestamp(now)
                self.data["tokens"] = tokens
                self._write()
                return {
                    "id": entry.get("id"),
                    "user": entry.get("username"),
                    "kind": entry.get("kind"),
                    "label": entry.get("label"),
                    "created_at": entry.get("created_at"),
                    "expires_at": entry.get("expires_at"),
                    "meta": dict(entry.get("meta") or {}),
                }
        return None

    def consume_one_time(self, kind: str, token: str) -> Optional[str]:
        cleaned = str(token or "").strip()
        if not cleaned:
            return None
        token_hash = _hash_token(cleaned)
        now = self._now()
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
            for idx, entry in enumerate(tokens):
                if entry.get("token_hash") != token_hash or entry.get("kind") != kind:
                    continue
                if entry.get("disabled") or not entry.get("one_time") or self._entry_expired(entry, now):
                    return None
                user = str(entry.get("username") or "").strip() or None
                tokens.pop(idx)
                self.data["tokens"] = tokens
                self._write()
                return user
        return None

    def issue_voice(self, username: str, *, label: Optional[str] = None) -> Dict[str, Any]:
        return self._issue(
            username,
            kind="voice",
            label=label,
            ttl_seconds=None,
            meta={"purpose": "voice"},
        )

    def verify_voice(self, token: str) -> Optional[str]:
        cleaned = str(token or "").strip()
        if not cleaned:
            return None
        token_hash = _hash_token(cleaned)
        now = self._now()
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
            for entry in tokens:
                if entry.get("token_hash") != token_hash or entry.get("kind") != "voice":
                    continue
                if entry.get("disabled") or entry.get("one_time") or self._entry_expired(entry, now):
                    return None
                entry["last_used_at"] = _timestamp(now)
                self.data["tokens"] = tokens
                self._write()
                username = str(entry.get("username") or "").strip()
                return username or None
        return None

    def list_voice_tokens(self, user: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
        rows = []
        for entry in tokens:
            if entry.get("kind") != "voice":
                continue
            if user and entry.get("username") != user:
                continue
            rows.append(
                {
                    "id": entry.get("id"),
                    "user": entry.get("username"),
                    "label": entry.get("label"),
                    "created_at": entry.get("created_at"),
                    "last_used_at": entry.get("last_used_at"),
                    "disabled": bool(entry.get("disabled")),
                }
            )
        rows.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return rows

    def revoke_voice(self, token_id: str) -> bool:
        cleaned = str(token_id or "").strip()
        if not cleaned:
            return False
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
            updated = False
            for entry in tokens:
                if entry.get("id") == cleaned and entry.get("kind") == "voice":
                    if entry.get("disabled"):
                        break
                    entry["disabled"] = True
                    entry["updated_at"] = _timestamp(self._now())
                    updated = True
                    break
            if updated:
                self.data["tokens"] = tokens
                self._write()
            return updated


class FileVoiceTokenStore:
    def __init__(self, tokens: FileTokenStore):
        self.tokens = tokens

    def issue(self, user: str, label: Optional[str] = None) -> Dict[str, Any]:
        return self.tokens.issue_voice(user, label=label)

    def verify(self, token: str) -> Optional[str]:
        return self.tokens.verify_voice(token)

    def list_tokens(self, user: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.tokens.list_voice_tokens(user)

    def revoke(self, token_id: str) -> bool:
        return self.tokens.revoke_voice(token_id)


class FileSsoStore:
    type_name = "file"

    def __init__(self, tokens: FileTokenStore, ttl_seconds: int = DEFAULT_SSO_TOKEN_TTL_SECONDS):
        self.tokens = tokens
        self.ttl_seconds = max(30, int(ttl_seconds))

    def issue(self, user: str) -> str:
        issued = self.tokens._issue(
            user,
            kind="sso",
            ttl_seconds=self.ttl_seconds,
            meta={"purpose": "sso"},
            one_time=True,
        )
        return str(issued.get("token") or "")

    def consume(self, token: str) -> Optional[str]:
        return self.tokens.consume_one_time("sso", token)

    def health(self) -> Dict[str, Any]:
        return {"type": self.type_name, "ok": True}


class FileStoreBundle:
    """Bundle exposing the same store surface as the PostgreSQL-backed store."""

    store_type = "file"

    def __init__(self, root: str):
        base = Path(root).expanduser().resolve()
        base.mkdir(parents=True, exist_ok=True)
        self.base_dir = base
        self.users = FileUserStore(base / "users.json")
        self.access_tokens = FileTokenStore(base / "auth_tokens.json")
        self.voice_tokens = FileVoiceTokenStore(self.access_tokens)
        self.sso_tokens = FileSsoStore(self.access_tokens)

    def close(self) -> None:
        return None

    def bootstrap_from_env(self, default_user: str = "") -> None:
        raw = (
            os.getenv("CUSTOMERS_BOOTSTRAP_ACCESS_TOKENS")
            or os.getenv("REFINER_BOOTSTRAP_ACCESS_TOKENS")
            or ""
        ).strip()
        if not raw:
            return
        try:
            payload = json.loads(raw)
        except Exception:
            return
        if not isinstance(payload, list):
            return
        for item in payload:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token") or "").strip()
            username = str(item.get("user") or default_user or "").strip()
            if not token or not username:
                continue
            role = str(item.get("role") or "user").strip() or "user"
            label = str(item.get("label") or "").strip() or None
            ttl_seconds = item.get("ttl_seconds")
            meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
            self.users.ensure_user(username, role=role)
            self.access_tokens.ensure_token(
                username,
                token,
                label=label,
                ttl_seconds=int(ttl_seconds) if ttl_seconds not in (None, "") else None,
                meta=meta,
            )


def create_central_store_from_env() -> Optional[object]:
    dsn = central_store_dsn_from_env()
    if dsn:
        min_size = int(
            os.getenv("CUSTOMERS_DB_POOL_MIN")
            or os.getenv("REFINER_AUTH_DB_POOL_MIN")
            or "1"
        )
        max_size = int(
            os.getenv("CUSTOMERS_DB_POOL_MAX")
            or os.getenv("REFINER_AUTH_DB_POOL_MAX")
            or "4"
        )
        timeout = float(
            os.getenv("CUSTOMERS_DB_POOL_TIMEOUT")
            or os.getenv("REFINER_AUTH_DB_POOL_TIMEOUT")
            or "10"
        )
        return PostgresCentralStore(dsn, min_size=min_size, max_size=max_size, timeout=timeout)
    state_dir = os.getenv("CUSTOMERS_STATE_DIR") or "data"
    return FileStoreBundle(state_dir)
