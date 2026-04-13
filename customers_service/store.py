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
ALLOWED_USER_ROLES = frozenset({"admin", "user"})
ALLOWED_TEAM_MEMBERSHIP_ROLES = frozenset({"owner", "member"})
TEAM_MEMBERSHIP_STATUS_PENDING = "pending"
TEAM_MEMBERSHIP_STATUS_ACTIVE = "active"
TEAM_MEMBERSHIP_STATUS_REJECTED = "rejected"
TEAM_MEMBERSHIP_STATUS_LEFT = "left"
TEAM_MEMBERSHIP_STATUS_REVOKED = "revoked"

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
    CREATE TABLE IF NOT EXISTS nm_teams (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        parent_id TEXT REFERENCES nm_teams(id) ON DELETE SET NULL,
        owner_username TEXT NOT NULL REFERENCES nm_users(username) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_teams_parent_idx
        ON nm_teams (parent_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_teams_owner_idx
        ON nm_teams (owner_username)
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_team_memberships (
        id TEXT PRIMARY KEY,
        team_id TEXT NOT NULL REFERENCES nm_teams(id) ON DELETE CASCADE,
        username TEXT NOT NULL REFERENCES nm_users(username) ON DELETE CASCADE,
        membership_role TEXT NOT NULL DEFAULT 'member'
            CHECK (membership_role IN ('owner', 'member')),
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'active', 'rejected', 'left', 'revoked')),
        invited_by TEXT REFERENCES nm_users(username) ON DELETE SET NULL,
        invited_at TIMESTAMPTZ,
        responded_at TIMESTAMPTZ,
        joined_at TIMESTAMPTZ,
        left_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS nm_team_memberships_team_user_idx
        ON nm_team_memberships (team_id, username)
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_team_memberships_user_status_idx
        ON nm_team_memberships (username, status, updated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_team_memberships_team_status_idx
        ON nm_team_memberships (team_id, status, updated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_team_memberships_invited_by_status_idx
        ON nm_team_memberships (invited_by, status, updated_at DESC)
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


def _normalize_user_role(value: Optional[str]) -> str:
    cleaned = str(value or "user").strip().lower() or "user"
    if cleaned not in ALLOWED_USER_ROLES:
        raise ValueError("invalid_role")
    return cleaned


def _normalize_team_membership_role(value: Optional[str]) -> str:
    cleaned = str(value or "member").strip().lower() or "member"
    if cleaned not in ALLOWED_TEAM_MEMBERSHIP_ROLES:
        raise ValueError("invalid_membership_role")
    return cleaned


def _normalize_statuses(values: Optional[Sequence[str]]) -> List[str]:
    if not values:
        return []
    cleaned: List[str] = []
    seen = set()
    for value in values:
        item = str(value or "").strip().lower()
        if not item or item in seen:
            continue
        cleaned.append(item)
        seen.add(item)
    return cleaned


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
        self.teams = PostgresTeamStore(self)
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

    @staticmethod
    def _payload_from_row(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        username = str(row.get("username") or "").strip()
        if not username:
            return None
        role = str(row.get("role") or "user").strip() or "user"
        return {
            "username": username,
            "role": role,
            "groups": [role],
            "email": str(row.get("email") or "").strip() or None,
            "external": bool(row.get("external")),
            "provider": str(row.get("provider") or "").strip() or None,
            "subject": str(row.get("subject") or "").strip() or None,
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
            "has_password": bool(row.get("password_hash")),
        }

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
        role_value = _normalize_user_role(role)
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
                    (username, role_value, email),
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
        role_value = _normalize_user_role(role)
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
                    (username, password_hash, role_value, email),
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
        role_value = _normalize_user_role(role)
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
                    (username, role_value, email, provider or None, subject),
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

    def set_password(self, username: str, password: str) -> bool:
        username = str(username or "").strip()
        if not username:
            return False
        password_hash = generate_password_hash(password)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE nm_users
                    SET password_hash = %s,
                        updated_at = NOW()
                    WHERE username = %s
                    RETURNING username
                    """,
                    (password_hash, username),
                ).fetchone()
        return bool(row)

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        username = str(username or "").strip()
        if not username:
            return None
        with self.store.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT username, password_hash, role, email, external, provider, subject, created_at, updated_at
                FROM nm_users
                WHERE username = %s
                """,
                (username,),
            ).fetchone()
        return self._payload_from_row(row)

    def list_users(self) -> List[Dict[str, Any]]:
        with self.store.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT username, password_hash, role, email, external, provider, subject, created_at, updated_at
                FROM nm_users
                ORDER BY username ASC
                """
            ).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._payload_from_row(row)
            if entry:
                payload.append(entry)
        return payload


class PostgresTeamStore:
    def __init__(self, store: PostgresCentralStore):
        self.store = store

    @staticmethod
    def _team_payload(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        team_id = str(row.get("id") or "").strip()
        if not team_id:
            return None
        return {
            "id": team_id,
            "name": str(row.get("name") or "").strip() or f"Team {team_id[:6]}",
            "parent_id": str(row.get("parent_id") or "").strip() or None,
            "owner": str(row.get("owner_username") or "").strip() or None,
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
            "member_count": int(row.get("member_count") or 0),
        }

    @staticmethod
    def _membership_payload(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        membership_id = str(row.get("id") or "").strip()
        if not membership_id:
            return None
        membership_role = str(row.get("membership_role") or "member").strip() or "member"
        status = str(row.get("status") or TEAM_MEMBERSHIP_STATUS_PENDING).strip() or TEAM_MEMBERSHIP_STATUS_PENDING
        return {
            "id": membership_id,
            "team_id": str(row.get("team_id") or "").strip() or None,
            "team_name": str(row.get("team_name") or "").strip() or None,
            "team_parent_id": str(row.get("team_parent_id") or "").strip() or None,
            "team_owner": str(row.get("team_owner") or "").strip() or None,
            "username": str(row.get("username") or "").strip() or None,
            "membership_role": membership_role,
            "status": status,
            "is_owner": membership_role == "owner",
            "invited_by": str(row.get("invited_by") or "").strip() or None,
            "invited_at": _timestamp(row.get("invited_at")),
            "responded_at": _timestamp(row.get("responded_at")),
            "joined_at": _timestamp(row.get("joined_at")),
            "left_at": _timestamp(row.get("left_at")),
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
        }

    def _team_exists(self, conn: Any, team_id: str) -> bool:
        row = conn.execute("SELECT id FROM nm_teams WHERE id = %s", (team_id,)).fetchone()
        return bool((row or {}).get("id"))

    def _user_exists(self, conn: Any, username: str) -> bool:
        row = conn.execute("SELECT username FROM nm_users WHERE username = %s", (username,)).fetchone()
        return bool((row or {}).get("username"))

    def _active_team_row_for_user(self, conn: Any, username: str) -> Optional[Dict[str, Any]]:
        return conn.execute(
            """
            SELECT m.id, m.team_id, t.name AS team_name
            FROM nm_team_memberships AS m
            JOIN nm_teams AS t ON t.id = m.team_id
            WHERE m.username = %s
              AND m.status = %s
            ORDER BY m.updated_at DESC, m.created_at DESC, m.id DESC
            LIMIT 1
            """,
            (username, TEAM_MEMBERSHIP_STATUS_ACTIVE),
        ).fetchone()

    def _membership_select(self) -> str:
        return """
            SELECT
                m.id,
                m.team_id,
                t.name AS team_name,
                t.parent_id AS team_parent_id,
                t.owner_username AS team_owner,
                m.username,
                m.membership_role,
                m.status,
                m.invited_by,
                m.invited_at,
                m.responded_at,
                m.joined_at,
                m.left_at,
                m.created_at,
                m.updated_at
            FROM nm_team_memberships AS m
            JOIN nm_teams AS t ON t.id = m.team_id
        """

    def list_teams(self) -> List[Dict[str, Any]]:
        with self.store.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    t.id,
                    t.name,
                    t.parent_id,
                    t.owner_username,
                    t.created_at,
                    t.updated_at,
                    COUNT(m.id) FILTER (WHERE m.status = %s) AS member_count
                FROM nm_teams AS t
                LEFT JOIN nm_team_memberships AS m ON m.team_id = t.id
                GROUP BY t.id, t.name, t.parent_id, t.owner_username, t.created_at, t.updated_at
                ORDER BY t.name ASC, t.id ASC
                """,
                (TEAM_MEMBERSHIP_STATUS_ACTIVE,),
            ).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._team_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def get_team(self, team_id: str) -> Optional[Dict[str, Any]]:
        cleaned = str(team_id or "").strip()
        if not cleaned:
            return None
        with self.store.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT
                    t.id,
                    t.name,
                    t.parent_id,
                    t.owner_username,
                    t.created_at,
                    t.updated_at,
                    COUNT(m.id) FILTER (WHERE m.status = %s) AS member_count
                FROM nm_teams AS t
                LEFT JOIN nm_team_memberships AS m ON m.team_id = t.id
                WHERE t.id = %s
                GROUP BY t.id, t.name, t.parent_id, t.owner_username, t.created_at, t.updated_at
                """,
                (TEAM_MEMBERSHIP_STATUS_ACTIVE, cleaned),
            ).fetchone()
        return self._team_payload(row)

    def get_membership(self, membership_id: str) -> Optional[Dict[str, Any]]:
        cleaned = str(membership_id or "").strip()
        if not cleaned:
            return None
        query = self._membership_select() + " WHERE m.id = %s"
        with self.store.pool.connection() as conn:
            row = conn.execute(query, (cleaned,)).fetchone()
        return self._membership_payload(row)

    def list_user_memberships(self, username: str, *, statuses: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        cleaned = str(username or "").strip()
        if not cleaned:
            return []
        query = self._membership_select() + " WHERE m.username = %s"
        params: List[Any] = [cleaned]
        status_values = _normalize_statuses(statuses)
        if status_values:
            query += " AND m.status = ANY(%s)"
            params.append(status_values)
        query += " ORDER BY m.updated_at DESC, m.created_at DESC, m.id DESC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._membership_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def list_invitations_sent_by(self, username: str, *, statuses: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        cleaned = str(username or "").strip()
        if not cleaned:
            return []
        query = self._membership_select() + " WHERE m.invited_by = %s"
        params: List[Any] = [cleaned]
        status_values = _normalize_statuses(statuses)
        if status_values:
            query += " AND m.status = ANY(%s)"
            params.append(status_values)
        query += " ORDER BY m.updated_at DESC, m.created_at DESC, m.id DESC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._membership_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def list_team_members(self, team_id: str, *, statuses: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        cleaned = str(team_id or "").strip()
        if not cleaned:
            return []
        query = self._membership_select() + " WHERE m.team_id = %s"
        params: List[Any] = [cleaned]
        status_values = _normalize_statuses(statuses)
        if status_values:
            query += " AND m.status = ANY(%s)"
            params.append(status_values)
        query += " ORDER BY m.membership_role ASC, m.username ASC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._membership_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def team_role_for_user(self, username: str, team_id: str) -> Optional[str]:
        cleaned_user = str(username or "").strip()
        cleaned_team = str(team_id or "").strip()
        if not cleaned_user or not cleaned_team:
            return None
        with self.store.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT membership_role
                FROM nm_team_memberships
                WHERE username = %s
                  AND team_id = %s
                  AND status = %s
                LIMIT 1
                """,
                (cleaned_user, cleaned_team, TEAM_MEMBERSHIP_STATUS_ACTIVE),
            ).fetchone()
        value = (row or {}).get("membership_role")
        return str(value).strip() if value else None

    def create_team(
        self,
        name: str,
        *,
        owner_username: str,
        parent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        owner = str(owner_username or "").strip()
        if not owner:
            raise ValueError("owner_required")
        cleaned_parent = str(parent_id or "").strip() or None
        team_name = str(name or "").strip()
        team_id = uuid.uuid4().hex
        membership_id = uuid.uuid4().hex
        with self.store.pool.connection() as conn:
            with conn.transaction():
                if not self._user_exists(conn, owner):
                    raise ValueError("user_not_found")
                if self._active_team_row_for_user(conn, owner):
                    raise ValueError("user_already_in_team")
                if cleaned_parent and not self._team_exists(conn, cleaned_parent):
                    raise ValueError("parent_team_not_found")
                conn.execute(
                    """
                    INSERT INTO nm_teams (id, name, parent_id, owner_username, created_at, updated_at, metadata)
                    VALUES (%s, %s, %s, %s, NOW(), NOW(), '{}'::jsonb)
                    """,
                    (team_id, team_name or f"Team {team_id[:6]}", cleaned_parent, owner),
                )
                conn.execute(
                    """
                    INSERT INTO nm_team_memberships (
                        id,
                        team_id,
                        username,
                        membership_role,
                        status,
                        invited_by,
                        invited_at,
                        responded_at,
                        joined_at,
                        left_at,
                        created_at,
                        updated_at,
                        metadata
                    ) VALUES (%s, %s, %s, 'owner', %s, %s, NOW(), NOW(), NOW(), NULL, NOW(), NOW(), '{}'::jsonb)
                    """,
                    (
                        membership_id,
                        team_id,
                        owner,
                        TEAM_MEMBERSHIP_STATUS_ACTIVE,
                        owner,
                    ),
                )
        team = self.get_team(team_id)
        if not team:
            raise RuntimeError("team_create_failed")
        return team

    def invite_user(
        self,
        team_id: str,
        username: str,
        *,
        invited_by: str,
        membership_role: str = "member",
    ) -> Dict[str, Any]:
        cleaned_team = str(team_id or "").strip()
        target = str(username or "").strip()
        actor = str(invited_by or "").strip()
        role_value = _normalize_team_membership_role(membership_role)
        if role_value == "owner":
            raise ValueError("invalid_membership_role")
        if not cleaned_team:
            raise ValueError("team_required")
        if not target:
            raise ValueError("username_required")
        if not actor:
            raise ValueError("invited_by_required")
        with self.store.pool.connection() as conn:
            with conn.transaction():
                team = conn.execute("SELECT id, owner_username FROM nm_teams WHERE id = %s", (cleaned_team,)).fetchone()
                if not team:
                    raise ValueError("team_not_found")
                if not self._user_exists(conn, target):
                    raise ValueError("user_not_found")
                if target == str(team.get("owner_username") or "").strip():
                    raise ValueError("user_already_in_team")
                active_membership = self._active_team_row_for_user(conn, target)
                if active_membership and str(active_membership.get("team_id") or "").strip() != cleaned_team:
                    raise ValueError("user_already_in_team")
                existing = conn.execute(
                    """
                    SELECT id, status
                    FROM nm_team_memberships
                    WHERE team_id = %s AND username = %s
                    """,
                    (cleaned_team, target),
                ).fetchone()
                if existing and str(existing.get("status") or "").strip() == TEAM_MEMBERSHIP_STATUS_ACTIVE:
                    raise ValueError("user_already_in_team")
                if existing:
                    membership_id = str(existing.get("id") or "").strip()
                    conn.execute(
                        """
                        UPDATE nm_team_memberships
                        SET membership_role = %s,
                            status = %s,
                            invited_by = %s,
                            invited_at = NOW(),
                            responded_at = NULL,
                            joined_at = NULL,
                            left_at = NULL,
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (role_value, TEAM_MEMBERSHIP_STATUS_PENDING, actor, membership_id),
                    )
                else:
                    membership_id = uuid.uuid4().hex
                    conn.execute(
                        """
                        INSERT INTO nm_team_memberships (
                            id,
                            team_id,
                            username,
                            membership_role,
                            status,
                            invited_by,
                            invited_at,
                            responded_at,
                            joined_at,
                            left_at,
                            created_at,
                            updated_at,
                            metadata
                        ) VALUES (%s, %s, %s, %s, %s, %s, NOW(), NULL, NULL, NULL, NOW(), NOW(), '{}'::jsonb)
                        """,
                        (membership_id, cleaned_team, target, role_value, TEAM_MEMBERSHIP_STATUS_PENDING, actor),
                    )
        membership = self.get_membership(membership_id)
        if not membership:
            raise RuntimeError("team_invite_failed")
        return membership

    def respond_to_invitation(self, membership_id: str, username: str, *, accept: bool) -> Dict[str, Any]:
        cleaned_id = str(membership_id or "").strip()
        cleaned_user = str(username or "").strip()
        if not cleaned_id:
            raise ValueError("invitation_required")
        if not cleaned_user:
            raise ValueError("username_required")
        with self.store.pool.connection() as conn:
            with conn.transaction():
                membership = conn.execute(
                    """
                    SELECT id, team_id, username, status
                    FROM nm_team_memberships
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (cleaned_id,),
                ).fetchone()
                if not membership:
                    raise ValueError("invitation_not_found")
                if str(membership.get("username") or "").strip() != cleaned_user:
                    raise ValueError("invitation_not_owned")
                if str(membership.get("status") or "").strip() != TEAM_MEMBERSHIP_STATUS_PENDING:
                    raise ValueError("invitation_not_pending")
                if accept:
                    active_membership = self._active_team_row_for_user(conn, cleaned_user)
                    active_team_id = str((active_membership or {}).get("team_id") or "").strip()
                    invite_team_id = str(membership.get("team_id") or "").strip()
                    if active_team_id and active_team_id != invite_team_id:
                        raise ValueError("user_already_in_team")
                    conn.execute(
                        """
                        UPDATE nm_team_memberships
                        SET status = %s,
                            responded_at = NOW(),
                            joined_at = NOW(),
                            left_at = NULL,
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (TEAM_MEMBERSHIP_STATUS_ACTIVE, cleaned_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE nm_team_memberships
                        SET status = %s,
                            responded_at = NOW(),
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (TEAM_MEMBERSHIP_STATUS_REJECTED, cleaned_id),
                    )
        membership = self.get_membership(cleaned_id)
        if not membership:
            raise RuntimeError("invitation_update_failed")
        return membership

    def leave_team(self, team_id: str, username: str) -> bool:
        cleaned_team = str(team_id or "").strip()
        cleaned_user = str(username or "").strip()
        if not cleaned_team or not cleaned_user:
            return False
        with self.store.pool.connection() as conn:
            with conn.transaction():
                membership = conn.execute(
                    """
                    SELECT id, membership_role
                    FROM nm_team_memberships
                    WHERE team_id = %s
                      AND username = %s
                      AND status = %s
                    FOR UPDATE
                    """,
                    (cleaned_team, cleaned_user, TEAM_MEMBERSHIP_STATUS_ACTIVE),
                ).fetchone()
                if not membership:
                    return False
                if str(membership.get("membership_role") or "").strip() == "owner":
                    raise ValueError("team_owner_cannot_leave")
                conn.execute(
                    """
                    UPDATE nm_team_memberships
                    SET status = %s,
                        responded_at = NOW(),
                        left_at = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (TEAM_MEMBERSHIP_STATUS_LEFT, str(membership.get("id") or "").strip()),
                )
        return True


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
                elif kind == "transfer_in":
                    if requested_delta <= 0:
                        requested_delta = abs(requested_delta)
                    desired = abs(requested_delta)
                    free_tokens = max(0, int(meta_dict.get("free_tokens") or meta_dict.get("free_used") or 0))
                    free_tokens = min(free_tokens, desired)
                    paid_tokens = max(0, int(meta_dict.get("paid_tokens") or meta_dict.get("paid_used") or (desired - free_tokens)))
                    paid_tokens = min(paid_tokens, desired - free_tokens)
                    paid_tokens += desired - free_tokens - paid_tokens
                    new_free += free_tokens
                    new_paid += paid_tokens
                    requested_delta = free_tokens + paid_tokens
                    meta_dict["free_used"] = free_tokens
                    meta_dict["paid_used"] = paid_tokens
                    meta_dict["used_total"] = requested_delta
                elif kind == "transfer_out":
                    if requested_delta >= 0:
                        requested_delta = -abs(requested_delta or 0)
                    desired = abs(requested_delta)
                    available = max(0, balance - int(summary.get("reserved") or 0))
                    if desired > available:
                        shortfall = desired
                        meta_dict["shortfall"] = shortfall
                        meta_dict["free_used"] = 0
                        meta_dict["paid_used"] = 0
                        meta_dict["used_total"] = 0
                        requested_delta = 0
                    else:
                        free_used = min(new_free, desired)
                        new_free -= free_used
                        remaining = desired - free_used
                        paid_used = min(new_paid, remaining)
                        new_paid -= paid_used
                        meta_dict["free_used"] = free_used
                        meta_dict["paid_used"] = paid_used
                        meta_dict["used_total"] = free_used + paid_used
                        requested_delta = -(free_used + paid_used)
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

    @staticmethod
    def _payload(username: str, entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        cleaned = str(username or "").strip()
        if not cleaned or not isinstance(entry, dict) or not entry:
            return None
        role = str(entry.get("role") or "user").strip() or "user"
        return {
            "username": cleaned,
            "role": role,
            "groups": [role],
            "email": str(entry.get("email") or "").strip() or None,
            "external": bool(entry.get("external")),
            "provider": str(entry.get("provider") or "").strip() or None,
            "subject": str(entry.get("subject") or "").strip() or None,
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
            "has_password": bool(entry.get("password_hash")),
        }

    def count_users(self) -> int:
        with self.lock:
            return len(self.data)

    def has_users(self) -> bool:
        return self.count_users() > 0

    def ensure_user(self, username: str, *, role: str = "user", email: Optional[str] = None) -> None:
        username = str(username or "").strip()
        if not username:
            return
        role_value = _normalize_user_role(role)
        with self.lock:
            entry = self.data.get(username, {})
            entry.setdefault("created_at", _timestamp(dt.datetime.now(UTC)))
            entry["role"] = role_value or entry.get("role") or "user"
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
        role_value = _normalize_user_role(role)
        now = _timestamp(dt.datetime.now(UTC))
        with self.lock:
            self.data[username] = {
                "password_hash": generate_password_hash(password),
                "role": role_value,
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
        role_value = _normalize_user_role(role)
        now = _timestamp(dt.datetime.now(UTC))
        with self.lock:
            entry = self.data.get(username, {})
            entry.setdefault("created_at", now)
            entry["updated_at"] = now
            entry["role"] = role_value
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

    def set_password(self, username: str, password: str) -> bool:
        cleaned = str(username or "").strip()
        if not cleaned:
            return False
        with self.lock:
            entry = self.data.get(cleaned)
            if not isinstance(entry, dict):
                return False
            entry["password_hash"] = generate_password_hash(password)
            entry["updated_at"] = _timestamp(dt.datetime.now(UTC))
            self._write()
            return True

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        cleaned = str(username or "").strip()
        if not cleaned:
            return None
        with self.lock:
            entry = dict(self.data.get(cleaned) or {})
        return self._payload(cleaned, entry)

    def list_users(self) -> List[Dict[str, Any]]:
        with self.lock:
            items = sorted(self.data.items(), key=lambda item: item[0])
        payload: List[Dict[str, Any]] = []
        for username, entry in items:
            normalized = self._payload(username, entry)
            if normalized:
                payload.append(normalized)
        return payload


class FileTeamStore:
    """JSON-backed team and invitation registry for development mode."""

    def __init__(self, path: Path, users: FileUserStore):
        self.path = path
        self.users = users
        self.lock = threading.RLock()
        payload = _read_json(path, {"version": 1, "teams": {}, "memberships": {}})
        if not isinstance(payload, dict):
            payload = {"version": 1, "teams": {}, "memberships": {}}
        if not isinstance(payload.get("teams"), dict):
            payload["teams"] = {}
        if not isinstance(payload.get("memberships"), dict):
            payload["memberships"] = {}
        self.data = payload

    def _write(self) -> None:
        _write_json_atomic(self.path, self.data)

    def _timestamp_now(self) -> str:
        return _timestamp(dt.datetime.now(UTC)) or ""

    @staticmethod
    def _team_payload(entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict):
            return None
        team_id = str(entry.get("id") or "").strip()
        if not team_id:
            return None
        return {
            "id": team_id,
            "name": str(entry.get("name") or "").strip() or f"Team {team_id[:6]}",
            "parent_id": str(entry.get("parent_id") or "").strip() or None,
            "owner": str(entry.get("owner") or "").strip() or None,
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
            "member_count": int(entry.get("member_count") or 0),
        }

    def _membership_payload(self, entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict):
            return None
        membership_id = str(entry.get("id") or "").strip()
        if not membership_id:
            return None
        team = self.data.get("teams", {}).get(str(entry.get("team_id") or "").strip()) or {}
        membership_role = str(entry.get("membership_role") or "member").strip() or "member"
        status = str(entry.get("status") or TEAM_MEMBERSHIP_STATUS_PENDING).strip() or TEAM_MEMBERSHIP_STATUS_PENDING
        return {
            "id": membership_id,
            "team_id": str(entry.get("team_id") or "").strip() or None,
            "team_name": str(team.get("name") or "").strip() or None,
            "team_parent_id": str(team.get("parent_id") or "").strip() or None,
            "team_owner": str(team.get("owner") or "").strip() or None,
            "username": str(entry.get("username") or "").strip() or None,
            "membership_role": membership_role,
            "status": status,
            "is_owner": membership_role == "owner",
            "invited_by": str(entry.get("invited_by") or "").strip() or None,
            "invited_at": entry.get("invited_at"),
            "responded_at": entry.get("responded_at"),
            "joined_at": entry.get("joined_at"),
            "left_at": entry.get("left_at"),
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
        }

    def _sorted_memberships(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(
            entries,
            key=lambda item: (
                str(item.get("updated_at") or ""),
                str(item.get("created_at") or ""),
                str(item.get("id") or ""),
            ),
            reverse=True,
        )

    def _active_membership_locked(self, username: str) -> Optional[Dict[str, Any]]:
        cleaned = str(username or "").strip()
        if not cleaned:
            return None
        for entry in self._sorted_memberships(list(self.data.get("memberships", {}).values())):
            if str(entry.get("username") or "").strip() != cleaned:
                continue
            if str(entry.get("status") or "").strip() == TEAM_MEMBERSHIP_STATUS_ACTIVE:
                return entry
        return None

    def list_teams(self) -> List[Dict[str, Any]]:
        with self.lock:
            teams = [dict(item) for item in self.data.get("teams", {}).values() if isinstance(item, dict)]
            memberships = [dict(item) for item in self.data.get("memberships", {}).values() if isinstance(item, dict)]
        counts: Dict[str, int] = {}
        for membership in memberships:
            if str(membership.get("status") or "").strip() != TEAM_MEMBERSHIP_STATUS_ACTIVE:
                continue
            team_id = str(membership.get("team_id") or "").strip()
            if not team_id:
                continue
            counts[team_id] = counts.get(team_id, 0) + 1
        payload: List[Dict[str, Any]] = []
        for team in sorted(teams, key=lambda item: (str(item.get("name") or ""), str(item.get("id") or ""))):
            team["member_count"] = counts.get(str(team.get("id") or "").strip(), 0)
            normalized = self._team_payload(team)
            if normalized:
                payload.append(normalized)
        return payload

    def get_team(self, team_id: str) -> Optional[Dict[str, Any]]:
        cleaned = str(team_id or "").strip()
        if not cleaned:
            return None
        teams = {item.get("id"): item for item in self.list_teams() if item.get("id")}
        return teams.get(cleaned)

    def get_membership(self, membership_id: str) -> Optional[Dict[str, Any]]:
        cleaned = str(membership_id or "").strip()
        if not cleaned:
            return None
        with self.lock:
            entry = dict(self.data.get("memberships", {}).get(cleaned) or {})
        return self._membership_payload(entry)

    def list_user_memberships(self, username: str, *, statuses: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        cleaned = str(username or "").strip()
        if not cleaned:
            return []
        wanted = set(_normalize_statuses(statuses))
        with self.lock:
            entries = [dict(item) for item in self.data.get("memberships", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in self._sorted_memberships(entries):
            if str(entry.get("username") or "").strip() != cleaned:
                continue
            status = str(entry.get("status") or "").strip()
            if wanted and status not in wanted:
                continue
            normalized = self._membership_payload(entry)
            if normalized:
                payload.append(normalized)
        return payload

    def list_invitations_sent_by(self, username: str, *, statuses: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        cleaned = str(username or "").strip()
        if not cleaned:
            return []
        wanted = set(_normalize_statuses(statuses))
        with self.lock:
            entries = [dict(item) for item in self.data.get("memberships", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in self._sorted_memberships(entries):
            if str(entry.get("invited_by") or "").strip() != cleaned:
                continue
            status = str(entry.get("status") or "").strip()
            if wanted and status not in wanted:
                continue
            normalized = self._membership_payload(entry)
            if normalized:
                payload.append(normalized)
        return payload

    def list_team_members(self, team_id: str, *, statuses: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        cleaned = str(team_id or "").strip()
        if not cleaned:
            return []
        wanted = set(_normalize_statuses(statuses))
        with self.lock:
            entries = [dict(item) for item in self.data.get("memberships", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in sorted(entries, key=lambda item: (str(item.get("membership_role") or ""), str(item.get("username") or ""))):
            if str(entry.get("team_id") or "").strip() != cleaned:
                continue
            status = str(entry.get("status") or "").strip()
            if wanted and status not in wanted:
                continue
            normalized = self._membership_payload(entry)
            if normalized:
                payload.append(normalized)
        return payload

    def team_role_for_user(self, username: str, team_id: str) -> Optional[str]:
        cleaned_user = str(username or "").strip()
        cleaned_team = str(team_id or "").strip()
        if not cleaned_user or not cleaned_team:
            return None
        with self.lock:
            for entry in self.data.get("memberships", {}).values():
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("username") or "").strip() != cleaned_user:
                    continue
                if str(entry.get("team_id") or "").strip() != cleaned_team:
                    continue
                if str(entry.get("status") or "").strip() != TEAM_MEMBERSHIP_STATUS_ACTIVE:
                    continue
                value = str(entry.get("membership_role") or "").strip()
                return value or None
        return None

    def create_team(self, name: str, *, owner_username: str, parent_id: Optional[str] = None) -> Dict[str, Any]:
        owner = str(owner_username or "").strip()
        cleaned_parent = str(parent_id or "").strip() or None
        if not owner:
            raise ValueError("owner_required")
        if not self.users.get_user(owner):
            raise ValueError("user_not_found")
        now = self._timestamp_now()
        team_id = uuid.uuid4().hex
        membership_id = uuid.uuid4().hex
        with self.lock:
            if self._active_membership_locked(owner):
                raise ValueError("user_already_in_team")
            if cleaned_parent and cleaned_parent not in self.data.get("teams", {}):
                raise ValueError("parent_team_not_found")
            self.data.setdefault("teams", {})[team_id] = {
                "id": team_id,
                "name": str(name or "").strip() or f"Team {team_id[:6]}",
                "parent_id": cleaned_parent,
                "owner": owner,
                "created_at": now,
                "updated_at": now,
            }
            self.data.setdefault("memberships", {})[membership_id] = {
                "id": membership_id,
                "team_id": team_id,
                "username": owner,
                "membership_role": "owner",
                "status": TEAM_MEMBERSHIP_STATUS_ACTIVE,
                "invited_by": owner,
                "invited_at": now,
                "responded_at": now,
                "joined_at": now,
                "left_at": None,
                "created_at": now,
                "updated_at": now,
            }
            self._write()
        team = self.get_team(team_id)
        if not team:
            raise RuntimeError("team_create_failed")
        return team

    def invite_user(
        self,
        team_id: str,
        username: str,
        *,
        invited_by: str,
        membership_role: str = "member",
    ) -> Dict[str, Any]:
        cleaned_team = str(team_id or "").strip()
        target = str(username or "").strip()
        actor = str(invited_by or "").strip()
        role_value = _normalize_team_membership_role(membership_role)
        if role_value == "owner":
            raise ValueError("invalid_membership_role")
        if not cleaned_team:
            raise ValueError("team_required")
        if not target:
            raise ValueError("username_required")
        if not actor:
            raise ValueError("invited_by_required")
        if not self.users.get_user(target):
            raise ValueError("user_not_found")
        now = self._timestamp_now()
        with self.lock:
            team = self.data.get("teams", {}).get(cleaned_team)
            if not isinstance(team, dict):
                raise ValueError("team_not_found")
            if target == str(team.get("owner") or "").strip():
                raise ValueError("user_already_in_team")
            active_membership = self._active_membership_locked(target)
            if active_membership and str(active_membership.get("team_id") or "").strip() != cleaned_team:
                raise ValueError("user_already_in_team")
            memberships = self.data.setdefault("memberships", {})
            existing_id = None
            for membership_id, entry in memberships.items():
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("team_id") or "").strip() != cleaned_team:
                    continue
                if str(entry.get("username") or "").strip() != target:
                    continue
                existing_id = membership_id
                break
            if existing_id:
                entry = dict(memberships.get(existing_id) or {})
                if str(entry.get("status") or "").strip() == TEAM_MEMBERSHIP_STATUS_ACTIVE:
                    raise ValueError("user_already_in_team")
                entry.update(
                    {
                        "membership_role": role_value,
                        "status": TEAM_MEMBERSHIP_STATUS_PENDING,
                        "invited_by": actor,
                        "invited_at": now,
                        "responded_at": None,
                        "joined_at": None,
                        "left_at": None,
                        "updated_at": now,
                    }
                )
                memberships[existing_id] = entry
                membership_id = existing_id
            else:
                membership_id = uuid.uuid4().hex
                memberships[membership_id] = {
                    "id": membership_id,
                    "team_id": cleaned_team,
                    "username": target,
                    "membership_role": role_value,
                    "status": TEAM_MEMBERSHIP_STATUS_PENDING,
                    "invited_by": actor,
                    "invited_at": now,
                    "responded_at": None,
                    "joined_at": None,
                    "left_at": None,
                    "created_at": now,
                    "updated_at": now,
                }
            self.data["teams"][cleaned_team]["updated_at"] = now
            self._write()
        membership = self.get_membership(membership_id)
        if not membership:
            raise RuntimeError("team_invite_failed")
        return membership

    def respond_to_invitation(self, membership_id: str, username: str, *, accept: bool) -> Dict[str, Any]:
        cleaned_id = str(membership_id or "").strip()
        cleaned_user = str(username or "").strip()
        if not cleaned_id:
            raise ValueError("invitation_required")
        if not cleaned_user:
            raise ValueError("username_required")
        now = self._timestamp_now()
        with self.lock:
            entry = dict(self.data.get("memberships", {}).get(cleaned_id) or {})
            if not entry:
                raise ValueError("invitation_not_found")
            if str(entry.get("username") or "").strip() != cleaned_user:
                raise ValueError("invitation_not_owned")
            if str(entry.get("status") or "").strip() != TEAM_MEMBERSHIP_STATUS_PENDING:
                raise ValueError("invitation_not_pending")
            if accept:
                active_membership = self._active_membership_locked(cleaned_user)
                active_team_id = str((active_membership or {}).get("team_id") or "").strip()
                invite_team_id = str(entry.get("team_id") or "").strip()
                if active_team_id and active_team_id != invite_team_id:
                    raise ValueError("user_already_in_team")
                entry["status"] = TEAM_MEMBERSHIP_STATUS_ACTIVE
                entry["joined_at"] = now
            else:
                entry["status"] = TEAM_MEMBERSHIP_STATUS_REJECTED
            entry["responded_at"] = now
            entry["updated_at"] = now
            entry["left_at"] = None if accept else entry.get("left_at")
            self.data.setdefault("memberships", {})[cleaned_id] = entry
            self._write()
        membership = self.get_membership(cleaned_id)
        if not membership:
            raise RuntimeError("invitation_update_failed")
        return membership

    def leave_team(self, team_id: str, username: str) -> bool:
        cleaned_team = str(team_id or "").strip()
        cleaned_user = str(username or "").strip()
        if not cleaned_team or not cleaned_user:
            return False
        now = self._timestamp_now()
        with self.lock:
            memberships = self.data.get("memberships", {})
            for membership_id, entry in memberships.items():
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("team_id") or "").strip() != cleaned_team:
                    continue
                if str(entry.get("username") or "").strip() != cleaned_user:
                    continue
                if str(entry.get("status") or "").strip() != TEAM_MEMBERSHIP_STATUS_ACTIVE:
                    continue
                if str(entry.get("membership_role") or "").strip() == "owner":
                    raise ValueError("team_owner_cannot_leave")
                updated = dict(entry)
                updated["status"] = TEAM_MEMBERSHIP_STATUS_LEFT
                updated["responded_at"] = now
                updated["left_at"] = now
                updated["updated_at"] = now
                memberships[membership_id] = updated
                self._write()
                return True
        return False


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
        self.teams = FileTeamStore(base / "teams.json", self.users)
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
