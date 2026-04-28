from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
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

from .authorization import (
    GROUP_MEMBERSHIP_ROLE_MEMBER,
    GROUP_MEMBERSHIP_ROLES,
    SERVICE_ACCESS_NONE,
    bootstrap_authorization_contract,
    normalize_group_key,
    normalize_group_membership_role,
    normalize_service_access_level,
    normalize_service_key,
)

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
GROUP_SYSTEM_KEYS = frozenset({"admin", "user"})
SERVICE_ACCOUNT_PROVIDER = "service_account"
SERVICE_ACCOUNT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,47}$")

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
    CREATE TABLE IF NOT EXISTS nm_groups (
        key TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        parent_key TEXT REFERENCES nm_groups(key) ON DELETE SET NULL,
        system BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_groups_parent_idx
        ON nm_groups (parent_key)
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_group_memberships (
        group_key TEXT NOT NULL REFERENCES nm_groups(key) ON DELETE CASCADE,
        username TEXT NOT NULL REFERENCES nm_users(username) ON DELETE CASCADE,
        membership_role TEXT NOT NULL DEFAULT 'member'
            CHECK (membership_role IN ('member', 'manager')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        PRIMARY KEY (group_key, username)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_group_memberships_user_idx
        ON nm_group_memberships (username, membership_role, updated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_group_memberships_group_idx
        ON nm_group_memberships (group_key, membership_role, updated_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_service_catalog (
        service_key TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        description TEXT,
        public_access_level TEXT NOT NULL DEFAULT 'none'
            CHECK (public_access_level IN ('none', 'request', 'observe', 'use', 'control')),
        dashboard_url TEXT,
        marketing_url TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_group_service_grants (
        group_key TEXT NOT NULL REFERENCES nm_groups(key) ON DELETE CASCADE,
        service_key TEXT NOT NULL REFERENCES nm_service_catalog(service_key) ON DELETE CASCADE,
        access_level TEXT NOT NULL
            CHECK (access_level IN ('none', 'request', 'observe', 'use', 'control')),
        granted_by TEXT REFERENCES nm_users(username) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        PRIMARY KEY (group_key, service_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_group_service_grants_service_idx
        ON nm_group_service_grants (service_key, access_level, updated_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS nm_service_accounts (
        service_account_id TEXT PRIMARY KEY,
        principal_username TEXT NOT NULL UNIQUE REFERENCES nm_users(username) ON DELETE CASCADE,
        display_name TEXT NOT NULL,
        description TEXT,
        service_key TEXT REFERENCES nm_service_catalog(service_key) ON DELETE SET NULL,
        created_by_username TEXT REFERENCES nm_users(username) ON DELETE SET NULL,
        disabled BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_service_accounts_service_idx
        ON nm_service_accounts (service_key, disabled, updated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS nm_service_accounts_creator_idx
        ON nm_service_accounts (created_by_username, disabled, updated_at DESC)
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


def normalize_service_account_id(value: Any) -> str:
    cleaned = str(value or "").strip().lower()
    if not SERVICE_ACCOUNT_ID_RE.match(cleaned):
        raise ValueError("invalid_service_account_id")
    return cleaned


def service_account_principal_username(service_account_id: Any) -> str:
    return f"svc_{normalize_service_account_id(service_account_id)}"


def _is_service_account_provider(entry: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(entry, dict):
        return False
    return str(entry.get("provider") or "").strip() == SERVICE_ACCOUNT_PROVIDER


def _service_account_conflict(entry: Optional[Dict[str, Any]]) -> bool:
    return _is_service_account_provider(entry)


def _service_account_group_keys(payload: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    raw_candidates: List[Any] = []
    for key in ("group_keys", "groups"):
        raw = payload.get(key)
        if isinstance(raw, list):
            raw_candidates.extend(raw)
    memberships = payload.get("group_memberships")
    if isinstance(memberships, list):
        for entry in memberships:
            if isinstance(entry, dict):
                raw_candidates.append(entry.get("group_key") or entry.get("key"))
    seen: set[str] = set()
    for raw in raw_candidates:
        try:
            group_key = normalize_group_key(raw)
        except ValueError:
            continue
        if group_key in seen:
            continue
        seen.add(group_key)
        values.append(group_key)
    return values


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
        self.access = PostgresAccessControlStore(self)
        self.service_accounts = PostgresServiceAccountStore(self)
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
        self.access.bootstrap_contract()
        raw_service_accounts = (
            os.getenv("CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNTS")
            or os.getenv("CUSTOMERS_SERVICE_ACCOUNTS_JSON")
            or ""
        ).strip()
        if raw_service_accounts:
            try:
                service_accounts_payload = json.loads(raw_service_accounts)
            except Exception:
                service_accounts_payload = None
            if isinstance(service_accounts_payload, list):
                for item in service_accounts_payload:
                    if not isinstance(item, dict):
                        continue
                    try:
                        service_account_id = normalize_service_account_id(
                            item.get("service_account_id") or item.get("id") or item.get("key")
                        )
                    except ValueError:
                        continue
                    try:
                        account = self.service_accounts.upsert_service_account(
                            service_account_id,
                            display_name=str(
                                item.get("display_name") or item.get("name") or service_account_id
                            ).strip()
                            or service_account_id,
                            description=str(item.get("description") or "").strip() or None,
                            service_key=item.get("service_key") or item.get("service"),
                            created_by=item.get("created_by") or default_user or None,
                            metadata=item.get("metadata") if isinstance(item.get("metadata"), dict) else None,
                            disabled=bool(item.get("disabled")),
                        )
                    except ValueError:
                        continue
                    for group_key in _service_account_group_keys(item):
                        try:
                            self.access.upsert_group_membership(
                                group_key,
                                str(account.get("principal_username") or "").strip(),
                                membership_role=GROUP_MEMBERSHIP_ROLE_MEMBER,
                            )
                        except ValueError:
                            continue
        raw = (
            os.getenv("CUSTOMERS_BOOTSTRAP_ACCESS_TOKENS")
            or os.getenv("REFINER_BOOTSTRAP_ACCESS_TOKENS")
            or ""
        ).strip()
        if raw:
            try:
                payload = json.loads(raw)
            except Exception:
                payload = None
            if isinstance(payload, list):
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
        raw_service_account_tokens = (
            os.getenv("CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNT_TOKENS")
            or os.getenv("CUSTOMERS_SERVICE_ACCOUNT_TOKENS_JSON")
            or ""
        ).strip()
        if not raw_service_account_tokens:
            return
        try:
            service_account_token_payload = json.loads(raw_service_account_tokens)
        except Exception:
            return
        if not isinstance(service_account_token_payload, list):
            return
        for item in service_account_token_payload:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token") or "").strip()
            if not token:
                continue
            service_account_id_raw = item.get("service_account_id") or item.get("id") or item.get("key")
            try:
                service_account_id = normalize_service_account_id(service_account_id_raw)
            except ValueError:
                continue
            account = self.service_accounts.get_service_account(service_account_id, include_disabled=True)
            if not account:
                continue
            label = str(item.get("label") or "").strip() or None
            ttl_seconds = item.get("ttl_seconds")
            meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
            meta = {
                **meta,
                "identity_type": "service_account",
                "service_account_id": service_account_id,
            }
            self.access_tokens.ensure_token(
                str(account.get("principal_username") or "").strip(),
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
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM nm_users
                WHERE COALESCE(provider, '') <> %s
                """,
                (SERVICE_ACCOUNT_PROVIDER,),
            ).fetchone()
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
                existing = conn.execute(
                    """
                    SELECT provider
                    FROM nm_users
                    WHERE username = %s
                    """,
                    (username,),
                ).fetchone()
                if _service_account_conflict(existing):
                    raise ValueError("principal_username_conflict")
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
                existing = conn.execute(
                    """
                    SELECT provider
                    FROM nm_users
                    WHERE username = %s
                    """,
                    (username,),
                ).fetchone()
                if _service_account_conflict(existing):
                    raise ValueError("principal_username_conflict")
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

    def get_metadata(self, username: str) -> Dict[str, Any]:
        username = str(username or "").strip()
        if not username:
            return {}
        with self.store.pool.connection() as conn:
            row = conn.execute(
                "SELECT metadata FROM nm_users WHERE username = %s",
                (username,),
            ).fetchone()
        metadata = (row or {}).get("metadata")
        return dict(metadata) if isinstance(metadata, dict) else {}

    def set_metadata(self, username: str, metadata: Optional[Dict[str, Any]]) -> bool:
        username = str(username or "").strip()
        if not username:
            return False
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE nm_users
                    SET metadata = %s,
                        updated_at = NOW()
                    WHERE username = %s
                    RETURNING username
                    """,
                    (_jsonb(dict(metadata or {})), username),
                ).fetchone()
        return bool(row)

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


class PostgresAccessControlStore:
    def __init__(self, store: PostgresCentralStore):
        self.store = store

    @staticmethod
    def _group_payload(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        group_key = str(row.get("key") or row.get("group_key") or "").strip().lower()
        if not group_key:
            return None
        return {
            "key": group_key,
            "name": str(row.get("name") or group_key).strip() or group_key,
            "parent_key": str(row.get("parent_key") or "").strip().lower() or None,
            "system": bool(row.get("system")),
            "metadata": dict(row.get("metadata")) if isinstance(row.get("metadata"), dict) else {},
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
        }

    @staticmethod
    def _membership_payload(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        group_key = str(row.get("group_key") or "").strip().lower()
        username = str(row.get("username") or "").strip()
        if not group_key or not username:
            return None
        return {
            "group_key": group_key,
            "group_name": str(row.get("group_name") or group_key).strip() or group_key,
            "parent_key": str(row.get("parent_key") or "").strip().lower() or None,
            "system": bool(row.get("system")),
            "username": username,
            "membership_role": normalize_group_membership_role(row.get("membership_role")),
            "metadata": dict(row.get("metadata")) if isinstance(row.get("metadata"), dict) else {},
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
        }

    @staticmethod
    def _service_payload(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        service_key = str(row.get("service_key") or row.get("key") or "").strip().lower()
        if not service_key:
            return None
        return {
            "service_key": service_key,
            "display_name": str(row.get("display_name") or service_key).strip() or service_key,
            "description": str(row.get("description") or "").strip() or None,
            "public_access_level": normalize_service_access_level(
                row.get("public_access_level"),
                default=SERVICE_ACCESS_NONE,
            ),
            "dashboard_url": str(row.get("dashboard_url") or "").strip() or None,
            "marketing_url": str(row.get("marketing_url") or "").strip() or None,
            "metadata": dict(row.get("metadata")) if isinstance(row.get("metadata"), dict) else {},
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
        }

    @staticmethod
    def _grant_payload(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        group_key = str(row.get("group_key") or "").strip().lower()
        service_key = str(row.get("service_key") or "").strip().lower()
        if not group_key or not service_key:
            return None
        payload: Dict[str, Any] = {
            "group_key": group_key,
            "service_key": service_key,
            "access_level": normalize_service_access_level(row.get("access_level")),
            "granted_by": str(row.get("granted_by") or "").strip() or None,
            "metadata": dict(row.get("metadata")) if isinstance(row.get("metadata"), dict) else {},
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
        }
        display_name = str(row.get("display_name") or "").strip()
        if display_name:
            payload["display_name"] = display_name
        public_access_level = row.get("public_access_level")
        if public_access_level not in (None, ""):
            payload["public_access_level"] = normalize_service_access_level(public_access_level)
        return payload

    @staticmethod
    def _ordered_groups(records: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pending: Dict[str, Dict[str, Any]] = {}
        for raw in records:
            try:
                key = normalize_group_key(raw.get("key") or raw.get("group_key"))
            except ValueError:
                continue
            parent_raw = raw.get("parent_key") or raw.get("parent_id")
            if parent_raw in (None, ""):
                parent_key = None
            else:
                try:
                    parent_key = normalize_group_key(parent_raw)
                except ValueError:
                    continue
            pending[key] = {
                "key": key,
                "name": str(raw.get("name") or key).strip() or key,
                "parent_key": parent_key,
                "system": bool(raw.get("system")),
                "metadata": dict(raw.get("metadata")) if isinstance(raw.get("metadata"), dict) else {},
            }
        ordered: List[Dict[str, Any]] = []
        emitted: set[str] = set()
        while pending:
            progressed = False
            for group_key, record in list(pending.items()):
                parent_key = record.get("parent_key")
                if not parent_key or parent_key in emitted or parent_key not in pending:
                    ordered.append(record)
                    emitted.add(group_key)
                    pending.pop(group_key, None)
                    progressed = True
            if progressed:
                continue
            group_key = sorted(pending.keys())[0]
            record = dict(pending.pop(group_key))
            if record.get("parent_key") == group_key:
                record["parent_key"] = None
            ordered.append(record)
            emitted.add(group_key)
        return ordered

    def _group_exists(self, conn: Any, group_key: str) -> bool:
        row = conn.execute("SELECT key FROM nm_groups WHERE key = %s", (group_key,)).fetchone()
        return bool((row or {}).get("key"))

    def _service_exists(self, conn: Any, service_key: str) -> bool:
        row = conn.execute(
            "SELECT service_key FROM nm_service_catalog WHERE service_key = %s",
            (service_key,),
        ).fetchone()
        return bool((row or {}).get("service_key"))

    def _user_exists(self, conn: Any, username: str) -> bool:
        row = conn.execute("SELECT username FROM nm_users WHERE username = %s", (username,)).fetchone()
        return bool((row or {}).get("username"))

    def bootstrap_contract(self, payload: Optional[Dict[str, Any]] = None) -> None:
        contract = payload if isinstance(payload, dict) else bootstrap_authorization_contract()
        groups = contract.get("groups") if isinstance(contract.get("groups"), list) else []
        services = contract.get("services") if isinstance(contract.get("services"), list) else []
        grants = contract.get("grants") if isinstance(contract.get("grants"), list) else []
        ordered_groups = self._ordered_groups([dict(item) for item in groups if isinstance(item, dict)])
        with self.store.pool.connection() as conn:
            with conn.transaction():
                for group in ordered_groups:
                    try:
                        self._upsert_group(conn, group)
                    except ValueError:
                        continue
                for service in services:
                    if not isinstance(service, dict):
                        continue
                    try:
                        self._upsert_service(conn, service)
                    except ValueError:
                        continue
                for grant in grants:
                    if not isinstance(grant, dict):
                        continue
                    try:
                        self._upsert_group_service_grant(conn, grant)
                    except ValueError:
                        continue

    def _upsert_group(self, conn: Any, payload: Dict[str, Any]) -> None:
        group_key = normalize_group_key(payload.get("key") or payload.get("group_key"))
        parent_raw = payload.get("parent_key") or payload.get("parent_id")
        parent_key = None
        if parent_raw not in (None, ""):
            parent_key = normalize_group_key(parent_raw)
            if parent_key == group_key:
                raise ValueError("group_parent_cycle")
            if not self._group_exists(conn, parent_key):
                raise ValueError("parent_group_not_found")
        existing = conn.execute(
            """
            SELECT name, system, metadata
            FROM nm_groups
            WHERE key = %s
            """,
            (group_key,),
        ).fetchone()
        name = str(payload.get("name") or (existing or {}).get("name") or group_key).strip() or group_key
        metadata = payload.get("metadata")
        if metadata is None and isinstance((existing or {}).get("metadata"), dict):
            metadata = dict((existing or {}).get("metadata") or {})
        metadata_value = dict(metadata or {})
        system = bool(payload.get("system")) or bool((existing or {}).get("system"))
        conn.execute(
            """
            INSERT INTO nm_groups (key, name, parent_key, system, created_at, updated_at, metadata)
            VALUES (%s, %s, %s, %s, NOW(), NOW(), %s)
            ON CONFLICT (key) DO UPDATE
            SET name = EXCLUDED.name,
                parent_key = EXCLUDED.parent_key,
                system = EXCLUDED.system,
                metadata = EXCLUDED.metadata,
                updated_at = NOW()
            """,
            (group_key, name, parent_key, system, _jsonb(metadata_value)),
        )

    def list_groups(self) -> List[Dict[str, Any]]:
        with self.store.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT key, name, parent_key, system, created_at, updated_at, metadata
                FROM nm_groups
                ORDER BY key ASC
                """
            ).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._group_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def get_group(self, group_key: str) -> Optional[Dict[str, Any]]:
        cleaned = normalize_group_key(group_key)
        with self.store.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT key, name, parent_key, system, created_at, updated_at, metadata
                FROM nm_groups
                WHERE key = %s
                """,
                (cleaned,),
            ).fetchone()
        return self._group_payload(row)

    def upsert_group(
        self,
        group_key: str,
        *,
        name: Optional[str] = None,
        parent_key: Optional[str] = None,
        system: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned = normalize_group_key(group_key)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                self._upsert_group(
                    conn,
                    {
                        "key": cleaned,
                        "name": name,
                        "parent_key": parent_key,
                        "system": system,
                        "metadata": dict(metadata or {}) if metadata is not None else None,
                    },
                )
        group = self.get_group(cleaned)
        if not group:
            raise RuntimeError("group_upsert_failed")
        return group

    def list_group_memberships(
        self,
        *,
        group_key: Optional[str] = None,
        username: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if group_key:
            clauses.append("m.group_key = %s")
            params.append(normalize_group_key(group_key))
        if username:
            cleaned_user = str(username or "").strip()
            if cleaned_user:
                clauses.append("m.username = %s")
                params.append(cleaned_user)
        sql = """
            SELECT
                m.group_key,
                g.name AS group_name,
                g.parent_key,
                g.system,
                m.username,
                m.membership_role,
                m.created_at,
                m.updated_at,
                m.metadata
            FROM nm_group_memberships AS m
            JOIN nm_groups AS g ON g.key = m.group_key
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY m.group_key ASC, m.username ASC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._membership_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def upsert_group_membership(
        self,
        group_key: str,
        username: str,
        *,
        membership_role: str = GROUP_MEMBERSHIP_ROLE_MEMBER,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned_group = normalize_group_key(group_key)
        cleaned_user = str(username or "").strip()
        if not cleaned_user:
            raise ValueError("username_required")
        role_value = normalize_group_membership_role(membership_role)
        metadata_value = dict(metadata or {})
        with self.store.pool.connection() as conn:
            with conn.transaction():
                if not self._group_exists(conn, cleaned_group):
                    raise ValueError("group_not_found")
                if not self._user_exists(conn, cleaned_user):
                    raise ValueError("user_not_found")
                conn.execute(
                    """
                    INSERT INTO nm_group_memberships (
                        group_key,
                        username,
                        membership_role,
                        created_at,
                        updated_at,
                        metadata
                    ) VALUES (%s, %s, %s, NOW(), NOW(), %s)
                    ON CONFLICT (group_key, username) DO UPDATE
                    SET membership_role = EXCLUDED.membership_role,
                        metadata = EXCLUDED.metadata,
                        updated_at = NOW()
                    """,
                    (cleaned_group, cleaned_user, role_value, _jsonb(metadata_value)),
                )
        membership = next(
            (
                item
                for item in self.list_group_memberships(group_key=cleaned_group, username=cleaned_user)
                if item.get("group_key") == cleaned_group and item.get("username") == cleaned_user
            ),
            None,
        )
        if not membership:
            raise RuntimeError("group_membership_upsert_failed")
        return membership

    def delete_group_membership(self, group_key: str, username: str) -> bool:
        cleaned_group = normalize_group_key(group_key)
        cleaned_user = str(username or "").strip()
        if not cleaned_user:
            return False
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    DELETE FROM nm_group_memberships
                    WHERE group_key = %s AND username = %s
                    RETURNING group_key
                    """,
                    (cleaned_group, cleaned_user),
                ).fetchone()
        return bool(row)

    def _upsert_service(self, conn: Any, payload: Dict[str, Any]) -> None:
        service_key = normalize_service_key(payload.get("service_key") or payload.get("key"))
        existing = conn.execute(
            """
            SELECT display_name, description, dashboard_url, marketing_url, metadata
            FROM nm_service_catalog
            WHERE service_key = %s
            """,
            (service_key,),
        ).fetchone()
        display_name = str(payload.get("display_name") or (existing or {}).get("display_name") or service_key).strip() or service_key
        description = payload.get("description")
        if description is None:
            description = (existing or {}).get("description")
        description_value = str(description or "").strip() or None
        dashboard_url = payload.get("dashboard_url")
        if dashboard_url is None:
            dashboard_url = (existing or {}).get("dashboard_url")
        marketing_url = payload.get("marketing_url")
        if marketing_url is None:
            marketing_url = (existing or {}).get("marketing_url")
        metadata = payload.get("metadata")
        if metadata is None and isinstance((existing or {}).get("metadata"), dict):
            metadata = dict((existing or {}).get("metadata") or {})
        metadata_value = dict(metadata or {})
        public_access_level = normalize_service_access_level(
            payload.get("public_access_level"),
            default=SERVICE_ACCESS_NONE,
        )
        conn.execute(
            """
            INSERT INTO nm_service_catalog (
                service_key,
                display_name,
                description,
                public_access_level,
                dashboard_url,
                marketing_url,
                created_at,
                updated_at,
                metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)
            ON CONFLICT (service_key) DO UPDATE
            SET display_name = EXCLUDED.display_name,
                description = EXCLUDED.description,
                public_access_level = EXCLUDED.public_access_level,
                dashboard_url = EXCLUDED.dashboard_url,
                marketing_url = EXCLUDED.marketing_url,
                metadata = EXCLUDED.metadata,
                updated_at = NOW()
            """,
            (
                service_key,
                display_name,
                description_value,
                public_access_level,
                str(dashboard_url or "").strip() or None,
                str(marketing_url or "").strip() or None,
                _jsonb(metadata_value),
            ),
        )

    def list_services(self) -> List[Dict[str, Any]]:
        with self.store.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    service_key,
                    display_name,
                    description,
                    public_access_level,
                    dashboard_url,
                    marketing_url,
                    created_at,
                    updated_at,
                    metadata
                FROM nm_service_catalog
                ORDER BY service_key ASC
                """
            ).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._service_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def get_service(self, service_key: str) -> Optional[Dict[str, Any]]:
        cleaned = normalize_service_key(service_key)
        with self.store.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT
                    service_key,
                    display_name,
                    description,
                    public_access_level,
                    dashboard_url,
                    marketing_url,
                    created_at,
                    updated_at,
                    metadata
                FROM nm_service_catalog
                WHERE service_key = %s
                """,
                (cleaned,),
            ).fetchone()
        return self._service_payload(row)

    def upsert_service(
        self,
        service_key: str,
        *,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        public_access_level: str = SERVICE_ACCESS_NONE,
        dashboard_url: Optional[str] = None,
        marketing_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned = normalize_service_key(service_key)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                self._upsert_service(
                    conn,
                    {
                        "service_key": cleaned,
                        "display_name": display_name,
                        "description": description,
                        "public_access_level": public_access_level,
                        "dashboard_url": dashboard_url,
                        "marketing_url": marketing_url,
                        "metadata": dict(metadata or {}) if metadata is not None else None,
                    },
                )
        service = self.get_service(cleaned)
        if not service:
            raise RuntimeError("service_upsert_failed")
        return service

    def _upsert_group_service_grant(self, conn: Any, payload: Dict[str, Any]) -> None:
        group_key = normalize_group_key(payload.get("group_key"))
        service_key = normalize_service_key(payload.get("service_key"))
        if not self._group_exists(conn, group_key):
            raise ValueError("group_not_found")
        if not self._service_exists(conn, service_key):
            raise ValueError("service_not_found")
        access_level = normalize_service_access_level(payload.get("access_level"))
        granted_by_raw = str(payload.get("granted_by") or "").strip() or None
        if granted_by_raw and not self._user_exists(conn, granted_by_raw):
            granted_by_raw = None
        existing = conn.execute(
            """
            SELECT metadata
            FROM nm_group_service_grants
            WHERE group_key = %s AND service_key = %s
            """,
            (group_key, service_key),
        ).fetchone()
        metadata = payload.get("metadata")
        if metadata is None and isinstance((existing or {}).get("metadata"), dict):
            metadata = dict((existing or {}).get("metadata") or {})
        metadata_value = dict(metadata or {})
        conn.execute(
            """
            INSERT INTO nm_group_service_grants (
                group_key,
                service_key,
                access_level,
                granted_by,
                created_at,
                updated_at,
                metadata
            ) VALUES (%s, %s, %s, %s, NOW(), NOW(), %s)
            ON CONFLICT (group_key, service_key) DO UPDATE
            SET access_level = EXCLUDED.access_level,
                granted_by = EXCLUDED.granted_by,
                metadata = EXCLUDED.metadata,
                updated_at = NOW()
            """,
            (group_key, service_key, access_level, granted_by_raw, _jsonb(metadata_value)),
        )

    def list_group_service_grants(
        self,
        *,
        group_key: Optional[str] = None,
        service_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if group_key:
            clauses.append("g.group_key = %s")
            params.append(normalize_group_key(group_key))
        if service_key:
            clauses.append("g.service_key = %s")
            params.append(normalize_service_key(service_key))
        sql = """
            SELECT
                g.group_key,
                g.service_key,
                g.access_level,
                g.granted_by,
                g.created_at,
                g.updated_at,
                g.metadata,
                s.display_name,
                s.public_access_level
            FROM nm_group_service_grants AS g
            JOIN nm_service_catalog AS s ON s.service_key = g.service_key
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY g.group_key ASC, g.service_key ASC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._grant_payload(row)
            if entry:
                payload.append(entry)
        return payload

    def get_group_service_grant(self, group_key: str, service_key: str) -> Optional[Dict[str, Any]]:
        grants = self.list_group_service_grants(group_key=group_key, service_key=service_key)
        return grants[0] if grants else None

    def upsert_group_service_grant(
        self,
        group_key: str,
        service_key: str,
        *,
        access_level: str,
        granted_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned_group = normalize_group_key(group_key)
        cleaned_service = normalize_service_key(service_key)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                self._upsert_group_service_grant(
                    conn,
                    {
                        "group_key": cleaned_group,
                        "service_key": cleaned_service,
                        "access_level": access_level,
                        "granted_by": granted_by,
                        "metadata": dict(metadata or {}) if metadata is not None else None,
                    },
                )
        grant = self.get_group_service_grant(cleaned_group, cleaned_service)
        if not grant:
            raise RuntimeError("group_service_grant_upsert_failed")
        return grant

    def delete_group_service_grant(self, group_key: str, service_key: str) -> bool:
        cleaned_group = normalize_group_key(group_key)
        cleaned_service = normalize_service_key(service_key)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    DELETE FROM nm_group_service_grants
                    WHERE group_key = %s AND service_key = %s
                    RETURNING group_key
                    """,
                    (cleaned_group, cleaned_service),
                ).fetchone()
        return bool(row)


class PostgresServiceAccountStore:
    def __init__(self, store: PostgresCentralStore):
        self.store = store

    @staticmethod
    def _payload_from_row(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(row, dict):
            return None
        service_account_id = str(row.get("service_account_id") or "").strip().lower()
        principal_username = str(row.get("principal_username") or "").strip()
        if not service_account_id or not principal_username:
            return None
        return {
            "service_account_id": service_account_id,
            "principal_username": principal_username,
            "display_name": str(row.get("display_name") or service_account_id).strip() or service_account_id,
            "description": str(row.get("description") or "").strip() or None,
            "service_key": str(row.get("service_key") or "").strip().lower() or None,
            "created_by": str(row.get("created_by_username") or "").strip() or None,
            "disabled": bool(row.get("disabled")),
            "metadata": dict(row.get("metadata")) if isinstance(row.get("metadata"), dict) else {},
            "created_at": _timestamp(row.get("created_at")),
            "updated_at": _timestamp(row.get("updated_at")),
        }

    def _ensure_principal_user(self, conn: Any, service_account_id: str, principal_username: str) -> None:
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
            ) VALUES (%s, NULL, 'user', NULL, TRUE, %s, %s, NOW(), NOW(), '{}'::jsonb)
            ON CONFLICT (username) DO UPDATE
            SET role = 'user',
                external = TRUE,
                provider = %s,
                subject = %s,
                updated_at = NOW()
            """,
            (
                principal_username,
                SERVICE_ACCOUNT_PROVIDER,
                service_account_id,
                SERVICE_ACCOUNT_PROVIDER,
                service_account_id,
            ),
        )

    def list_service_accounts(self, *, include_disabled: bool = False) -> List[Dict[str, Any]]:
        sql = """
            SELECT
                service_account_id,
                principal_username,
                display_name,
                description,
                service_key,
                created_by_username,
                disabled,
                metadata,
                created_at,
                updated_at
            FROM nm_service_accounts
        """
        params: List[Any] = []
        if not include_disabled:
            sql += " WHERE NOT disabled"
        sql += " ORDER BY service_account_id ASC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows or []:
            entry = self._payload_from_row(row)
            if entry:
                payload.append(entry)
        return payload

    def get_service_account(
        self,
        service_account_id: str,
        *,
        include_disabled: bool = False,
    ) -> Optional[Dict[str, Any]]:
        cleaned = normalize_service_account_id(service_account_id)
        sql = """
            SELECT
                service_account_id,
                principal_username,
                display_name,
                description,
                service_key,
                created_by_username,
                disabled,
                metadata,
                created_at,
                updated_at
            FROM nm_service_accounts
            WHERE service_account_id = %s
        """
        params: List[Any] = [cleaned]
        if not include_disabled:
            sql += " AND NOT disabled"
        with self.store.pool.connection() as conn:
            row = conn.execute(sql, tuple(params)).fetchone()
        return self._payload_from_row(row)

    def get_by_principal_username(
        self,
        principal_username: str,
        *,
        include_disabled: bool = False,
    ) -> Optional[Dict[str, Any]]:
        cleaned_principal = str(principal_username or "").strip()
        if not cleaned_principal:
            return None
        sql = """
            SELECT
                service_account_id,
                principal_username,
                display_name,
                description,
                service_key,
                created_by_username,
                disabled,
                metadata,
                created_at,
                updated_at
            FROM nm_service_accounts
            WHERE principal_username = %s
        """
        params: List[Any] = [cleaned_principal]
        if not include_disabled:
            sql += " AND NOT disabled"
        with self.store.pool.connection() as conn:
            row = conn.execute(sql, tuple(params)).fetchone()
        return self._payload_from_row(row)

    def upsert_service_account(
        self,
        service_account_id: str,
        *,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        service_key: Optional[str] = None,
        created_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        disabled: bool = False,
    ) -> Dict[str, Any]:
        cleaned_id = normalize_service_account_id(service_account_id)
        principal_username = service_account_principal_username(cleaned_id)
        cleaned_service_key = None
        if service_key not in (None, ""):
            cleaned_service_key = normalize_service_key(service_key)
        cleaned_created_by = str(created_by or "").strip() or None
        metadata_value = dict(metadata or {})
        with self.store.pool.connection() as conn:
            with conn.transaction():
                if cleaned_service_key and not self.store.access._service_exists(conn, cleaned_service_key):
                    raise ValueError("service_not_found")
                if cleaned_created_by and not self.store.access._user_exists(conn, cleaned_created_by):
                    raise ValueError("created_by_not_found")
                existing_user = conn.execute(
                    """
                    SELECT provider, subject
                    FROM nm_users
                    WHERE username = %s
                    """,
                    (principal_username,),
                ).fetchone()
                if existing_user and (
                    str(existing_user.get("provider") or "").strip() != SERVICE_ACCOUNT_PROVIDER
                    or str(existing_user.get("subject") or "").strip() != cleaned_id
                ):
                    raise ValueError("principal_username_conflict")
                self._ensure_principal_user(conn, cleaned_id, principal_username)
                conn.execute(
                    """
                    INSERT INTO nm_service_accounts (
                        service_account_id,
                        principal_username,
                        display_name,
                        description,
                        service_key,
                        created_by_username,
                        disabled,
                        created_at,
                        updated_at,
                        metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)
                    ON CONFLICT (service_account_id) DO UPDATE
                    SET display_name = EXCLUDED.display_name,
                        description = EXCLUDED.description,
                        service_key = COALESCE(EXCLUDED.service_key, nm_service_accounts.service_key),
                        disabled = EXCLUDED.disabled,
                        metadata = EXCLUDED.metadata,
                        updated_at = NOW()
                    """,
                    (
                        cleaned_id,
                        principal_username,
                        str(display_name or cleaned_id).strip() or cleaned_id,
                        str(description or "").strip() or None,
                        cleaned_service_key,
                        cleaned_created_by,
                        bool(disabled),
                        _jsonb(metadata_value),
                    ),
                )
        account = self.get_service_account(cleaned_id, include_disabled=True)
        if not account:
            raise RuntimeError("service_account_upsert_failed")
        return account

    def set_disabled(self, service_account_id: str, disabled: bool) -> Optional[Dict[str, Any]]:
        cleaned_id = normalize_service_account_id(service_account_id)
        with self.store.pool.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE nm_service_accounts
                    SET disabled = %s,
                        updated_at = NOW()
                    WHERE service_account_id = %s
                    RETURNING
                        service_account_id,
                        principal_username,
                        display_name,
                        description,
                        service_key,
                        created_by_username,
                        disabled,
                        metadata,
                        created_at,
                        updated_at
                    """,
                    (bool(disabled), cleaned_id),
                ).fetchone()
        return self._payload_from_row(row)


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

    def list_tokens(self, user: Optional[str] = None) -> List[Dict[str, Any]]:
        params: List[Any] = []
        sql = """
            SELECT id, username, label, created_at, expires_at, last_used_at, disabled, meta
            FROM nm_auth_tokens
            WHERE kind = 'access'
        """
        cleaned_user = str(user or "").strip()
        if cleaned_user:
            sql += " AND username = %s"
            params.append(cleaned_user)
        sql += " ORDER BY created_at DESC"
        with self.store.pool.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": row.get("id"),
                "user": row.get("username"),
                "label": row.get("label"),
                "created_at": _timestamp(row.get("created_at")),
                "expires_at": _timestamp(row.get("expires_at")),
                "last_used_at": _timestamp(row.get("last_used_at")),
                "disabled": bool(row.get("disabled")),
                "meta": row.get("meta") if isinstance(row.get("meta"), dict) else {},
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
                    WHERE id = %s AND kind = 'access'
                    RETURNING id
                    """,
                    (cleaned,),
                ).fetchone()
        return bool(row)


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
            return sum(
                1
                for entry in self.data.values()
                if isinstance(entry, dict)
                and str(entry.get("provider") or "").strip() != SERVICE_ACCOUNT_PROVIDER
            )

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
            if _service_account_conflict(self.get_user(username)):
                raise ValueError("principal_username_conflict")
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
            if _service_account_conflict(self.get_user(username)):
                raise ValueError("principal_username_conflict")
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

    def get_metadata(self, username: str) -> Dict[str, Any]:
        cleaned = str(username or "").strip()
        if not cleaned:
            return {}
        with self.lock:
            entry = self.data.get(cleaned) or {}
            metadata = entry.get("metadata")
        return dict(metadata) if isinstance(metadata, dict) else {}

    def set_metadata(self, username: str, metadata: Optional[Dict[str, Any]]) -> bool:
        cleaned = str(username or "").strip()
        if not cleaned:
            return False
        with self.lock:
            entry = self.data.get(cleaned)
            if not isinstance(entry, dict):
                return False
            entry["metadata"] = dict(metadata or {})
            entry["updated_at"] = _timestamp(dt.datetime.now(UTC))
            self._write()
            return True

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


class FileAccessControlStore:
    def __init__(self, path: Path, users: FileUserStore):
        self.path = path
        self.users = users
        self.lock = threading.RLock()
        payload = _read_json(
            path,
            {
                "version": 1,
                "groups": {},
                "memberships": {},
                "services": {},
                "grants": {},
            },
        )
        if not isinstance(payload, dict):
            payload = {
                "version": 1,
                "groups": {},
                "memberships": {},
                "services": {},
                "grants": {},
            }
        for key in ("groups", "memberships", "services", "grants"):
            if not isinstance(payload.get(key), dict):
                payload[key] = {}
        self.data = payload

    def _write(self) -> None:
        _write_json_atomic(self.path, self.data)

    def _timestamp_now(self) -> str:
        return _timestamp(dt.datetime.now(UTC)) or ""

    @staticmethod
    def _membership_id(group_key: str, username: str) -> str:
        return f"{group_key}:{username}"

    @staticmethod
    def _grant_id(group_key: str, service_key: str) -> str:
        return f"{group_key}:{service_key}"

    @staticmethod
    def _group_payload(entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict):
            return None
        group_key = str(entry.get("key") or "").strip().lower()
        if not group_key:
            return None
        return {
            "key": group_key,
            "name": str(entry.get("name") or group_key).strip() or group_key,
            "parent_key": str(entry.get("parent_key") or "").strip().lower() or None,
            "system": bool(entry.get("system")),
            "metadata": dict(entry.get("metadata")) if isinstance(entry.get("metadata"), dict) else {},
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
        }

    def _membership_payload(self, entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict):
            return None
        group_key = str(entry.get("group_key") or "").strip().lower()
        username = str(entry.get("username") or "").strip()
        if not group_key or not username:
            return None
        group = self.data.get("groups", {}).get(group_key) or {}
        return {
            "group_key": group_key,
            "group_name": str(group.get("name") or group_key).strip() or group_key,
            "parent_key": str(group.get("parent_key") or "").strip().lower() or None,
            "system": bool(group.get("system")),
            "username": username,
            "membership_role": normalize_group_membership_role(entry.get("membership_role")),
            "metadata": dict(entry.get("metadata")) if isinstance(entry.get("metadata"), dict) else {},
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
        }

    @staticmethod
    def _service_payload(entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict):
            return None
        service_key = str(entry.get("service_key") or "").strip().lower()
        if not service_key:
            return None
        return {
            "service_key": service_key,
            "display_name": str(entry.get("display_name") or service_key).strip() or service_key,
            "description": str(entry.get("description") or "").strip() or None,
            "public_access_level": normalize_service_access_level(
                entry.get("public_access_level"),
                default=SERVICE_ACCESS_NONE,
            ),
            "dashboard_url": str(entry.get("dashboard_url") or "").strip() or None,
            "marketing_url": str(entry.get("marketing_url") or "").strip() or None,
            "metadata": dict(entry.get("metadata")) if isinstance(entry.get("metadata"), dict) else {},
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
        }

    def _grant_payload(self, entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict):
            return None
        group_key = str(entry.get("group_key") or "").strip().lower()
        service_key = str(entry.get("service_key") or "").strip().lower()
        if not group_key or not service_key:
            return None
        service = self.data.get("services", {}).get(service_key) or {}
        payload: Dict[str, Any] = {
            "group_key": group_key,
            "service_key": service_key,
            "access_level": normalize_service_access_level(entry.get("access_level")),
            "granted_by": str(entry.get("granted_by") or "").strip() or None,
            "metadata": dict(entry.get("metadata")) if isinstance(entry.get("metadata"), dict) else {},
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
        }
        if service:
            payload["display_name"] = str(service.get("display_name") or service_key).strip() or service_key
            payload["public_access_level"] = normalize_service_access_level(
                service.get("public_access_level"),
                default=SERVICE_ACCESS_NONE,
            )
        return payload

    def bootstrap_contract(self, payload: Optional[Dict[str, Any]] = None) -> None:
        contract = payload if isinstance(payload, dict) else bootstrap_authorization_contract()
        groups = contract.get("groups") if isinstance(contract.get("groups"), list) else []
        services = contract.get("services") if isinstance(contract.get("services"), list) else []
        grants = contract.get("grants") if isinstance(contract.get("grants"), list) else []
        with self.lock:
            for group in PostgresAccessControlStore._ordered_groups([dict(item) for item in groups if isinstance(item, dict)]):
                try:
                    self._upsert_group_locked(group)
                except ValueError:
                    continue
            for service in services:
                if not isinstance(service, dict):
                    continue
                try:
                    self._upsert_service_locked(service)
                except ValueError:
                    continue
            for grant in grants:
                if not isinstance(grant, dict):
                    continue
                try:
                    self._upsert_group_service_grant_locked(grant)
                except ValueError:
                    continue
            self._write()

    def list_groups(self) -> List[Dict[str, Any]]:
        with self.lock:
            values = [dict(item) for item in self.data.get("groups", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in sorted(values, key=lambda item: str(item.get("key") or "")):
            normalized = self._group_payload(entry)
            if normalized:
                payload.append(normalized)
        return payload

    def get_group(self, group_key: str) -> Optional[Dict[str, Any]]:
        cleaned = normalize_group_key(group_key)
        with self.lock:
            entry = dict(self.data.get("groups", {}).get(cleaned) or {})
        return self._group_payload(entry)

    def _upsert_group_locked(self, payload: Dict[str, Any]) -> None:
        group_key = normalize_group_key(payload.get("key") or payload.get("group_key"))
        parent_raw = payload.get("parent_key") or payload.get("parent_id")
        parent_key = None
        if parent_raw not in (None, ""):
            parent_key = normalize_group_key(parent_raw)
            if parent_key == group_key:
                raise ValueError("group_parent_cycle")
            if parent_key not in self.data.get("groups", {}):
                raise ValueError("parent_group_not_found")
        existing = self.data.get("groups", {}).get(group_key) or {}
        metadata = payload.get("metadata")
        if metadata is None and isinstance(existing.get("metadata"), dict):
            metadata = dict(existing.get("metadata") or {})
        now = self._timestamp_now()
        self.data.setdefault("groups", {})[group_key] = {
            "key": group_key,
            "name": str(payload.get("name") or existing.get("name") or group_key).strip() or group_key,
            "parent_key": parent_key,
            "system": bool(payload.get("system")) or bool(existing.get("system")),
            "metadata": dict(metadata or {}),
            "created_at": existing.get("created_at") or now,
            "updated_at": now,
        }

    def upsert_group(
        self,
        group_key: str,
        *,
        name: Optional[str] = None,
        parent_key: Optional[str] = None,
        system: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned = normalize_group_key(group_key)
        with self.lock:
            self._upsert_group_locked(
                {
                    "key": cleaned,
                    "name": name,
                    "parent_key": parent_key,
                    "system": system,
                    "metadata": dict(metadata or {}) if metadata is not None else None,
                }
            )
            self._write()
            entry = dict(self.data.get("groups", {}).get(cleaned) or {})
        group = self._group_payload(entry)
        if not group:
            raise RuntimeError("group_upsert_failed")
        return group

    def list_group_memberships(
        self,
        *,
        group_key: Optional[str] = None,
        username: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        cleaned_group = normalize_group_key(group_key) if group_key else None
        cleaned_user = str(username or "").strip() or None
        with self.lock:
            entries = [dict(item) for item in self.data.get("memberships", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in sorted(entries, key=lambda item: (str(item.get("group_key") or ""), str(item.get("username") or ""))):
            if cleaned_group and str(entry.get("group_key") or "").strip().lower() != cleaned_group:
                continue
            if cleaned_user and str(entry.get("username") or "").strip() != cleaned_user:
                continue
            normalized = self._membership_payload(entry)
            if normalized:
                payload.append(normalized)
        return payload

    def upsert_group_membership(
        self,
        group_key: str,
        username: str,
        *,
        membership_role: str = GROUP_MEMBERSHIP_ROLE_MEMBER,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned_group = normalize_group_key(group_key)
        cleaned_user = str(username or "").strip()
        if not cleaned_user:
            raise ValueError("username_required")
        role_value = normalize_group_membership_role(membership_role)
        now = self._timestamp_now()
        with self.lock:
            if cleaned_group not in self.data.get("groups", {}):
                raise ValueError("group_not_found")
            if not self.users.get_user(cleaned_user):
                raise ValueError("user_not_found")
            membership_id = self._membership_id(cleaned_group, cleaned_user)
            existing = self.data.get("memberships", {}).get(membership_id) or {}
            self.data.setdefault("memberships", {})[membership_id] = {
                "group_key": cleaned_group,
                "username": cleaned_user,
                "membership_role": role_value,
                "metadata": dict(metadata or {}),
                "created_at": existing.get("created_at") or now,
                "updated_at": now,
            }
            self._write()
            entry = dict(self.data.get("memberships", {}).get(membership_id) or {})
        membership = self._membership_payload(entry)
        if not membership:
            raise RuntimeError("group_membership_upsert_failed")
        return membership

    def delete_group_membership(self, group_key: str, username: str) -> bool:
        cleaned_group = normalize_group_key(group_key)
        cleaned_user = str(username or "").strip()
        if not cleaned_user:
            return False
        with self.lock:
            membership_id = self._membership_id(cleaned_group, cleaned_user)
            if membership_id not in self.data.get("memberships", {}):
                return False
            self.data["memberships"].pop(membership_id, None)
            self._write()
        return True

    def _upsert_service_locked(self, payload: Dict[str, Any]) -> None:
        service_key = normalize_service_key(payload.get("service_key") or payload.get("key"))
        existing = self.data.get("services", {}).get(service_key) or {}
        metadata = payload.get("metadata")
        if metadata is None and isinstance(existing.get("metadata"), dict):
            metadata = dict(existing.get("metadata") or {})
        now = self._timestamp_now()
        self.data.setdefault("services", {})[service_key] = {
            "service_key": service_key,
            "display_name": str(payload.get("display_name") or existing.get("display_name") or service_key).strip() or service_key,
            "description": str(
                payload.get("description")
                if payload.get("description") is not None
                else existing.get("description") or ""
            ).strip() or None,
            "public_access_level": normalize_service_access_level(
                payload.get("public_access_level"),
                default=SERVICE_ACCESS_NONE,
            ),
            "dashboard_url": str(
                payload.get("dashboard_url")
                if payload.get("dashboard_url") is not None
                else existing.get("dashboard_url") or ""
            ).strip() or None,
            "marketing_url": str(
                payload.get("marketing_url")
                if payload.get("marketing_url") is not None
                else existing.get("marketing_url") or ""
            ).strip() or None,
            "metadata": dict(metadata or {}),
            "created_at": existing.get("created_at") or now,
            "updated_at": now,
        }

    def list_services(self) -> List[Dict[str, Any]]:
        with self.lock:
            values = [dict(item) for item in self.data.get("services", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in sorted(values, key=lambda item: str(item.get("service_key") or "")):
            normalized = self._service_payload(entry)
            if normalized:
                payload.append(normalized)
        return payload

    def get_service(self, service_key: str) -> Optional[Dict[str, Any]]:
        cleaned = normalize_service_key(service_key)
        with self.lock:
            entry = dict(self.data.get("services", {}).get(cleaned) or {})
        return self._service_payload(entry)

    def upsert_service(
        self,
        service_key: str,
        *,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        public_access_level: str = SERVICE_ACCESS_NONE,
        dashboard_url: Optional[str] = None,
        marketing_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned = normalize_service_key(service_key)
        with self.lock:
            self._upsert_service_locked(
                {
                    "service_key": cleaned,
                    "display_name": display_name,
                    "description": description,
                    "public_access_level": public_access_level,
                    "dashboard_url": dashboard_url,
                    "marketing_url": marketing_url,
                    "metadata": dict(metadata or {}) if metadata is not None else None,
                }
            )
            self._write()
            entry = dict(self.data.get("services", {}).get(cleaned) or {})
        service = self._service_payload(entry)
        if not service:
            raise RuntimeError("service_upsert_failed")
        return service

    def _upsert_group_service_grant_locked(self, payload: Dict[str, Any]) -> None:
        group_key = normalize_group_key(payload.get("group_key"))
        service_key = normalize_service_key(payload.get("service_key"))
        if group_key not in self.data.get("groups", {}):
            raise ValueError("group_not_found")
        if service_key not in self.data.get("services", {}):
            raise ValueError("service_not_found")
        existing = self.data.get("grants", {}).get(self._grant_id(group_key, service_key)) or {}
        granted_by_raw = str(payload.get("granted_by") or "").strip() or None
        if granted_by_raw and not self.users.get_user(granted_by_raw):
            granted_by_raw = None
        now = self._timestamp_now()
        self.data.setdefault("grants", {})[self._grant_id(group_key, service_key)] = {
            "group_key": group_key,
            "service_key": service_key,
            "access_level": normalize_service_access_level(payload.get("access_level")),
            "granted_by": granted_by_raw,
            "metadata": dict(payload.get("metadata") or {}),
            "created_at": existing.get("created_at") or now,
            "updated_at": now,
        }

    def list_group_service_grants(
        self,
        *,
        group_key: Optional[str] = None,
        service_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        cleaned_group = normalize_group_key(group_key) if group_key else None
        cleaned_service = normalize_service_key(service_key) if service_key else None
        with self.lock:
            entries = [dict(item) for item in self.data.get("grants", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in sorted(entries, key=lambda item: (str(item.get("group_key") or ""), str(item.get("service_key") or ""))):
            if cleaned_group and str(entry.get("group_key") or "").strip().lower() != cleaned_group:
                continue
            if cleaned_service and str(entry.get("service_key") or "").strip().lower() != cleaned_service:
                continue
            normalized = self._grant_payload(entry)
            if normalized:
                payload.append(normalized)
        return payload

    def get_group_service_grant(self, group_key: str, service_key: str) -> Optional[Dict[str, Any]]:
        grants = self.list_group_service_grants(group_key=group_key, service_key=service_key)
        return grants[0] if grants else None

    def upsert_group_service_grant(
        self,
        group_key: str,
        service_key: str,
        *,
        access_level: str,
        granted_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cleaned_group = normalize_group_key(group_key)
        cleaned_service = normalize_service_key(service_key)
        with self.lock:
            self._upsert_group_service_grant_locked(
                {
                    "group_key": cleaned_group,
                    "service_key": cleaned_service,
                    "access_level": access_level,
                    "granted_by": granted_by,
                    "metadata": dict(metadata or {}) if metadata is not None else None,
                }
            )
            self._write()
            entry = dict(self.data.get("grants", {}).get(self._grant_id(cleaned_group, cleaned_service)) or {})
        grant = self._grant_payload(entry)
        if not grant:
            raise RuntimeError("group_service_grant_upsert_failed")
        return grant

    def delete_group_service_grant(self, group_key: str, service_key: str) -> bool:
        cleaned_group = normalize_group_key(group_key)
        cleaned_service = normalize_service_key(service_key)
        with self.lock:
            grant_id = self._grant_id(cleaned_group, cleaned_service)
            if grant_id not in self.data.get("grants", {}):
                return False
            self.data["grants"].pop(grant_id, None)
            self._write()
        return True


class FileServiceAccountStore:
    def __init__(self, path: Path, users: FileUserStore, access: FileAccessControlStore):
        self.path = path
        self.users = users
        self.access = access
        self.lock = threading.RLock()
        payload = _read_json(path, {"version": 1, "service_accounts": {}})
        if not isinstance(payload, dict):
            payload = {"version": 1, "service_accounts": {}}
        if not isinstance(payload.get("service_accounts"), dict):
            payload["service_accounts"] = {}
        self.data = payload

    def _write(self) -> None:
        _write_json_atomic(self.path, self.data)

    def _timestamp_now(self) -> str:
        return _timestamp(dt.datetime.now(UTC)) or ""

    @staticmethod
    def _payload(entry: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(entry, dict):
            return None
        service_account_id = str(entry.get("service_account_id") or "").strip().lower()
        principal_username = str(entry.get("principal_username") or "").strip()
        if not service_account_id or not principal_username:
            return None
        return {
            "service_account_id": service_account_id,
            "principal_username": principal_username,
            "display_name": str(entry.get("display_name") or service_account_id).strip() or service_account_id,
            "description": str(entry.get("description") or "").strip() or None,
            "service_key": str(entry.get("service_key") or "").strip().lower() or None,
            "created_by": str(entry.get("created_by") or entry.get("created_by_username") or "").strip() or None,
            "disabled": bool(entry.get("disabled")),
            "metadata": dict(entry.get("metadata")) if isinstance(entry.get("metadata"), dict) else {},
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
        }

    def list_service_accounts(self, *, include_disabled: bool = False) -> List[Dict[str, Any]]:
        with self.lock:
            items = [dict(item) for item in self.data.get("service_accounts", {}).values() if isinstance(item, dict)]
        payload: List[Dict[str, Any]] = []
        for entry in sorted(items, key=lambda item: str(item.get("service_account_id") or "")):
            normalized = self._payload(entry)
            if not normalized:
                continue
            if normalized.get("disabled") and not include_disabled:
                continue
            payload.append(normalized)
        return payload

    def get_service_account(
        self,
        service_account_id: str,
        *,
        include_disabled: bool = False,
    ) -> Optional[Dict[str, Any]]:
        cleaned_id = normalize_service_account_id(service_account_id)
        with self.lock:
            entry = dict(self.data.get("service_accounts", {}).get(cleaned_id) or {})
        normalized = self._payload(entry)
        if normalized and (include_disabled or not normalized.get("disabled")):
            return normalized
        return None

    def get_by_principal_username(
        self,
        principal_username: str,
        *,
        include_disabled: bool = False,
    ) -> Optional[Dict[str, Any]]:
        cleaned_principal = str(principal_username or "").strip()
        if not cleaned_principal:
            return None
        with self.lock:
            items = [dict(item) for item in self.data.get("service_accounts", {}).values() if isinstance(item, dict)]
        for entry in items:
            if str(entry.get("principal_username") or "").strip() != cleaned_principal:
                continue
            normalized = self._payload(entry)
            if normalized and (include_disabled or not normalized.get("disabled")):
                return normalized
        return None

    def upsert_service_account(
        self,
        service_account_id: str,
        *,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        service_key: Optional[str] = None,
        created_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        disabled: bool = False,
    ) -> Dict[str, Any]:
        cleaned_id = normalize_service_account_id(service_account_id)
        cleaned_service_key = None
        if service_key not in (None, ""):
            cleaned_service_key = normalize_service_key(service_key)
            if not self.access.get_service(cleaned_service_key):
                raise ValueError("service_not_found")
        cleaned_created_by = str(created_by or "").strip() or None
        if cleaned_created_by and not self.users.get_user(cleaned_created_by):
            raise ValueError("created_by_not_found")
        principal_username = service_account_principal_username(cleaned_id)
        existing_user = self.users.get_user(principal_username)
        if existing_user and not (
            _is_service_account_provider(existing_user)
            and str(existing_user.get("subject") or "").strip() == cleaned_id
        ):
            raise ValueError("principal_username_conflict")
        self.users.upsert_external_user(
            principal_username,
            role="user",
            provider=SERVICE_ACCOUNT_PROVIDER,
            subject=cleaned_id,
        )
        now = self._timestamp_now()
        with self.lock:
            existing = dict(self.data.get("service_accounts", {}).get(cleaned_id) or {})
            self.data.setdefault("service_accounts", {})[cleaned_id] = {
                "service_account_id": cleaned_id,
                "principal_username": principal_username,
                "display_name": str(display_name or existing.get("display_name") or cleaned_id).strip() or cleaned_id,
                "description": str(
                    description if description is not None else existing.get("description") or ""
                ).strip()
                or None,
                "service_key": cleaned_service_key or existing.get("service_key"),
                "created_by": existing.get("created_by") or cleaned_created_by,
                "disabled": bool(disabled),
                "metadata": dict(metadata or existing.get("metadata") or {}),
                "created_at": existing.get("created_at") or now,
                "updated_at": now,
            }
            self._write()
            entry = dict(self.data.get("service_accounts", {}).get(cleaned_id) or {})
        account = self._payload(entry)
        if not account:
            raise RuntimeError("service_account_upsert_failed")
        return account

    def set_disabled(self, service_account_id: str, disabled: bool) -> Optional[Dict[str, Any]]:
        cleaned_id = normalize_service_account_id(service_account_id)
        now = self._timestamp_now()
        with self.lock:
            entry = self.data.get("service_accounts", {}).get(cleaned_id)
            if not isinstance(entry, dict):
                return None
            entry["disabled"] = bool(disabled)
            entry["updated_at"] = now
            self._write()
            updated = dict(entry)
        return self._payload(updated)


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

    def list_tokens(self, user: Optional[str] = None) -> List[Dict[str, Any]]:
        cleaned_user = str(user or "").strip() or None
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
        rows: List[Dict[str, Any]] = []
        for entry in tokens:
            if entry.get("kind") != "access":
                continue
            if cleaned_user and str(entry.get("username") or "").strip() != cleaned_user:
                continue
            rows.append(
                {
                    "id": entry.get("id"),
                    "user": entry.get("username"),
                    "label": entry.get("label"),
                    "created_at": entry.get("created_at"),
                    "expires_at": entry.get("expires_at"),
                    "last_used_at": entry.get("last_used_at"),
                    "disabled": bool(entry.get("disabled")),
                    "meta": dict(entry.get("meta") or {}),
                }
            )
        rows.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return rows

    def revoke(self, token_id: str) -> bool:
        cleaned = str(token_id or "").strip()
        if not cleaned:
            return False
        with self.lock:
            tokens = [item for item in self.data.get("tokens", []) if isinstance(item, dict)]
            updated = False
            for entry in tokens:
                if entry.get("id") != cleaned or entry.get("kind") != "access":
                    continue
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
        self.access = FileAccessControlStore(base / "access_control.json", self.users)
        self.service_accounts = FileServiceAccountStore(
            base / "service_accounts.json",
            self.users,
            self.access,
        )
        self.access_tokens = FileTokenStore(base / "auth_tokens.json")
        self.voice_tokens = FileVoiceTokenStore(self.access_tokens)
        self.sso_tokens = FileSsoStore(self.access_tokens)

    def close(self) -> None:
        return None

    def bootstrap_from_env(self, default_user: str = "") -> None:
        self.access.bootstrap_contract()
        raw_service_accounts = (
            os.getenv("CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNTS")
            or os.getenv("CUSTOMERS_SERVICE_ACCOUNTS_JSON")
            or ""
        ).strip()
        if raw_service_accounts:
            try:
                service_accounts_payload = json.loads(raw_service_accounts)
            except Exception:
                service_accounts_payload = None
            if isinstance(service_accounts_payload, list):
                for item in service_accounts_payload:
                    if not isinstance(item, dict):
                        continue
                    try:
                        service_account_id = normalize_service_account_id(
                            item.get("service_account_id") or item.get("id") or item.get("key")
                        )
                    except ValueError:
                        continue
                    try:
                        account = self.service_accounts.upsert_service_account(
                            service_account_id,
                            display_name=str(
                                item.get("display_name") or item.get("name") or service_account_id
                            ).strip()
                            or service_account_id,
                            description=str(item.get("description") or "").strip() or None,
                            service_key=item.get("service_key") or item.get("service"),
                            created_by=item.get("created_by") or default_user or None,
                            metadata=item.get("metadata") if isinstance(item.get("metadata"), dict) else None,
                            disabled=bool(item.get("disabled")),
                        )
                    except ValueError:
                        continue
                    for group_key in _service_account_group_keys(item):
                        try:
                            self.access.upsert_group_membership(
                                group_key,
                                str(account.get("principal_username") or "").strip(),
                                membership_role=GROUP_MEMBERSHIP_ROLE_MEMBER,
                            )
                        except ValueError:
                            continue
        raw = (
            os.getenv("CUSTOMERS_BOOTSTRAP_ACCESS_TOKENS")
            or os.getenv("REFINER_BOOTSTRAP_ACCESS_TOKENS")
            or ""
        ).strip()
        if raw:
            try:
                payload = json.loads(raw)
            except Exception:
                payload = None
            if isinstance(payload, list):
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
        raw_service_account_tokens = (
            os.getenv("CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNT_TOKENS")
            or os.getenv("CUSTOMERS_SERVICE_ACCOUNT_TOKENS_JSON")
            or ""
        ).strip()
        if not raw_service_account_tokens:
            return
        try:
            service_account_token_payload = json.loads(raw_service_account_tokens)
        except Exception:
            return
        if not isinstance(service_account_token_payload, list):
            return
        for item in service_account_token_payload:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token") or "").strip()
            if not token:
                continue
            service_account_id_raw = item.get("service_account_id") or item.get("id") or item.get("key")
            try:
                service_account_id = normalize_service_account_id(service_account_id_raw)
            except ValueError:
                continue
            account = self.service_accounts.get_service_account(service_account_id, include_disabled=True)
            if not account:
                continue
            label = str(item.get("label") or "").strip() or None
            ttl_seconds = item.get("ttl_seconds")
            meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
            meta = {
                **meta,
                "identity_type": "service_account",
                "service_account_id": service_account_id,
            }
            self.access_tokens.ensure_token(
                str(account.get("principal_username") or "").strip(),
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
