from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        cleaned = value.strip()
        if cleaned:
            return cleaned
    return default


def env_bool(*names: str, default: bool = False) -> bool:
    raw = env_first(*names, default="")
    if not raw:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(*names: str, default: int) -> int:
    raw = env_first(*names, default="")
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def env_list(*names: str) -> List[str]:
    raw = env_first(*names, default="")
    if not raw:
        return []
    values = [item.strip() for item in raw.split(",")]
    return [item for item in values if item]


def parse_app_tokens(raw: str) -> Dict[str, str]:
    tokens: Dict[str, str] = {}
    for part in (raw or "").split(","):
        chunk = part.strip()
        if not chunk:
            continue
        if "=" in chunk:
            app_id, token = chunk.split("=", 1)
        elif ":" in chunk:
            app_id, token = chunk.split(":", 1)
        else:
            continue
        app_id = app_id.strip()
        token = token.strip()
        if app_id and token:
            tokens[app_id] = token
    return tokens


@dataclass(slots=True)
class Settings:
    service_name: str
    version: str
    host: str
    port: int
    secret_key: str
    require_secret_key: bool
    session_cookie_name: str
    site_base: str
    api_base: str
    cookie_domain: Optional[str]
    cookie_samesite: str
    secure_cookies: bool
    enforce_https: bool
    cors_origins: List[str]
    state_dir: str
    auth_mode: str
    password_min_length: int
    oidc_enabled: bool
    oidc_exchange_enabled: bool
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_uri: str
    oidc_scope: str
    oidc_username_claim: str
    oidc_email_claim: str
    oidc_groups_claim: str
    oidc_admin_domains: List[str]
    oidc_admin_groups: List[str]
    oidc_discovery_ttl: int
    oidc_jwt_leeway: int
    oidc_skip_jwt_verify: bool
    oidc_use_userinfo: bool
    oidc_button_label: str
    oidc_require_config: bool
    oidc_client_auth: str
    oidc_allowed_audiences: List[str]
    oidc_allowed_redirect_uris: List[str]
    oidc_extra_params: str
    sso_ttl_seconds: int
    sso_store_mode: str
    sso_redis_url: Optional[str]
    sso_redis_prefix: str
    app_tokens: Dict[str, str]
    allow_setup: bool
    self_registration_enabled: bool

    @classmethod
    def from_env(cls) -> "Settings":
        auth_mode = env_first("CUSTOMERS_AUTH_MODE", "NM_AUTH_MODE", default="local").lower()
        if auth_mode not in {"local", "oidc", "mixed"}:
            auth_mode = "local"

        api_base = env_first("CUSTOMERS_API_BASE", "NEURALMIMICRY_API_BASE")
        site_base = env_first("NEURALMIMICRY_SITE_BASE", default="https://neuralmimicry.ai")
        cookie_samesite = env_first("CUSTOMERS_COOKIE_SAMESITE", default="") or (
            "None" if env_list("CUSTOMERS_CORS_ORIGINS") else "Lax"
        )
        secure_cookies = env_bool("CUSTOMERS_SECURE_COOKIES", default=(cookie_samesite == "None"))
        secret_key = env_first("CUSTOMERS_SECRET_KEY", "REFINER_SECRET_KEY")
        require_secret_key = env_bool("CUSTOMERS_REQUIRE_SECRET_KEY", default=False)
        if require_secret_key and not secret_key:
            raise RuntimeError("CUSTOMERS_SECRET_KEY is required when CUSTOMERS_REQUIRE_SECRET_KEY is enabled.")
        if not secret_key:
            secret_key = "customers-dev-secret-key-change-me"

        oidc_enabled = env_bool(
            "CUSTOMERS_OIDC_ENABLED",
            "NM_OIDC_ENABLED",
            default=(auth_mode in {"oidc", "mixed"}),
        )
        oidc_exchange_enabled = env_bool(
            "CUSTOMERS_OIDC_EXCHANGE_ENABLED",
            "NM_OIDC_EXCHANGE_ENABLED",
            default=oidc_enabled,
        )

        return cls(
            service_name=env_first("CUSTOMERS_SERVICE_NAME", default="customers"),
            version=env_first("CUSTOMERS_VERSION", default="0.1.0"),
            host=env_first("CUSTOMERS_HOST", default="0.0.0.0"),
            port=env_int("CUSTOMERS_PORT", default=5010),
            secret_key=secret_key,
            require_secret_key=require_secret_key,
            session_cookie_name=env_first("CUSTOMERS_SESSION_COOKIE_NAME", default="nm_customers_session"),
            site_base=site_base.rstrip("/"),
            api_base=api_base.rstrip("/"),
            cookie_domain=(env_first("CUSTOMERS_COOKIE_DOMAIN") or None),
            cookie_samesite=cookie_samesite,
            secure_cookies=secure_cookies,
            enforce_https=env_bool("CUSTOMERS_ENFORCE_HTTPS", default=False),
            cors_origins=env_list("CUSTOMERS_CORS_ORIGINS") or ([site_base.rstrip("/")] if site_base else []),
            state_dir=env_first("CUSTOMERS_STATE_DIR", default="data"),
            auth_mode=auth_mode,
            password_min_length=max(8, env_int("CUSTOMERS_PASSWORD_MIN_LENGTH", default=12)),
            oidc_enabled=oidc_enabled,
            oidc_exchange_enabled=oidc_exchange_enabled,
            oidc_issuer=env_first("CUSTOMERS_OIDC_ISSUER", "NM_OIDC_ISSUER"),
            oidc_client_id=env_first("CUSTOMERS_OIDC_CLIENT_ID", "NM_OIDC_CLIENT_ID"),
            oidc_client_secret=env_first("CUSTOMERS_OIDC_CLIENT_SECRET", "NM_OIDC_CLIENT_SECRET"),
            oidc_redirect_uri=env_first("CUSTOMERS_OIDC_REDIRECT_URI", "NM_OIDC_REDIRECT_URI", "NM_OIDC_REDIRECT_URL"),
            oidc_scope=env_first("CUSTOMERS_OIDC_SCOPE", "NM_OIDC_SCOPE", default="openid email profile"),
            oidc_username_claim=env_first("CUSTOMERS_OIDC_USERNAME_CLAIM", "NM_OIDC_USERNAME_CLAIM", default="email"),
            oidc_email_claim=env_first("CUSTOMERS_OIDC_EMAIL_CLAIM", "NM_OIDC_EMAIL_CLAIM", default="email"),
            oidc_groups_claim=env_first("CUSTOMERS_OIDC_GROUPS_CLAIM", "NM_OIDC_GROUPS_CLAIM", default="groups"),
            oidc_admin_domains=env_list("CUSTOMERS_OIDC_ADMIN_DOMAINS", "NM_OIDC_ADMIN_DOMAINS"),
            oidc_admin_groups=env_list("CUSTOMERS_OIDC_ADMIN_GROUPS", "NM_OIDC_ADMIN_GROUPS"),
            oidc_discovery_ttl=max(60, env_int("CUSTOMERS_OIDC_DISCOVERY_TTL", default=3600)),
            oidc_jwt_leeway=max(0, env_int("CUSTOMERS_OIDC_JWT_LEEWAY", default=120)),
            oidc_skip_jwt_verify=env_bool("CUSTOMERS_OIDC_SKIP_JWT_VERIFY", "NM_OIDC_SKIP_JWT_VERIFY", default=False),
            oidc_use_userinfo=env_bool("CUSTOMERS_OIDC_USE_USERINFO", "NM_OIDC_USE_USERINFO", default=False),
            oidc_button_label=env_first("CUSTOMERS_OIDC_BUTTON_LABEL", "NM_OIDC_BUTTON_LABEL", default="Sign in with SSO"),
            oidc_require_config=env_bool("CUSTOMERS_OIDC_REQUIRE_CONFIG", "NM_OIDC_REQUIRE_CONFIG", default=True),
            oidc_client_auth=env_first("CUSTOMERS_OIDC_CLIENT_AUTH", "NM_OIDC_CLIENT_AUTH", default="basic").lower(),
            oidc_allowed_audiences=env_list(
                "CUSTOMERS_OIDC_ALLOWED_AUDIENCES",
                "CUSTOMERS_OIDC_AUDIENCE",
                "NM_OIDC_ALLOWED_AUDIENCES",
                "NM_OIDC_AUDIENCE",
            ),
            oidc_allowed_redirect_uris=env_list("CUSTOMERS_OIDC_ALLOWED_REDIRECT_URIS", "NM_OIDC_ALLOWED_REDIRECT_URIS"),
            oidc_extra_params=env_first("CUSTOMERS_OIDC_EXTRA_PARAMS", default=""),
            sso_ttl_seconds=max(30, env_int("CUSTOMERS_SSO_TTL", default=300)),
            sso_store_mode=env_first("CUSTOMERS_SSO_STORE", default="auto").lower(),
            sso_redis_url=(env_first("CUSTOMERS_SSO_REDIS_URL", "REDIS_URL") or None),
            sso_redis_prefix=env_first("CUSTOMERS_SSO_REDIS_PREFIX", default="customers:sso:"),
            app_tokens=parse_app_tokens(env_first("CUSTOMERS_APP_TOKENS", default="")),
            allow_setup=env_bool("CUSTOMERS_ALLOW_SETUP", default=True),
            self_registration_enabled=env_bool("CUSTOMERS_SELF_REGISTRATION_ENABLED", default=False),
        )
