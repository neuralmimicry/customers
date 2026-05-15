from __future__ import annotations

import atexit
import base64
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

import requests
from flask import (
    Flask,
    Response,
    current_app,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .authorization import (
    GROUP_MEMBERSHIP_ROLE_MANAGER,
    SERVICE_ACCESS_NONE,
    manageable_group_keys_for_user,
    normalize_group_key,
    normalize_group_membership_role,
    normalize_service_access_level,
    normalize_service_key,
    resolve_group_effective_grants,
    resolve_user_service_access,
    service_access_at_least,
    visible_group_keys_for_user,
)
from .auth_security import (
    build_totp_enrolment,
    ensure_passkey_user_id,
    find_passkey,
    generate_totp_secret,
    metadata_with_security_state,
    passkey_authentication_options,
    passkey_registration_options,
    security_state_from_metadata,
    security_summary,
    verify_passkey_authentication,
    verify_passkey_registration,
    verify_totp_code,
)
from .config import Settings
from .nmchain_client import NmChainClient
from .store import (
    ALLOWED_USER_ROLES,
    GROUP_SYSTEM_KEYS,
    SERVICE_ACCOUNT_PROVIDER,
    TEAM_MEMBERSHIP_STATUS_ACTIVE,
    TEAM_MEMBERSHIP_STATUS_PENDING,
    create_central_store_from_env,
    normalize_service_account_id,
)
from .profile_settings import (
    SettingsValidationError,
    default_settings as default_user_settings,
    metadata_with_settings,
    settings_from_metadata,
    validate_settings_patch,
)

logger = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LOGIN_MAX_ATTEMPTS = int(os.getenv("CUSTOMERS_LOGIN_MAX_ATTEMPTS") or "6")
LOGIN_WINDOW_SEC = int(os.getenv("CUSTOMERS_LOGIN_WINDOW_SEC") or "600")

_OIDC_CACHE: Dict[str, Any] = {"config_ts": 0.0, "jwks_ts": 0.0, "config": None, "jwks": None}
_OIDC_CACHE_LOCK = threading.Lock()
_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
_LOGIN_ATTEMPTS_LOCK = threading.Lock()
_IDENTITY_CACHE_KEY = "_nm_current_identity"
_IDENTITY_CACHE_MISS = object()
_PENDING_LOGIN_SESSION_KEY = "nm_pending_login"
_PENDING_TOTP_SETUP_SESSION_KEY = "nm_pending_totp_setup"
_PENDING_PASSKEY_REGISTRATION_SESSION_KEY = "nm_pending_passkey_registration"
_PENDING_PASSKEY_AUTHENTICATION_SESSION_KEY = "nm_pending_passkey_authentication"


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return max(minimum, default)
    try:
        return max(minimum, int(raw))
    except Exception:
        return max(minimum, default)


def _env_float(name: str, default: float, *, minimum: float = 0.1) -> float:
    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return max(minimum, default)
    try:
        return max(minimum, float(raw))
    except Exception:
        return max(minimum, default)


_API_EXCHANGE_MAX_WORKERS = _env_int("CUSTOMERS_API_EXCHANGE_WORKERS", 16, minimum=4)
_API_EXCHANGE_WAIT_TIMEOUT_SEC = _env_float("CUSTOMERS_API_EXCHANGE_WAIT_TIMEOUT", 20.0, minimum=1.0)
_OIDC_HTTP_TIMEOUT_SEC = _env_float("CUSTOMERS_OIDC_HTTP_TIMEOUT", 12.0, minimum=1.0)
_OIDC_TOKEN_TIMEOUT_SEC = _env_float("CUSTOMERS_OIDC_TOKEN_TIMEOUT", 15.0, minimum=1.0)
_API_EXCHANGE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=_API_EXCHANGE_MAX_WORKERS,
    thread_name_prefix="customers-api",
)
atexit.register(_API_EXCHANGE_EXECUTOR.shutdown, wait=False, cancel_futures=True)


def _settings() -> Settings:
    return current_app.extensions["nm_settings"]


def _store() -> Any:
    return current_app.extensions["nm_store"]


def _service_account_store() -> Any:
    return _store().service_accounts


def _nmchain() -> Optional[NmChainClient]:
    return current_app.extensions.get("nmchain")


def _store_backend_name() -> str:
    store = _store()
    return getattr(store, "store_type", "postgres")


def _submit_api_exchange(task: Callable[..., Any], *args: Any, **kwargs: Any) -> concurrent.futures.Future[Any]:
    return _API_EXCHANGE_EXECUTOR.submit(task, *args, **kwargs)


def _wait_api_exchange(future: concurrent.futures.Future[Any], *, timeout: Optional[float] = None) -> Any:
    return future.result(timeout=timeout if timeout is not None else _API_EXCHANGE_WAIT_TIMEOUT_SEC)


def _run_api_exchange(
    task: Callable[..., Any],
    *args: Any,
    result_timeout: Optional[float] = None,
    **kwargs: Any,
) -> Any:
    return _wait_api_exchange(_submit_api_exchange(task, *args, **kwargs), timeout=result_timeout)


def _submit_background_api_exchange(
    description: str,
    task: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> None:
    def _runner() -> None:
        try:
            task(*args, **kwargs)
        except Exception as exc:
            logger.warning("%s failed: %s", description, exc)

    _submit_api_exchange(_runner)


def _extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.strip().split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return auth_header.strip()


def _current_app_actor() -> Optional[str]:
    token = _extract_bearer_token(request.headers.get("Authorization") or request.headers.get("authorization"))
    if not token:
        return None
    for app_id, value in _settings().app_tokens.items():
        if secrets.compare_digest(token, value):
            return app_id
    return None


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _trusted_internal_service_keys() -> set[str]:
    return {
        str(app_id or "").strip()
        for app_id in _settings().app_tokens.keys()
        if str(app_id or "").strip()
    }


def _current_internal_actor() -> Optional[str]:
    actor = _current_app_actor()
    if actor:
        return actor
    identity = _current_request_identity()
    if not isinstance(identity, dict):
        return None
    if str(identity.get("identity_type") or "").strip().lower() != "service_account":
        return None
    service_key = str(identity.get("service_key") or "").strip()
    if not service_key or service_key not in _trusted_internal_service_keys():
        return None
    return service_key


def require_app_token(view: Callable[..., Response]) -> Callable[..., Response]:
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Response:
        actor = _current_internal_actor()
        if not actor:
            return jsonify({"error": "forbidden"}), 403
        request.environ["nm.app_actor"] = actor
        return view(*args, **kwargs)

    return wrapper


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For") or ""
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.remote_addr or ""


def _login_key(username: str) -> str:
    return f"{(username or '').strip().lower()}:{_client_ip()}"


def _record_login_attempt(username: str, ok: bool) -> None:
    key = _login_key(username)
    now = time.time()
    with _LOGIN_ATTEMPTS_LOCK:
        attempts = [ts for ts in _LOGIN_ATTEMPTS.get(key, []) if now - ts < LOGIN_WINDOW_SEC]
        if not ok:
            attempts.append(now)
        _LOGIN_ATTEMPTS[key] = attempts


def _login_throttled(username: str) -> bool:
    key = _login_key(username)
    now = time.time()
    with _LOGIN_ATTEMPTS_LOCK:
        attempts = [ts for ts in _LOGIN_ATTEMPTS.get(key, []) if now - ts < LOGIN_WINDOW_SEC]
        _LOGIN_ATTEMPTS[key] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _is_secure_request() -> bool:
    if request.is_secure:
        return True
    forwarded_proto = request.headers.get("X-Forwarded-Proto") or ""
    if forwarded_proto:
        return forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    return False


def _apply_cors(response: Response) -> Response:
    origin = request.headers.get("Origin") or ""
    allowed = {item.rstrip("/") for item in _settings().cors_origins if item}
    normalized = origin.rstrip("/")
    if normalized and normalized in allowed:
        response.headers["Access-Control-Allow-Origin"] = normalized
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = ", ".join(
            [
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "X-NM-App-Actor",
                "X-NM-Acting-User",
                "X-NM-Acting-Role",
            ]
        )
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PATCH,DELETE,OPTIONS"
    return response


def _safe_next_path(value: Optional[str]) -> str:
    raw = (value or "").strip()
    if not raw:
        return "/"
    if raw.startswith("//"):
        return "/"
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        return "/"
    return raw if raw.startswith("/") else f"/{raw}"


def _host_matches_pattern(host: str, pattern: str) -> bool:
    host = (host or "").strip().lower()
    pattern = (pattern or "").strip().lower().lstrip(".")
    if not host or not pattern:
        return False
    return host == pattern or host.endswith("." + pattern)


def _safe_external_redirect(value: Optional[str]) -> str:
    raw = (value or "").strip()
    if not raw:
        return "/"
    parsed = urlparse(raw)
    if not parsed.scheme and not parsed.netloc:
        return _safe_next_path(raw)
    if parsed.scheme not in {"http", "https"}:
        return "/"
    host = (parsed.hostname or "").strip().lower()
    allowed_patterns = []
    if _settings().cookie_domain:
        allowed_patterns.append(_settings().cookie_domain)
    if _settings().site_base:
        allowed_patterns.append(urlparse(_settings().site_base).hostname or "")
    if _settings().api_base:
        allowed_patterns.append(urlparse(_settings().api_base).hostname or "")
    if request.host:
        allowed_patterns.append(request.host.split(":", 1)[0])
    if any(_host_matches_pattern(host, pattern) for pattern in allowed_patterns if pattern):
        return raw
    return "/"


def _payload_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value != 0
    normalized = str(value).strip().lower()
    if not normalized:
        return default
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _reserved_username_error() -> Tuple[Response, int]:
    return jsonify({"error": "reserved_username"}), 409


def _parse_kv_params(raw: str) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for chunk in (raw or "").split(","):
        item = chunk.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            params[key] = value
    return params


def _b64url_decode(value: str) -> bytes:
    if not value:
        return b""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _parse_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("invalid_jwt_format")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    signature = _b64url_decode(parts[2])
    signing_input = ".".join(parts[:2]).encode("utf-8")
    return header, payload, signature, signing_input


def _jwk_to_public_key(jwk: Dict[str, Any]):
    if jwk.get("kty") != "RSA":
        return None
    n = jwk.get("n")
    e = jwk.get("e")
    if not n or not e:
        return None
    from cryptography.hazmat.primitives.asymmetric import rsa

    numbers = rsa.RSAPublicNumbers(
        int.from_bytes(_b64url_decode(e), "big"),
        int.from_bytes(_b64url_decode(n), "big"),
    )
    return numbers.public_key()


def _oidc_http_get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = _OIDC_HTTP_TIMEOUT_SEC,
) -> requests.Response:
    return requests.get(url, headers=headers, timeout=timeout)


def _oidc_http_post(
    url: str,
    *,
    data: Dict[str, Any],
    auth: Optional[Tuple[str, str]] = None,
    timeout: float = _OIDC_TOKEN_TIMEOUT_SEC,
) -> requests.Response:
    return requests.post(url, data=data, auth=auth, timeout=timeout)


def _oidc_cache_read(cache_key: str, ts_key: str, ttl_seconds: int) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _OIDC_CACHE_LOCK:
        cached = _OIDC_CACHE.get(cache_key)
        cached_ts = float(_OIDC_CACHE.get(ts_key, 0.0))
    if isinstance(cached, dict) and (now - cached_ts) < ttl_seconds:
        return cached
    return None


def _oidc_cache_write(cache_key: str, ts_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    with _OIDC_CACHE_LOCK:
        _OIDC_CACHE[cache_key] = payload
        _OIDC_CACHE[ts_key] = time.time()
    return payload


def _oidc_discovery() -> Optional[Dict[str, Any]]:
    settings = _settings()
    if not settings.oidc_enabled or not settings.oidc_issuer:
        return None
    cached = _oidc_cache_read("config", "config_ts", settings.oidc_discovery_ttl)
    if cached:
        return cached
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    response = _run_api_exchange(
        _oidc_http_get,
        url,
        timeout=_OIDC_HTTP_TIMEOUT_SEC,
        result_timeout=_OIDC_TOKEN_TIMEOUT_SEC,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("oidc_discovery_invalid_json")
    issuer = str(data.get("issuer") or "").strip()
    if issuer and issuer.rstrip("/") != settings.oidc_issuer.rstrip("/"):
        raise RuntimeError("oidc_issuer_mismatch")
    return _oidc_cache_write("config", "config_ts", data)


def _oidc_prefetch_jwks(config: Optional[Dict[str, Any]]) -> Optional[concurrent.futures.Future[Any]]:
    settings = _settings()
    if settings.oidc_skip_jwt_verify:
        return None
    if _oidc_cache_read("jwks", "jwks_ts", settings.oidc_discovery_ttl):
        return None
    config = config or _oidc_discovery()
    if not isinstance(config, dict):
        return None
    jwks_uri = str(config.get("jwks_uri") or "").strip()
    if not jwks_uri:
        return None
    return _submit_api_exchange(_oidc_http_get, jwks_uri, timeout=_OIDC_HTTP_TIMEOUT_SEC)


def _oidc_jwks(
    *,
    config: Optional[Dict[str, Any]] = None,
    prefetched_response: Optional[concurrent.futures.Future[Any]] = None,
) -> Optional[Dict[str, Any]]:
    settings = _settings()
    cached = _oidc_cache_read("jwks", "jwks_ts", settings.oidc_discovery_ttl)
    if cached:
        return cached
    if prefetched_response is not None:
        try:
            response = _wait_api_exchange(prefetched_response, timeout=_OIDC_TOKEN_TIMEOUT_SEC)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return _oidc_cache_write("jwks", "jwks_ts", data)
        except Exception:
            pass
    config = config or _oidc_discovery()
    if not config:
        return None
    jwks_uri = config.get("jwks_uri")
    if not jwks_uri:
        return None
    response = _run_api_exchange(
        _oidc_http_get,
        jwks_uri,
        timeout=_OIDC_HTTP_TIMEOUT_SEC,
        result_timeout=_OIDC_TOKEN_TIMEOUT_SEC,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        return None
    return _oidc_cache_write("jwks", "jwks_ts", data)


def _verify_jwt(
    token: str,
    *,
    nonce: Optional[str],
    config: Optional[Dict[str, Any]] = None,
    jwks_future: Optional[concurrent.futures.Future[Any]] = None,
) -> Dict[str, Any]:
    settings = _settings()
    header, payload, signature, signing_input = _parse_jwt(token)
    if not settings.oidc_skip_jwt_verify:
        if header.get("alg") != "RS256":
            raise RuntimeError("unsupported_jwt_algorithm")
        jwks = _oidc_jwks(config=config, prefetched_response=jwks_future) or {}
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list) or not keys:
            raise RuntimeError("jwks_missing")
        kid = header.get("kid")
        jwk = next((item for item in keys if item.get("kid") == kid), None) if kid else None
        if not jwk:
            jwk = keys[0]
        public_key = _jwk_to_public_key(jwk)
        if not public_key:
            raise RuntimeError("unsupported_jwks_key")
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    now = int(time.time())
    issuer = payload.get("iss")
    if issuer and str(issuer).rstrip("/") != settings.oidc_issuer.rstrip("/"):
        raise RuntimeError("oidc_issuer_mismatch")
    allowed_audiences = {settings.oidc_client_id} if settings.oidc_client_id else set()
    allowed_audiences.update({item for item in settings.oidc_allowed_audiences if item})
    audience = payload.get("aud")
    if isinstance(audience, list):
        if allowed_audiences and not any(item in allowed_audiences for item in audience):
            raise RuntimeError("oidc_audience_mismatch")
    elif audience and allowed_audiences and audience not in allowed_audiences:
        raise RuntimeError("oidc_audience_mismatch")
    exp = payload.get("exp")
    if exp and (now - settings.oidc_jwt_leeway) > int(exp):
        raise RuntimeError("oidc_token_expired")
    if nonce is not None:
        token_nonce = payload.get("nonce")
        if token_nonce and token_nonce != nonce:
            raise RuntimeError("oidc_nonce_mismatch")
    return payload


def _oidc_prefetch_userinfo(
    access_token: Optional[str],
    *,
    claims: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Optional[concurrent.futures.Future[Any]]:
    settings = _settings()
    if not claims or not access_token:
        return None
    if not (settings.oidc_use_userinfo or not claims.get(settings.oidc_email_claim)):
        return None
    config = config or _oidc_discovery()
    userinfo_endpoint = config.get("userinfo_endpoint") if isinstance(config, dict) else None
    if not userinfo_endpoint:
        return None
    return _submit_api_exchange(
        _oidc_http_get,
        userinfo_endpoint,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=_OIDC_HTTP_TIMEOUT_SEC,
    )


def _oidc_maybe_enrich_claims(
    claims: Dict[str, Any],
    access_token: Optional[str],
    *,
    config: Optional[Dict[str, Any]] = None,
    userinfo_future: Optional[concurrent.futures.Future[Any]] = None,
) -> Dict[str, Any]:
    settings = _settings()
    if not claims or not access_token:
        return claims
    if not (settings.oidc_use_userinfo or not claims.get(settings.oidc_email_claim)):
        return claims
    try:
        if userinfo_future is not None:
            response = _wait_api_exchange(userinfo_future, timeout=_OIDC_TOKEN_TIMEOUT_SEC)
        else:
            config = config or _oidc_discovery()
            userinfo_endpoint = config.get("userinfo_endpoint") if isinstance(config, dict) else None
            if not userinfo_endpoint:
                return claims
            response = _run_api_exchange(
                _oidc_http_get,
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=_OIDC_HTTP_TIMEOUT_SEC,
                result_timeout=_OIDC_TOKEN_TIMEOUT_SEC,
            )
        if response.status_code >= 400:
            return claims
        payload = response.json()
    except Exception:
        return claims
    if isinstance(payload, dict):
        claims.update(payload)
    return claims


def _oidc_redirect_uri() -> str:
    settings = _settings()
    if settings.oidc_redirect_uri:
        return settings.oidc_redirect_uri
    if settings.api_base:
        return settings.api_base.rstrip("/") + "/oidc/callback"
    return request.host_url.rstrip("/") + "/oidc/callback"


def _oidc_allowed_redirect_uris() -> List[str]:
    settings = _settings()
    candidates = []
    if settings.oidc_redirect_uri:
        candidates.append(settings.oidc_redirect_uri.rstrip("/"))
    if settings.api_base:
        candidates.append(settings.api_base.rstrip("/") + "/oidc/callback")
    candidates.extend(item.rstrip("/") for item in settings.oidc_allowed_redirect_uris if item)
    seen = set()
    values = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            values.append(candidate)
            seen.add(candidate)
    return values


def _oidc_is_redirect_allowed(redirect_uri: str) -> bool:
    candidate = (redirect_uri or "").strip().rstrip("/")
    if not candidate:
        return False
    return candidate in _oidc_allowed_redirect_uris()


def _oidc_role_from_claims(claims: Dict[str, Any]) -> str:
    settings = _settings()
    email = claims.get(settings.oidc_email_claim) or claims.get("email")
    if isinstance(email, str) and settings.oidc_admin_domains:
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if domain and domain in {item.lower() for item in settings.oidc_admin_domains}:
            return "admin"
    groups = claims.get(settings.oidc_groups_claim) or claims.get("groups")
    group_values: List[str] = []
    if isinstance(groups, str):
        group_values = [groups]
    elif isinstance(groups, list):
        group_values = [str(item).strip() for item in groups if str(item).strip()]
    if settings.oidc_admin_groups:
        wanted = {item.lower() for item in settings.oidc_admin_groups}
        if any(item.lower() in wanted for item in group_values):
            return "admin"
    return "user"


def _oidc_username_from_claims(claims: Dict[str, Any]) -> Optional[str]:
    settings = _settings()
    for key in (settings.oidc_username_claim, "preferred_username", "email", "sub"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _store_health() -> Dict[str, Any]:
    store = _store()
    store_type = _store_backend_name()
    if store_type == "postgres":
        try:
            with store.pool.connection() as conn:
                conn.execute("SELECT 1")
            return {"type": "postgres", "ok": True}
        except Exception as exc:
            return {"type": "postgres", "ok": False, "error": str(exc)}
    return {"type": store_type, "ok": True}


def _issue_sso_token(user: str) -> str:
    return _store().sso_tokens.issue(user)


def _consume_sso_token(token: str) -> Optional[str]:
    return _store().sso_tokens.consume(token)


def _user_entry(user: Optional[str]) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return {}
    entry = _store().users.get_user(cleaned)
    return dict(entry) if isinstance(entry, dict) else {}


def _is_service_account_user_entry(entry: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(entry, dict):
        return False
    return str(entry.get("provider") or "").strip() == SERVICE_ACCOUNT_PROVIDER


def _service_account_record(
    service_account_id: Optional[str],
    *,
    include_disabled: bool = False,
) -> Optional[Dict[str, Any]]:
    cleaned = str(service_account_id or "").strip()
    if not cleaned:
        return None
    try:
        normalized = normalize_service_account_id(cleaned)
    except ValueError:
        return None
    return _service_account_store().get_service_account(
        normalized,
        include_disabled=include_disabled,
    )


def _service_account_for_principal(
    principal_username: Optional[str],
    *,
    include_disabled: bool = False,
) -> Optional[Dict[str, Any]]:
    cleaned = str(principal_username or "").strip()
    if not cleaned:
        return None
    return _service_account_store().get_by_principal_username(
        cleaned,
        include_disabled=include_disabled,
    )


def _is_service_account_principal(principal_username: Optional[str]) -> bool:
    return _service_account_for_principal(principal_username, include_disabled=True) is not None


def _principal_role_group(principal_username: Optional[str]) -> Optional[str]:
    cleaned = str(principal_username or "").strip()
    if not cleaned or _is_service_account_principal(cleaned):
        return None
    return _role_for_user(cleaned)


def _role_for_user(user: str) -> Optional[str]:
    return _store().users.get_role(user)


def _email_for_user(user: str) -> Optional[str]:
    return _store().users.get_email(user)


def _access_store() -> Any:
    return _store().access


def _all_groups() -> List[Dict[str, Any]]:
    return _access_store().list_groups()


def _all_services() -> List[Dict[str, Any]]:
    return _access_store().list_services()


def _all_group_grants() -> List[Dict[str, Any]]:
    return _access_store().list_group_service_grants()


def _group_memberships_for_user(user: str) -> List[Dict[str, Any]]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return []
    return _access_store().list_group_memberships(username=cleaned)


def _groups_for_user(user: str) -> List[str]:
    role = str(_principal_role_group(user) or "").strip().lower()
    groups: List[str] = []
    seen = set()
    for candidate in [role, *[item.get("group_key") for item in _group_memberships_for_user(user)]]:
        normalized = str(candidate or "").strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        groups.append(normalized)
    return groups


def _manageable_group_keys(user: str) -> List[str]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return []
    return manageable_group_keys_for_user(
        role=_principal_role_group(cleaned),
        groups=_all_groups(),
        group_memberships=_group_memberships_for_user(cleaned),
    )


def _visible_group_keys(user: str) -> List[str]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return []
    return visible_group_keys_for_user(
        role=_principal_role_group(cleaned),
        groups=_all_groups(),
        group_memberships=_group_memberships_for_user(cleaned),
    )


def _visible_group_records_for_user(user: str) -> List[Dict[str, Any]]:
    visible = set(_visible_group_keys(user))
    if not visible:
        return []
    return [item for item in _all_groups() if str(item.get("key") or "").strip().lower() in visible]


def _service_access_records_for_user(user: str) -> List[Dict[str, Any]]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return resolve_user_service_access(
            role=None,
            group_memberships=[],
            groups=_all_groups(),
            services=_all_services(),
            grants=[],
        )
    return resolve_user_service_access(
        role=_principal_role_group(cleaned),
        group_memberships=_group_memberships_for_user(cleaned),
        groups=_all_groups(),
        services=_all_services(),
        grants=_all_group_grants(),
    )


def _service_access_map_for_user(user: str) -> Dict[str, Dict[str, Any]]:
    return {
        str(item.get("service_key") or "").strip(): item
        for item in _service_access_records_for_user(user)
        if str(item.get("service_key") or "").strip()
    }


def _visible_service_keys_for_user(user: str) -> List[str]:
    return [
        str(item.get("service_key") or "").strip()
        for item in _service_access_records_for_user(user)
        if bool(item.get("visible")) and str(item.get("service_key") or "").strip()
    ]


def _can_manage_group(user: Optional[str], group_key: Optional[str]) -> bool:
    cleaned_user = str(user or "").strip()
    cleaned_group = str(group_key or "").strip()
    if not cleaned_user or not cleaned_group:
        return False
    if _is_admin_user(cleaned_user):
        return True
    try:
        normalized_group = normalize_group_key(cleaned_group)
    except ValueError:
        return False
    return normalized_group in set(_manageable_group_keys(cleaned_user))


def _can_view_group(user: Optional[str], group_key: Optional[str]) -> bool:
    cleaned_user = str(user or "").strip()
    cleaned_group = str(group_key or "").strip()
    if not cleaned_user or not cleaned_group:
        return False
    if _is_admin_user(cleaned_user):
        return True
    try:
        normalized_group = normalize_group_key(cleaned_group)
    except ValueError:
        return False
    return normalized_group in set(_visible_group_keys(cleaned_user))


def _group_membership_for_user(group_key: str, username: str) -> Optional[Dict[str, Any]]:
    cleaned_group = str(group_key or "").strip().lower()
    cleaned_user = str(username or "").strip()
    if not cleaned_group or not cleaned_user:
        return None
    memberships = _access_store().list_group_memberships(group_key=cleaned_group, username=cleaned_user)
    return memberships[0] if memberships else None


def _annotate_group_membership(entry: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    payload = dict(entry or {})
    username = str(payload.get("username") or "").strip()
    service_account = _service_account_for_principal(username, include_disabled=True)
    if service_account:
        payload["principal_type"] = "service_account"
        payload["service_account_id"] = service_account.get("service_account_id")
        payload["principal_username"] = username
        payload["principal_display_name"] = service_account.get("display_name") or username
        if service_account.get("service_key"):
            payload["service_key"] = service_account.get("service_key")
        payload["disabled"] = bool(service_account.get("disabled"))
        return payload
    if username:
        payload["principal_type"] = "user"
        payload["principal_username"] = username
        payload["principal_display_name"] = username
    return payload


def _can_manage_service_account(actor: Optional[str], account: Optional[Dict[str, Any]]) -> bool:
    cleaned_actor = str(actor or "").strip()
    if not cleaned_actor or not isinstance(account, dict):
        return False
    if _is_admin_user(cleaned_actor):
        return True
    principal_username = str(account.get("principal_username") or "").strip()
    if not principal_username:
        return False
    group_keys = {
        str(item.get("group_key") or "").strip().lower()
        for item in _group_memberships_for_user(principal_username)
        if str(item.get("group_key") or "").strip()
    }
    if not group_keys:
        return False
    manageable = set(_manageable_group_keys(cleaned_actor))
    return group_keys.issubset(manageable)


def _can_view_service_account(actor: Optional[str], account: Optional[Dict[str, Any]]) -> bool:
    cleaned_actor = str(actor or "").strip()
    if not cleaned_actor or not isinstance(account, dict):
        return False
    if _is_admin_user(cleaned_actor):
        return True
    if str(account.get("created_by") or "").strip() == cleaned_actor:
        return True
    principal_username = str(account.get("principal_username") or "").strip()
    if not principal_username:
        return False
    actor_visible_groups = set(_visible_group_keys(cleaned_actor))
    service_account_groups = {
        str(item.get("group_key") or "").strip().lower()
        for item in _group_memberships_for_user(principal_username)
        if str(item.get("group_key") or "").strip()
    }
    return bool(actor_visible_groups & service_account_groups)


def _service_account_token_payload(token_entry: Dict[str, Any], account: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": token_entry.get("id"),
        "service_account_id": account.get("service_account_id"),
        "principal_username": account.get("principal_username"),
        "label": token_entry.get("label"),
        "created_at": token_entry.get("created_at"),
        "expires_at": token_entry.get("expires_at"),
        "last_used_at": token_entry.get("last_used_at"),
        "disabled": bool(token_entry.get("disabled")),
        "meta": token_entry.get("meta") if isinstance(token_entry.get("meta"), dict) else {},
    }


def _service_account_payload(
    account: Dict[str, Any],
    *,
    actor: Optional[str] = None,
    include_tokens: bool = False,
) -> Dict[str, Any]:
    principal_username = str(account.get("principal_username") or "").strip()
    memberships = [_annotate_group_membership(item) for item in _group_memberships_for_user(principal_username)]
    groups = [
        str(item.get("group_key") or "").strip().lower()
        for item in memberships
        if str(item.get("group_key") or "").strip()
    ]
    visible_groups = _visible_group_keys(principal_username)
    service_access_records = _service_access_records_for_user(principal_username)
    service_access = {
        str(item.get("service_key") or "").strip(): item
        for item in service_access_records
        if str(item.get("service_key") or "").strip()
    }
    payload: Dict[str, Any] = {
        **dict(account),
        "identity_type": "service_account",
        "user": str(account.get("service_account_id") or "").strip(),
        "role": "service_account",
        "groups": groups,
        "group_memberships": memberships,
        "manageable_groups": [],
        "visible_groups": visible_groups,
        "can_manage_access": False,
        "email": None,
        "active_team": None,
        "team_count": 0,
        "pending_invitation_count": 0,
        "is_admin": False,
        "service_access": service_access,
        "visible_services": [
            str(item.get("service_key") or "").strip()
            for item in service_access_records
            if bool(item.get("visible")) and str(item.get("service_key") or "").strip()
        ],
        "settings": default_user_settings(),
        "can_manage": _can_manage_service_account(actor, account) if actor else False,
    }
    if include_tokens and actor and payload["can_manage"]:
        payload["access_tokens"] = [
            _service_account_token_payload(item, account)
            for item in _store().access_tokens.list_tokens(principal_username)
        ]
    return payload


def _service_account_identity_payload_for_principal(principal_username: str) -> Optional[Dict[str, Any]]:
    account = _service_account_for_principal(principal_username)
    if not account:
        return None
    return _service_account_payload(account)


def _service_account_group_keys_from_payload(payload: Dict[str, Any]) -> List[str]:
    raw_values: List[Any] = []
    for key in ("group_keys", "groups"):
        value = payload.get(key)
        if isinstance(value, list):
            raw_values.extend(value)
    memberships = payload.get("group_memberships")
    if isinstance(memberships, list):
        for entry in memberships:
            if isinstance(entry, dict):
                raw_values.append(entry.get("group_key") or entry.get("key"))
    group_keys: List[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        try:
            group_key = normalize_group_key(raw)
        except ValueError:
            continue
        if group_key in seen:
            continue
        seen.add(group_key)
        group_keys.append(group_key)
    return group_keys


def _team_store() -> Any:
    return _store().teams


def _team_memberships_for_user(user: str, *, statuses: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return []
    return _team_store().list_user_memberships(cleaned, statuses=statuses)


def _incoming_team_invitations_for_user(user: str) -> List[Dict[str, Any]]:
    return _team_memberships_for_user(user, statuses=[TEAM_MEMBERSHIP_STATUS_PENDING])


def _active_team_memberships_for_user(user: str) -> List[Dict[str, Any]]:
    return _team_memberships_for_user(user, statuses=[TEAM_MEMBERSHIP_STATUS_ACTIVE])


def _primary_team_for_user(user: str) -> Optional[Dict[str, Any]]:
    memberships = _active_team_memberships_for_user(user)
    return memberships[0] if memberships else None


def _team_role_for_user(user: str, team_id: str) -> Optional[str]:
    cleaned_user = str(user or "").strip()
    cleaned_team = str(team_id or "").strip()
    if not cleaned_user or not cleaned_team:
        return None
    return _team_store().team_role_for_user(cleaned_user, cleaned_team)


def _is_admin_user(user: Optional[str]) -> bool:
    cleaned = str(user or "").strip()
    if not cleaned:
        return False
    return "admin" in _groups_for_user(cleaned)


def _can_manage_team(user: Optional[str], team_id: Optional[str]) -> bool:
    cleaned_user = str(user or "").strip()
    cleaned_team = str(team_id or "").strip()
    if not cleaned_user or not cleaned_team:
        return False
    if _is_admin_user(cleaned_user):
        return True
    return _team_role_for_user(cleaned_user, cleaned_team) == "owner"


def _can_view_team(user: Optional[str], team_id: Optional[str]) -> bool:
    cleaned_user = str(user or "").strip()
    cleaned_team = str(team_id or "").strip()
    if not cleaned_user or not cleaned_team:
        return False
    if _is_admin_user(cleaned_user):
        return True
    if _team_role_for_user(cleaned_user, cleaned_team):
        return True
    incoming = _incoming_team_invitations_for_user(cleaned_user)
    if any(str(item.get("team_id") or "").strip() == cleaned_team for item in incoming):
        return True
    outgoing = _team_store().list_invitations_sent_by(cleaned_user, statuses=[TEAM_MEMBERSHIP_STATUS_PENDING])
    return any(str(item.get("team_id") or "").strip() == cleaned_team for item in outgoing)


def _user_metadata(user: Optional[str]) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return {}
    try:
        metadata = _store().users.get_metadata(cleaned)
    except Exception:
        metadata = {}
    return dict(metadata) if isinstance(metadata, dict) else {}


def _user_settings(user: Optional[str]) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return default_user_settings()
    return settings_from_metadata(_user_metadata(cleaned))


def _update_user_settings(user: str, raw_settings: Any) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    if not cleaned:
        raise SettingsValidationError(["user is required"])
    current_metadata = _user_metadata(cleaned)
    current_settings = settings_from_metadata(current_metadata)
    merged = validate_settings_patch(raw_settings, current=current_settings)
    updated_metadata = metadata_with_settings(current_metadata, merged, updated_at=_now_iso())
    if not _store().users.set_metadata(cleaned, updated_metadata):
        raise KeyError(cleaned)
    return merged


def _user_has_local_password(user: Optional[str]) -> bool:
    entry = _user_entry(user)
    if _is_service_account_user_entry(entry):
        return False
    return bool(entry.get("has_password"))


def _user_security_state(user: Optional[str]) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return security_state_from_metadata({}, secret_key=_settings().secret_key)
    return security_state_from_metadata(_user_metadata(cleaned), secret_key=_settings().secret_key)


def _update_user_security_state(user: str, security_state: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    if not cleaned:
        raise KeyError("user")
    current_metadata = _user_metadata(cleaned)
    updated_metadata = metadata_with_security_state(
        current_metadata,
        security_state,
        secret_key=_settings().secret_key,
    )
    if not _store().users.set_metadata(cleaned, updated_metadata):
        raise KeyError(cleaned)
    return security_state


def _local_security_supported_for_user(user: Optional[str]) -> bool:
    cleaned = str(user or "").strip()
    if not cleaned:
        return False
    if _settings().auth_mode == "oidc":
        return False
    return _user_has_local_password(cleaned)


def _user_security_payload(user: Optional[str], *, include_passkeys: bool) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    supported = _local_security_supported_for_user(cleaned)
    return security_summary(
        _user_security_state(cleaned),
        totp_supported=supported,
        passkeys_supported=supported,
        include_passkeys=include_passkeys,
    )


def _totp_enabled_for_user(user: Optional[str]) -> bool:
    return bool(_user_security_state(user).get("totp", {}).get("enabled"))


def _request_origin() -> str:
    origin = str(request.headers.get("Origin") or "").strip()
    if origin:
        return origin.rstrip("/")
    host = str(request.headers.get("X-Forwarded-Host") or request.host or "").strip()
    if not host:
        return ""
    proto = str(request.headers.get("X-Forwarded-Proto") or "").split(",", 1)[0].strip().lower()
    if proto not in {"http", "https"}:
        proto = "https" if _is_secure_request() else "http"
    return f"{proto}://{host}".rstrip("/")


def _passkey_rp_id() -> str:
    settings = _settings()
    if settings.passkey_rp_id:
        return settings.passkey_rp_id.strip().lower()
    if settings.cookie_domain:
        return settings.cookie_domain.lstrip(".").strip().lower()
    for candidate in (settings.site_base, settings.api_base):
        parsed = urlparse(candidate or "")
        if parsed.hostname:
            return parsed.hostname.strip().lower()
    host = str(request.headers.get("X-Forwarded-Host") or request.host or "").strip()
    return host.split(":", 1)[0].strip().lower()


def _passkey_rp_name() -> str:
    name = str(_settings().passkey_rp_name or "").strip()
    return name or "NeuralMimicry"


def _passkey_allowed_origins() -> List[str]:
    settings = _settings()
    origins: List[str] = []
    seen = set()
    for candidate in [*settings.passkey_allowed_origins, settings.api_base, settings.site_base, _request_origin()]:
        cleaned = str(candidate or "").strip().rstrip("/")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        origins.append(cleaned)
    return origins


def _write_auth_challenge(key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    challenge = dict(payload or {})
    challenge["created_at"] = time.time()
    session[key] = challenge
    return challenge


def _read_auth_challenge(key: str) -> Optional[Dict[str, Any]]:
    raw = session.get(key)
    if not isinstance(raw, dict):
        return None
    created_at = float(raw.get("created_at") or 0.0)
    if not created_at or (time.time() - created_at) > _settings().auth_challenge_ttl_seconds:
        session.pop(key, None)
        return None
    return dict(raw)


def _clear_auth_challenges(*keys: str) -> None:
    targets = keys or (
        _PENDING_LOGIN_SESSION_KEY,
        _PENDING_TOTP_SETUP_SESSION_KEY,
        _PENDING_PASSKEY_REGISTRATION_SESSION_KEY,
        _PENDING_PASSKEY_AUTHENTICATION_SESSION_KEY,
    )
    for key in targets:
        session.pop(key, None)


def _validate_local_auth_security(user: Optional[str]) -> Optional[Tuple[Response, int]]:
    cleaned = str(user or "").strip()
    if not cleaned:
        return jsonify({"error": "unauthorized"}), 401
    if _settings().auth_mode == "oidc":
        return jsonify({"error": "oidc_required"}), 403
    if not _user_has_local_password(cleaned):
        return jsonify({"error": "local_auth_unavailable"}), 409
    return None


def _validate_account_creation_payload(
    payload: Dict[str, Any],
    *,
    require_email: bool,
) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[Response, int]]]:
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    confirm = str(payload.get("confirm") or "")
    email = str(payload.get("email") or "").strip()
    if require_email and not email:
        return None, (jsonify({"error": "email_required", "details": "Email is required."}), 400)
    if not username or not password:
        return None, (jsonify({"error": "username_and_password_required"}), 400)
    if not USERNAME_RE.match(username):
        return None, (
            jsonify(
                {
                    "error": "invalid_username",
                    "details": "Username must be 3-32 chars (letters, numbers, underscore, dash).",
                }
            ),
            400,
        )
    if _is_service_account_principal(username):
        return None, _reserved_username_error()
    if email and not EMAIL_RE.match(email):
        return None, (jsonify({"error": "invalid_email", "details": "Enter a valid email address."}), 400)
    if len(password) < _settings().password_min_length:
        return None, (
            jsonify(
                {
                    "error": "password_too_short",
                    "details": f"Password must be at least {_settings().password_min_length} characters.",
                }
            ),
            400,
        )
    if confirm and confirm != password:
        return None, (jsonify({"error": "password_mismatch", "details": "Passwords do not match."}), 400)
    return {
        "username": username,
        "password": password,
        "email": email or None,
    }, None


def _attempt_local_login(username: str, password: str, *, source: str) -> Tuple[str, Dict[str, Any], int]:
    cleaned_username = str(username or "").strip()
    cleaned_password = str(password or "")
    if not cleaned_username or not cleaned_password:
        return "error", {"error": "username_and_password_required"}, 400
    if _login_throttled(cleaned_username):
        return "error", {"error": "too_many_attempts"}, 429
    if not _store().users.verify(cleaned_username, cleaned_password):
        _record_login_attempt(cleaned_username, ok=False)
        return "error", {"error": "invalid_credentials"}, 401
    _record_login_attempt(cleaned_username, ok=True)
    if _totp_enabled_for_user(cleaned_username):
        session.pop("user", None)
        _write_auth_challenge(
            _PENDING_LOGIN_SESSION_KEY,
            {"user": cleaned_username, "source": source, "factor": "totp"},
        )
        return (
            "mfa_required",
            {
                "status": "mfa_required",
                "mfa": {
                    "type": "totp",
                    "label": "Authenticator app",
                },
            },
            202,
        )
    _finalize_login(cleaned_username, auth_mode="local", provider="local", source=source)
    session.pop("login_next", None)
    return "success", _login_payload(cleaned_username, source=source), 200


def _complete_totp_login(code: Any, *, source: str) -> Tuple[str, Dict[str, Any], int]:
    pending = _read_auth_challenge(_PENDING_LOGIN_SESSION_KEY)
    if not pending:
        return "error", {"error": "mfa_challenge_missing"}, 400
    username = str(pending.get("user") or "").strip()
    if not username:
        _clear_auth_challenges(_PENDING_LOGIN_SESSION_KEY)
        return "error", {"error": "mfa_challenge_missing"}, 400
    security_state = _user_security_state(username)
    totp_state = security_state.get("totp", {})
    secret = str(totp_state.get("secret") or "").strip()
    if not bool(totp_state.get("enabled")) or not secret:
        _clear_auth_challenges(_PENDING_LOGIN_SESSION_KEY)
        return "error", {"error": "totp_not_enabled"}, 409
    if not verify_totp_code(secret, code):
        return "error", {"error": "invalid_mfa_code"}, 401
    _clear_auth_challenges(_PENDING_LOGIN_SESSION_KEY)
    _finalize_login(username, auth_mode="local_mfa", provider="local", source=source)
    session.pop("login_next", None)
    return "success", _login_payload(username, source=source), 200


def _auth_error_message(payload: Optional[Dict[str, Any]], default: str) -> str:
    data = dict(payload or {})
    details = str(data.get("details") or "").strip()
    if details:
        return details
    code = str(data.get("error") or "").strip()
    messages = {
        "email_required": "Email is required.",
        "invalid_credentials": "Invalid username or password.",
        "invalid_email": "Enter a valid email address.",
        "invalid_mfa_code": "Enter a valid six-digit authenticator code.",
        "invalid_username": "Username must be 3-32 chars (letters, numbers, underscore, dash).",
        "local_auth_unavailable": "This account does not support local sign-in.",
        "mfa_challenge_missing": "The sign-in check has expired. Please start again.",
        "password_mismatch": "Passwords do not match.",
        "registration_not_allowed": "Self-registration is not available.",
        "reserved_username": "That username is reserved.",
        "setup_not_allowed": "Setup has already been completed.",
        "setup_required": "Setup is required before you can sign in.",
        "too_many_attempts": "Too many attempts. Please try again later.",
        "totp_not_enabled": "Authenticator-app sign-in is not enabled for this account.",
        "user_exists": "That username is already in use.",
        "username_and_password_required": "Username and password are required.",
    }
    return messages.get(code) or default


def _user_record_payload(entry: Dict[str, Any], *, include_access: bool = False) -> Dict[str, Any]:
    payload = dict(entry)
    username = str(payload.get("username") or "").strip()
    payload["identity_type"] = "user"
    payload["groups"] = _groups_for_user(username)
    payload["group_memberships"] = _group_memberships_for_user(username)
    payload["manageable_groups"] = _manageable_group_keys(username)
    if include_access:
        payload["service_access"] = _service_access_map_for_user(username)
        payload["visible_services"] = _visible_service_keys_for_user(username)
    return payload


def _group_effective_grants(group_key: str) -> List[Dict[str, Any]]:
    cleaned = normalize_group_key(group_key)
    groups = _all_groups()
    services = {str(item.get("service_key") or "").strip(): item for item in _all_services()}
    direct_grants = {
        str(item.get("service_key") or "").strip(): item
        for item in _access_store().list_group_service_grants(group_key=cleaned)
        if str(item.get("service_key") or "").strip()
    }
    effective = resolve_group_effective_grants(groups, _all_group_grants()).get(cleaned) or {}
    payload: List[Dict[str, Any]] = []
    for service_key in sorted(set(direct_grants.keys()) | set(effective.keys())):
        direct = direct_grants.get(service_key) or {}
        effective_entry = effective.get(service_key) or {}
        service = services.get(service_key) or {}
        payload.append(
            {
                "group_key": cleaned,
                "service_key": service_key,
                "display_name": str(
                    service.get("display_name")
                    or direct.get("display_name")
                    or service_key
                ).strip()
                or service_key,
                "public_access_level": normalize_service_access_level(
                    service.get("public_access_level") or direct.get("public_access_level") or SERVICE_ACCESS_NONE
                ),
                "direct_access_level": direct.get("access_level") or SERVICE_ACCESS_NONE,
                "effective_access_level": effective_entry.get("effective_access_level") or SERVICE_ACCESS_NONE,
                "bounded_by_group": effective_entry.get("bounded_by_group"),
                "granted_by": direct.get("granted_by"),
                "metadata": direct.get("metadata") if isinstance(direct.get("metadata"), dict) else {},
                "created_at": direct.get("created_at"),
                "updated_at": direct.get("updated_at"),
            }
        )
    return payload


def _parent_group_effective_access_level(group_key: str, service_key: str) -> Optional[str]:
    group = _access_store().get_group(group_key) or {}
    parent_key = str(group.get("parent_key") or "").strip().lower() or None
    if not parent_key:
        return None
    effective = resolve_group_effective_grants(_all_groups(), _all_group_grants())
    parent_entry = ((effective.get(parent_key) or {}).get(normalize_service_key(service_key)) or {})
    return parent_entry.get("effective_access_level") or SERVICE_ACCESS_NONE


def _group_detail_payload(group_key: str, actor: str) -> Dict[str, Any]:
    cleaned = normalize_group_key(group_key)
    group = _access_store().get_group(cleaned) or {}
    if not group:
        raise KeyError(cleaned)
    can_manage = _can_manage_group(actor, cleaned)
    raw_actor_membership = _group_membership_for_user(cleaned, actor)
    actor_membership = _annotate_group_membership(raw_actor_membership) if raw_actor_membership else None
    memberships = _access_store().list_group_memberships(group_key=cleaned) if can_manage else []
    if not can_manage and actor_membership:
        memberships = [actor_membership]
    elif can_manage:
        memberships = [_annotate_group_membership(item) for item in memberships]
    children = [
        item
        for item in _visible_group_records_for_user(actor)
        if str(item.get("parent_key") or "").strip().lower() == cleaned
    ]
    payload: Dict[str, Any] = {
        "group": group,
        "children": children,
        "can_manage": can_manage,
        "membership": actor_membership,
        "members": memberships,
    }
    if can_manage or actor_membership:
        payload["grants"] = _group_effective_grants(cleaned)
    return payload


def _user_identity_payload(user: str, *, include_directory: bool = False) -> Dict[str, Any]:
    cleaned = str(user or "").strip()
    role = _role_for_user(cleaned)
    groups = _groups_for_user(cleaned)
    group_memberships = _group_memberships_for_user(cleaned)
    manageable_groups = _manageable_group_keys(cleaned)
    visible_groups = _visible_group_keys(cleaned)
    service_access_records = _service_access_records_for_user(cleaned)
    service_access = {
        str(item.get("service_key") or "").strip(): item
        for item in service_access_records
        if str(item.get("service_key") or "").strip()
    }
    email = _email_for_user(cleaned)
    active_teams = _active_team_memberships_for_user(cleaned)
    incoming_invitations = _incoming_team_invitations_for_user(cleaned)
    payload: Dict[str, Any] = {
        "authenticated": True,
        "identity_type": "user",
        "user": cleaned,
        "role": role,
        "groups": groups,
        "group_memberships": group_memberships,
        "manageable_groups": manageable_groups,
        "visible_groups": visible_groups,
        "can_manage_access": bool(manageable_groups),
        "email": email,
        "active_team": active_teams[0] if active_teams else None,
        "team_count": len(active_teams),
        "pending_invitation_count": len(incoming_invitations),
        "is_admin": "admin" in groups,
        "service_access": service_access,
        "visible_services": [
            str(item.get("service_key") or "").strip()
            for item in service_access_records
            if bool(item.get("visible")) and str(item.get("service_key") or "").strip()
        ],
        "settings": _user_settings(cleaned),
        "security": _user_security_payload(cleaned, include_passkeys=include_directory),
    }
    if include_directory:
        payload["teams"] = active_teams
        payload["pending_invitations"] = incoming_invitations
        payload["outgoing_invitations"] = _team_store().list_invitations_sent_by(
            cleaned,
            statuses=[TEAM_MEMBERSHIP_STATUS_PENDING],
        )
        user_entry = _store().users.get_user(cleaned) or {}
        if "has_password" in user_entry:
            payload["has_password"] = bool(user_entry.get("has_password"))
        team_records = _visible_team_records_for_user(cleaned)
        payload["team_tree"] = _build_team_tree(team_records, active_teams + incoming_invitations)
        payload["group_directory"] = _visible_group_records_for_user(cleaned)
    return payload


def _visible_team_records_for_user(user: str) -> List[Dict[str, Any]]:
    cleaned = str(user or "").strip()
    all_teams = _team_store().list_teams()
    if _is_admin_user(cleaned):
        return all_teams
    team_ids = set()
    for membership in _active_team_memberships_for_user(cleaned) + _incoming_team_invitations_for_user(cleaned):
        team_id = str(membership.get("team_id") or "").strip()
        if team_id:
            team_ids.add(team_id)
    outgoing = _team_store().list_invitations_sent_by(cleaned, statuses=[TEAM_MEMBERSHIP_STATUS_PENDING])
    for membership in outgoing:
        team_id = str(membership.get("team_id") or "").strip()
        if team_id:
            team_ids.add(team_id)
    teams_by_id = {str(item.get("id") or "").strip(): dict(item) for item in all_teams if item.get("id")}
    pending = list(team_ids)
    while pending:
        current = pending.pop()
        parent_id = str((teams_by_id.get(current) or {}).get("parent_id") or "").strip()
        if parent_id and parent_id not in team_ids:
            team_ids.add(parent_id)
            pending.append(parent_id)
    return [teams_by_id[team_id] for team_id in sorted(team_ids) if team_id in teams_by_id]


def _build_team_tree(teams: List[Dict[str, Any]], memberships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    teams_by_id: Dict[str, Dict[str, Any]] = {}
    membership_map = {
        str(item.get("team_id") or "").strip(): item
        for item in memberships
        if str(item.get("team_id") or "").strip()
    }
    for team in teams:
        team_id = str(team.get("id") or "").strip()
        if not team_id:
            continue
        node = dict(team)
        node["children"] = []
        membership = membership_map.get(team_id)
        if membership:
            node["membership_role"] = membership.get("membership_role")
            node["membership_status"] = membership.get("status")
        teams_by_id[team_id] = node
    roots: List[Dict[str, Any]] = []
    for node in sorted(teams_by_id.values(), key=lambda item: (str(item.get("name") or ""), str(item.get("id") or ""))):
        parent_id = str(node.get("parent_id") or "").strip()
        if parent_id and parent_id in teams_by_id:
            teams_by_id[parent_id].setdefault("children", []).append(node)
        else:
            roots.append(node)
    return roots


def _validate_password_change_payload(payload: Dict[str, Any], *, require_current: bool) -> Tuple[Optional[Dict[str, str]], Optional[Tuple[Response, int]]]:
    current_password = str(payload.get("current_password") or payload.get("password_current") or "")
    new_password = str(payload.get("new_password") or payload.get("password") or "")
    confirm_password = str(payload.get("confirm") or payload.get("confirm_password") or "")
    if require_current and not current_password:
        return None, (jsonify({"error": "current_password_required"}), 400)
    if not new_password:
        return None, (jsonify({"error": "password_required"}), 400)
    if len(new_password) < _settings().password_min_length:
        return None, (
            jsonify(
                {
                    "error": "password_too_short",
                    "details": f"Password must be at least {_settings().password_min_length} characters.",
                }
            ),
            400,
        )
    if confirm_password and confirm_password != new_password:
        return None, (jsonify({"error": "password_mismatch", "details": "Passwords do not match."}), 400)
    return {
        "current_password": current_password,
        "new_password": new_password,
    }, None


def _record_identity_event(
    user: str,
    *,
    role: Optional[str] = None,
    email: Optional[str] = None,
    provider: Optional[str] = None,
    subject: Optional[str] = None,
    request_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    chain = _nmchain()
    if not chain:
        return
    payload = _user_identity_payload(user)
    details = dict(meta or {})
    for key in ("groups", "active_team", "team_count", "pending_invitation_count"):
        if key not in details and key in payload:
            details[key] = payload.get(key)
    _submit_background_api_exchange(
        f"nmchain identity upsert failed for {user}",
        chain.upsert_identity,
        user,
        role=role,
        email=email,
        provider=provider,
        subject=subject,
        request_id=request_id,
        meta=details,
    )


def _record_login_event(
    user: str,
    *,
    auth_mode: str,
    provider: Optional[str] = None,
    session_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    chain = _nmchain()
    if not chain:
        return
    details = dict(meta or {})
    if provider and "provider" not in details:
        details["provider"] = provider
    _submit_background_api_exchange(
        f"nmchain login event failed for {user}",
        chain.observe_login,
        user,
        system="customers",
        auth_mode=auth_mode,
        session_id=session_id,
        remote_addr=_client_ip() or None,
        meta=details,
    )


def _current_request_identity() -> Optional[Dict[str, Any]]:
    cached = getattr(g, _IDENTITY_CACHE_KEY, _IDENTITY_CACHE_MISS)
    if cached is not _IDENTITY_CACHE_MISS:
        return cached
    identity: Optional[Dict[str, Any]] = None
    session_user = session.get("user")
    if isinstance(session_user, str) and session_user.strip():
        identity = _user_identity_payload(session_user.strip())
    else:
        token = _extract_bearer_token(request.headers.get("Authorization") or request.headers.get("authorization"))
        if token and not _current_app_actor():
            try:
                verified = _store().access_tokens.verify(token)
            except Exception as exc:
                logger.warning("access token verification failed: %s", exc)
                verified = None
            if isinstance(verified, dict):
                principal_username = str(verified.get("user") or "").strip()
                if principal_username:
                    service_account = _service_account_for_principal(
                        principal_username,
                        include_disabled=True,
                    )
                    if service_account:
                        identity = None if bool(service_account.get("disabled")) else _service_account_payload(service_account)
                    else:
                        identity = _user_identity_payload(principal_username)
    setattr(g, _IDENTITY_CACHE_KEY, identity)
    return identity


def _current_user() -> Optional[str]:
    identity = _current_request_identity()
    if not isinstance(identity, dict):
        return None
    if str(identity.get("identity_type") or "").strip() == "service_account":
        return None
    user = str(identity.get("user") or "").strip()
    return user or None


def _issue_access_token_payload(user: str, *, source: str) -> Dict[str, Any]:
    try:
        issued = _store().access_tokens.issue(user, label=source, meta={"source": source})
    except Exception as exc:
        logger.warning("access token issue failed for %s: %s", user, exc)
        return {}
    payload: Dict[str, Any] = {"access_token": issued.get("token")}
    expires_at = issued.get("expires_at")
    if expires_at:
        payload["access_expires_at"] = expires_at
    return payload


def _issue_service_account_access_token(
    account: Dict[str, Any],
    *,
    label: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    principal_username = str(account.get("principal_username") or "").strip()
    service_account_id = str(account.get("service_account_id") or "").strip()
    if not principal_username or not service_account_id:
        raise ValueError("service_account_required")
    issued = _store().access_tokens.issue(
        principal_username,
        label=label,
        ttl_seconds=ttl_seconds,
        meta={
            **(dict(meta or {})),
            "identity_type": "service_account",
            "service_account_id": service_account_id,
            "service_key": account.get("service_key"),
        },
    )
    return {
        "access_token": issued.get("token"),
        "access_token_record": _service_account_token_payload(issued, account),
        "access_expires_at": issued.get("expires_at"),
    }


def _login_payload(user: str, *, source: str) -> Dict[str, Any]:
    payload = {
        "status": "ok",
        "sso_token": _issue_sso_token(user),
        "sso_expires_in": _settings().sso_ttl_seconds,
        **_issue_access_token_payload(user, source=source),
    }
    payload.update(_user_identity_payload(user))
    return payload


def _finalize_login(
    user: str,
    *,
    auth_mode: str,
    provider: str,
    source: str,
    role: Optional[str] = None,
    email: Optional[str] = None,
    subject: Optional[str] = None,
    session_id: Optional[str] = None,
) -> None:
    session["user"] = user
    _clear_auth_challenges(
        _PENDING_LOGIN_SESSION_KEY,
        _PENDING_PASSKEY_AUTHENTICATION_SESSION_KEY,
    )
    _record_identity_event(
        user,
        role=role or _role_for_user(user),
        email=email if email is not None else _email_for_user(user),
        provider=provider,
        subject=subject,
        meta={"source": source},
    )
    _record_login_event(
        user,
        auth_mode=auth_mode,
        provider=provider,
        session_id=session_id,
        meta={"source": source},
    )


def _auth_config_payload() -> Dict[str, Any]:
    settings = _settings()
    has_users = _store().users.has_users()
    local_auth_available = settings.auth_mode != "oidc"
    setup_available = local_auth_available and settings.allow_setup and not has_users
    self_registration_available = local_auth_available and settings.self_registration_enabled and has_users
    return {
        "service": settings.service_name,
        "auth_mode": settings.auth_mode,
        "oidc_enabled": settings.oidc_enabled,
        "oidc_button_label": settings.oidc_button_label,
        "password_min_length": settings.password_min_length,
        "has_users": has_users,
        "setup_allowed": bool(settings.allow_setup),
        "setup_available": setup_available,
        "local_login_enabled": local_auth_available and has_users,
        "self_registration_enabled": self_registration_available,
        "team_provisioning_available": True,
        "service_accounts_supported": True,
        "totp_supported": local_auth_available,
        "passkeys_supported": local_auth_available,
    }


def _maybe_provision_workspace(user: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    workspace_name = str(
        payload.get("workspace_name")
        or payload.get("team_name")
        or payload.get("workspace")
        or ""
    ).strip()
    create_team_explicit = any(key in payload for key in ("create_team", "create_workspace"))
    create_team = _payload_bool(
        payload.get("create_team") if "create_team" in payload else payload.get("create_workspace"),
        default=False,
    )
    if not workspace_name and not create_team:
        return None
    if not create_team and workspace_name and not create_team_explicit:
        create_team = True
    if not create_team:
        return None
    try:
        team = _team_store().create_team(
            workspace_name or f"{user} workspace",
            owner_username=user,
        )
        return {
            "workspace_provisioned": True,
            "workspace": team,
        }
    except ValueError as exc:
        logger.warning("workspace provision skipped for %s: %s", user, exc)
        return {
            "workspace_provisioned": False,
            "workspace_error": str(exc),
        }
    except Exception as exc:
        logger.warning("workspace provision failed for %s: %s", user, exc)
        return {
            "workspace_provisioned": False,
            "workspace_error": "workspace_create_failed",
        }


def create_app() -> Flask:
    settings = Settings.from_env()
    if settings.oidc_enabled and settings.oidc_require_config:
        if not settings.oidc_issuer or not settings.oidc_client_id:
            raise RuntimeError("OIDC is enabled but CUSTOMERS_OIDC_ISSUER or CUSTOMERS_OIDC_CLIENT_ID is missing.")

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = settings.secret_key
    app.config.update(
        SESSION_COOKIE_NAME=settings.session_cookie_name,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=settings.cookie_samesite,
        SESSION_COOKIE_SECURE=settings.secure_cookies,
        SESSION_COOKIE_DOMAIN=settings.cookie_domain,
        JSON_SORT_KEYS=False,
    )

    store = create_central_store_from_env()
    store.users.ensure_admin_from_env()
    store.bootstrap_from_env((os.getenv("CUSTOMERS_ADMIN_USER") or "").strip())

    app.extensions["nm_settings"] = settings
    app.extensions["nm_store"] = store
    app.extensions["nmchain"] = NmChainClient.from_env()

    @app.before_request
    def _before_request() -> Optional[Response]:
        if settings.enforce_https and not _is_secure_request() and request.method != "OPTIONS":
            if request.method == "GET":
                return redirect(request.url.replace("http://", "https://", 1), code=308)
            return jsonify({"error": "https_required"}), 403
        if request.method == "OPTIONS":
            return make_response("", 204)
        return None

    @app.after_request
    def _after_request(response: Response) -> Response:
        return _apply_cors(response)

    @app.route("/")
    def index() -> Response:
        return redirect(url_for("login"))

    @app.route("/api/health")
    def api_health() -> Response:
        auth_config = _auth_config_payload()
        return jsonify(
            {
                "status": "ok",
                "service": settings.service_name,
                "version": settings.version,
                "store": _store_health(),
                "auth_mode": settings.auth_mode,
                "oidc_enabled": settings.oidc_enabled,
                "allow_setup": settings.allow_setup,
                "has_users": auth_config["has_users"],
                "setup_available": auth_config["setup_available"],
                "self_registration_enabled": auth_config["self_registration_enabled"],
                "oidc_button_label": settings.oidc_button_label,
                "team_provisioning_available": auth_config["team_provisioning_available"],
                "nmchain_enabled": bool(_nmchain()),
                "app_tokens_configured": sorted(settings.app_tokens.keys()),
            }
        )

    @app.route("/api/version")
    def api_version() -> Response:
        return jsonify({"service": settings.service_name, "version": settings.version})

    @app.route("/api/auth/config")
    def api_auth_config() -> Response:
        return jsonify(_auth_config_payload())

    def _render_login_page(*, error: Optional[str] = None, mfa_required: bool = False) -> Response:
        pending_login = _read_auth_challenge(_PENDING_LOGIN_SESSION_KEY)
        return make_response(
            render_template(
                "login.html",
                error=error,
                api_base=settings.api_base,
                oidc_enabled=settings.oidc_enabled,
                oidc_label=settings.oidc_button_label,
                local_enabled=store.users.has_users(),
                next_path=_safe_next_path(request.args.get("next") or session.get("login_next")),
                self_registration_enabled=bool(settings.self_registration_enabled and store.users.has_users()),
                passkeys_supported=settings.auth_mode != "oidc",
                password_min_length=settings.password_min_length,
                mfa_required=mfa_required or bool(pending_login),
                pending_username=str((pending_login or {}).get("user") or "").strip(),
            )
        )

    def _render_setup_page(*, error: Optional[str] = None) -> Response:
        return make_response(
            render_template(
                "setup.html",
                error=error,
                api_base=settings.api_base,
                next_path=_safe_next_path(request.args.get("next") or session.get("login_next")),
                passkeys_supported=settings.auth_mode != "oidc",
                password_min_length=settings.password_min_length,
            )
        )

    def _render_register_page(*, error: Optional[str] = None) -> Response:
        return make_response(
            render_template(
                "register.html",
                error=error,
                api_base=settings.api_base,
                next_path=_safe_next_path(request.args.get("next") or session.get("login_next")),
                passkeys_supported=settings.auth_mode != "oidc",
                password_min_length=settings.password_min_length,
            )
        )

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response:
        next_path = _safe_next_path(request.args.get("next") or session.get("login_next"))
        if settings.auth_mode == "oidc":
            session["login_next"] = next_path
            return redirect(url_for("oidc_login", next=next_path))
        if not store.users.has_users() and settings.allow_setup and not settings.oidc_enabled:
            session["login_next"] = next_path
            return redirect(url_for("setup"))
        error = None
        mfa_required = bool(_read_auth_challenge(_PENDING_LOGIN_SESSION_KEY))
        if request.method == "POST":
            totp_code = str(request.form.get("totp_code") or "").strip()
            if totp_code or mfa_required:
                outcome, payload, _status = _complete_totp_login(totp_code, source="login_form_mfa")
                if outcome == "success":
                    return redirect(next_path)
                error = _auth_error_message(payload, "Sign-in failed.")
                mfa_required = True
            else:
                username = str(request.form.get("username") or "").strip()
                password = str(request.form.get("password") or "")
                outcome, payload, _status = _attempt_local_login(username, password, source="login_form")
                if outcome == "success":
                    return redirect(next_path)
                if outcome == "mfa_required":
                    error = None
                    mfa_required = True
                else:
                    error = _auth_error_message(payload, "Invalid username or password.")
        return _render_login_page(error=error, mfa_required=mfa_required)

    @app.route("/register", methods=["GET", "POST"])
    def register() -> Response:
        next_path = _safe_next_path(request.args.get("next") or session.get("login_next"))
        if settings.auth_mode == "oidc":
            return redirect(url_for("login", next=next_path))
        if not settings.self_registration_enabled:
            return redirect(url_for("login", next=next_path))
        if not store.users.has_users():
            return redirect(url_for("setup", next=next_path))
        error = None
        if request.method == "POST":
            payload = {
                "username": request.form.get("username"),
                "password": request.form.get("password"),
                "confirm": request.form.get("confirm"),
                "email": request.form.get("email"),
                "workspace_name": request.form.get("workspace_name"),
                "create_team": request.form.get("workspace_name"),
            }
            response, status = _handle_registration_payload(payload, source="register_form")
            if status == 201:
                return redirect(next_path)
            body = response.get_json() if hasattr(response, "get_json") else {}
            error = _auth_error_message(body, "Registration failed.")
        return _render_register_page(error=error)

    @app.route("/setup", methods=["GET", "POST"])
    def setup() -> Response:
        next_path = _safe_next_path(request.args.get("next") or session.get("login_next"))
        if settings.auth_mode == "oidc":
            return redirect(url_for("login", next=next_path))
        if store.users.has_users() or not settings.allow_setup:
            return redirect(url_for("login", next=next_path))
        error = None
        if request.method == "POST":
            payload = {
                "username": request.form.get("username"),
                "password": request.form.get("password"),
                "confirm": request.form.get("confirm"),
                "email": request.form.get("email"),
            }
            response = _handle_setup_payload(payload, source="setup_form")
            if response[1] == 201:
                session.pop("login_next", None)
                return redirect(next_path)
            body = response[0].get_json() if hasattr(response[0], "get_json") else {}
            error = _auth_error_message(body, "Setup failed.")
        return _render_setup_page(error=error)

    @app.route("/logout")
    def logout() -> Response:
        _clear_auth_challenges()
        session.pop("user", None)
        session.pop("login_next", None)
        return redirect(url_for("login"))

    @app.route("/auth/external-login")
    def external_login() -> Response:
        target = _safe_external_redirect(request.args.get("rd"))
        user = _current_user()
        if user:
            return redirect(target)
        next_path = url_for("external_login", rd=target)
        session["login_next"] = next_path
        if settings.auth_mode == "oidc":
            return redirect(url_for("oidc_login", next=next_path))
        return redirect(url_for("login", next=next_path))

    @app.route("/oidc/login")
    def oidc_login() -> Response:
        if not settings.oidc_enabled:
            return jsonify({"error": "oidc_not_enabled"}), 404
        next_path = _safe_next_path(request.args.get("next") or session.get("login_next"))
        session["login_next"] = next_path
        config = _oidc_discovery()
        if not config:
            return jsonify({"error": "oidc_config_missing"}), 500
        auth_endpoint = config.get("authorization_endpoint")
        if not auth_endpoint:
            return jsonify({"error": "oidc_authorization_missing"}), 500
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(16)
        code_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
        session["oidc_state"] = state
        session["oidc_nonce"] = nonce
        session["oidc_code_verifier"] = code_verifier
        params = {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": _oidc_redirect_uri(),
            "scope": settings.oidc_scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        params.update(_parse_kv_params(settings.oidc_extra_params))
        return redirect(auth_endpoint + "?" + urlencode(params), code=302)

    @app.route("/oidc/callback")
    def oidc_callback() -> Response:
        if not settings.oidc_enabled:
            return jsonify({"error": "oidc_not_enabled"}), 404
        error = str(request.args.get("error") or "").strip()
        if error:
            return redirect(url_for("login"))
        code = str(request.args.get("code") or "").strip()
        state = str(request.args.get("state") or "").strip()
        if not code or not state or state != session.get("oidc_state"):
            return redirect(url_for("login"))
        config = _oidc_discovery() or {}
        token_endpoint = config.get("token_endpoint")
        if not token_endpoint:
            return jsonify({"error": "oidc_token_endpoint_missing"}), 500
        jwks_future = _oidc_prefetch_jwks(config)
        token_payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _oidc_redirect_uri(),
            "client_id": settings.oidc_client_id,
        }
        code_verifier = session.get("oidc_code_verifier")
        if code_verifier:
            token_payload["code_verifier"] = code_verifier
        auth = None
        if settings.oidc_client_secret:
            if settings.oidc_client_auth == "post":
                token_payload["client_secret"] = settings.oidc_client_secret
            else:
                auth = (settings.oidc_client_id, settings.oidc_client_secret)
        token_response = _run_api_exchange(
            _oidc_http_post,
            token_endpoint,
            data=token_payload,
            auth=auth,
            timeout=_OIDC_TOKEN_TIMEOUT_SEC,
            result_timeout=_OIDC_TOKEN_TIMEOUT_SEC + 1.0,
        )
        if token_response.status_code >= 400:
            return redirect(url_for("login"))
        token_data = token_response.json()
        id_token = str(token_data.get("id_token") or "")
        access_token = str(token_data.get("access_token") or "")
        if not id_token:
            return redirect(url_for("login"))
        raw_claims: Dict[str, Any] = {}
        try:
            _, raw_claims, _, _ = _parse_jwt(id_token)
        except Exception:
            raw_claims = {}
        userinfo_future = _oidc_prefetch_userinfo(access_token, claims=raw_claims, config=config)
        try:
            claims = _verify_jwt(
                id_token,
                nonce=session.get("oidc_nonce"),
                config=config,
                jwks_future=jwks_future,
            )
        except Exception:
            return redirect(url_for("login"))
        claims = _oidc_maybe_enrich_claims(
            claims,
            access_token,
            config=config,
            userinfo_future=userinfo_future,
        )
        username = _oidc_username_from_claims(claims)
        if not username:
            return redirect(url_for("login"))
        email = claims.get(settings.oidc_email_claim) if isinstance(claims.get(settings.oidc_email_claim), str) else None
        role = _oidc_role_from_claims(claims)
        subject = claims.get("sub") if isinstance(claims.get("sub"), str) else None
        try:
            store.users.upsert_external_user(username, role=role, email=email, provider="oidc", subject=subject)
        except ValueError as exc:
            if str(exc) == "principal_username_conflict":
                logger.warning("oidc principal %s collides with reserved service-account username", username)
                return redirect(url_for("login"))
            raise
        _finalize_login(
            username,
            auth_mode="oidc",
            provider="oidc",
            source="oidc_callback",
            role=role,
            email=email,
            subject=subject,
            session_id=subject,
        )
        for key in ("oidc_state", "oidc_nonce", "oidc_code_verifier"):
            session.pop(key, None)
        next_path = _safe_next_path(session.pop("login_next", None))
        return redirect(next_path or "/")

    @app.route("/sso")
    def sso_login() -> Response:
        token = str(request.args.get("token") or "").strip()
        next_path = _safe_next_path(request.args.get("next"))
        user = _consume_sso_token(token)
        if not user:
            return redirect(url_for("login"))
        _finalize_login(user, auth_mode="sso", provider="sso", source="sso_login")
        return redirect(next_path or "/")

    def _handle_setup_payload(payload: Dict[str, Any], *, source: str) -> Tuple[Response, int]:
        if settings.auth_mode == "oidc":
            return jsonify({"error": "oidc_required"}), 403
        if store.users.has_users() or not settings.allow_setup:
            return jsonify({"error": "setup_not_allowed"}), 409
        validated, error_response = _validate_account_creation_payload(payload, require_email=False)
        if error_response is not None:
            return error_response
        username = str((validated or {}).get("username") or "").strip()
        password = str((validated or {}).get("password") or "")
        email = (validated or {}).get("email")
        try:
            store.users.create_user(username, password, role="admin", email=email or None)
        except ValueError as exc:
            if str(exc) == "principal_username_conflict":
                return _reserved_username_error()
            raise
        workspace_payload = _maybe_provision_workspace(username, payload)
        _finalize_login(
            username,
            auth_mode="setup",
            provider="setup",
            source=source,
            role="admin",
            email=email or None,
        )
        response_payload = _login_payload(username, source=source)
        if workspace_payload:
            response_payload.update(workspace_payload)
        return jsonify(response_payload), 201

    @app.route("/api/setup", methods=["POST"])
    def api_setup() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        response, status = _handle_setup_payload(payload, source="api_setup")
        return response, status

    def _handle_registration_payload(payload: Dict[str, Any], *, source: str) -> Tuple[Response, int]:
        if settings.auth_mode == "oidc":
            return jsonify({"error": "oidc_required"}), 403
        if not settings.self_registration_enabled:
            return jsonify({"error": "registration_not_allowed"}), 403
        if not store.users.has_users():
            return jsonify({"error": "setup_required"}), 400
        validated, error_response = _validate_account_creation_payload(payload, require_email=True)
        if error_response is not None:
            return error_response
        username = str((validated or {}).get("username") or "").strip()
        password = str((validated or {}).get("password") or "")
        email = str((validated or {}).get("email") or "").strip()
        if store.users.get_user(username):
            return jsonify({"error": "user_exists", "details": "That username is already in use."}), 409
        try:
            store.users.create_user(username, password, role="user", email=email)
        except ValueError as exc:
            if str(exc) == "principal_username_conflict":
                return _reserved_username_error()
            raise
        workspace_payload = _maybe_provision_workspace(username, payload)
        _finalize_login(
            username,
            auth_mode="register",
            provider="register",
            source=source,
            role="user",
            email=email,
        )
        response_payload = _login_payload(username, source=source)
        if workspace_payload:
            response_payload.update(workspace_payload)
        return jsonify(response_payload), 201

    @app.route("/api/register", methods=["POST"])
    def api_register() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        response, status = _handle_registration_payload(payload, source="api_register")
        return response, status

    @app.route("/api/login", methods=["POST"])
    def api_login() -> Response:
        if not store.users.has_users():
            return jsonify({"error": "setup_required"}), 400
        if settings.auth_mode == "oidc":
            return jsonify({"error": "oidc_required"}), 403
        payload = request.get_json(force=True, silent=True) or {}
        outcome, response_payload, status = _attempt_local_login(
            str(payload.get("username") or "").strip(),
            str(payload.get("password") or ""),
            source="api_login",
        )
        return jsonify(response_payload), status

    @app.route("/api/login/mfa/totp", methods=["POST"])
    def api_login_mfa_totp() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        outcome, response_payload, status = _complete_totp_login(
            payload.get("code") or payload.get("totp_code"),
            source="api_login_mfa_totp",
        )
        return jsonify(response_payload), status

    @app.route("/api/oidc/exchange", methods=["POST"])
    def api_oidc_exchange() -> Response:
        if not settings.oidc_enabled or not settings.oidc_exchange_enabled:
            return jsonify({"error": "oidc_not_enabled"}), 404
        payload = request.get_json(force=True, silent=True) or {}
        code = str(payload.get("code") or "").strip()
        code_verifier = str(payload.get("code_verifier") or "").strip()
        client_id = str(payload.get("client_id") or "").strip()
        redirect_uri = str(payload.get("redirect_uri") or "").strip()
        id_token = str(payload.get("id_token") or "").strip()
        access_token = str(payload.get("access_token") or "").strip()
        if redirect_uri and not _oidc_is_redirect_allowed(redirect_uri):
            return jsonify({"error": "redirect_uri_not_allowed"}), 400
        config = _oidc_discovery() or {}
        jwks_future = _oidc_prefetch_jwks(config)
        if code:
            if client_id and client_id != settings.oidc_client_id:
                return jsonify({"error": "client_id_mismatch"}), 400
            token_endpoint = config.get("token_endpoint")
            if not token_endpoint:
                return jsonify({"error": "oidc_token_endpoint_missing"}), 500
            token_payload = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri or _oidc_redirect_uri(),
                "client_id": settings.oidc_client_id,
            }
            if code_verifier:
                token_payload["code_verifier"] = code_verifier
            auth = None
            if settings.oidc_client_secret:
                if settings.oidc_client_auth == "post":
                    token_payload["client_secret"] = settings.oidc_client_secret
                else:
                    auth = (settings.oidc_client_id, settings.oidc_client_secret)
            token_response = _run_api_exchange(
                _oidc_http_post,
                token_endpoint,
                data=token_payload,
                auth=auth,
                timeout=_OIDC_TOKEN_TIMEOUT_SEC,
                result_timeout=_OIDC_TOKEN_TIMEOUT_SEC + 1.0,
            )
            if token_response.status_code >= 400:
                return jsonify({"error": "token_exchange_failed"}), 401
            token_data = token_response.json()
            id_token = str(token_data.get("id_token") or "").strip()
            access_token = str(token_data.get("access_token") or "").strip()
        if not id_token:
            return jsonify({"error": "id_token_required"}), 400
        raw_claims: Dict[str, Any] = {}
        try:
            _, raw_claims, _, _ = _parse_jwt(id_token)
        except Exception:
            raw_claims = {}
        userinfo_future = _oidc_prefetch_userinfo(access_token, claims=raw_claims, config=config)
        try:
            claims = _verify_jwt(id_token, nonce=None, config=config, jwks_future=jwks_future)
        except Exception:
            return jsonify({"error": "invalid_id_token"}), 401
        claims = _oidc_maybe_enrich_claims(
            claims,
            access_token,
            config=config,
            userinfo_future=userinfo_future,
        )
        username = _oidc_username_from_claims(claims)
        if not username:
            return jsonify({"error": "username_missing"}), 400
        email = claims.get(settings.oidc_email_claim) if isinstance(claims.get(settings.oidc_email_claim), str) else None
        role = _oidc_role_from_claims(claims)
        subject = claims.get("sub") if isinstance(claims.get("sub"), str) else None
        try:
            store.users.upsert_external_user(username, role=role, email=email, provider="oidc", subject=subject)
        except ValueError as exc:
            if str(exc) == "principal_username_conflict":
                return jsonify({"error": "reserved_username"}), 409
            raise
        _finalize_login(
            username,
            auth_mode="oidc",
            provider="oidc",
            source="api_oidc_exchange",
            role=role,
            email=email,
            subject=subject,
            session_id=subject,
        )
        return jsonify(_login_payload(username, source="api_oidc_exchange"))

    @app.route("/api/sso/issue", methods=["POST"])
    def api_sso_issue() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        payload = {
            "status": "ok",
            "token": _issue_sso_token(user),
            "expires_in": settings.sso_ttl_seconds,
        }
        payload.update(_user_identity_payload(user))
        return jsonify(payload)

    @app.route("/api/logout", methods=["POST"])
    def api_logout() -> Response:
        _clear_auth_challenges()
        session.pop("user", None)
        session.pop("login_next", None)
        return jsonify({"status": "ok"})

    @app.route("/api/session")
    def api_session() -> Response:
        identity = _current_request_identity()
        if not identity:
            return jsonify({"authenticated": False, "user": None}), 200
        return jsonify({"authenticated": True, **identity})

    @app.route("/api/authz/nginx")
    def api_authz_nginx() -> Response:
        identity = _current_request_identity()
        if not identity:
            response = make_response("", 401)
            response.headers["Cache-Control"] = "no-store"
            return response
        response = make_response("", 204)
        response.headers["Cache-Control"] = "no-store"
        user = str(identity.get("user") or "").strip()
        response.headers["X-Auth-Request-User"] = user
        role = str(identity.get("role") or "").strip()
        if role:
            response.headers["X-Auth-Request-Role"] = role
        groups = [
            str(item).strip()
            for item in identity.get("groups", [])
            if str(item).strip()
        ]
        if groups:
            response.headers["X-Auth-Request-Groups"] = ",".join(groups)
        identity_type = str(identity.get("identity_type") or "").strip()
        if identity_type:
            response.headers["X-Auth-Request-Identity-Type"] = identity_type
        active_team = identity.get("active_team") if isinstance(identity.get("active_team"), dict) else None
        if active_team and active_team.get("team_id"):
            response.headers["X-Auth-Request-Team"] = str(active_team.get("team_id") or "")
        return response

    @app.route("/api/profile", methods=["GET", "POST"])
    def api_profile() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        if request.method == "GET":
            return jsonify(_user_identity_payload(user, include_directory=True))
        payload = request.get_json(force=True, silent=True) or {}
        email = None
        if "email" in payload:
            email = str(payload.get("email") or "").strip()
            if email and not EMAIL_RE.match(email):
                return jsonify({"error": "invalid_email", "details": "Enter a valid email address."}), 400
        if "settings" in payload:
            try:
                _update_user_settings(user, payload.get("settings"))
            except SettingsValidationError as exc:
                return jsonify({"error": "invalid_settings", "details": exc.issues}), 400
            except KeyError:
                return jsonify({"error": "user_not_found"}), 404
        if "email" in payload:
            store.users.set_email(user, email or None)
        _record_identity_event(
            user,
            role=_role_for_user(user),
            email=_email_for_user(user),
            provider="profile",
            meta={"source": "api_profile", "settings_updated": "settings" in payload},
        )
        return jsonify({"status": "ok", **_user_identity_payload(user, include_directory=True)})

    @app.route("/api/profile/password", methods=["POST"])
    def api_profile_password() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        user_entry = _store().users.get_user(user) or {}
        if not bool(user_entry.get("has_password")):
            return jsonify({"error": "local_password_unavailable"}), 409
        payload = request.get_json(force=True, silent=True) or {}
        validated, error_response = _validate_password_change_payload(payload, require_current=True)
        if error_response is not None:
            return error_response
        current_password = str((validated or {}).get("current_password") or "")
        new_password = str((validated or {}).get("new_password") or "")
        if not _store().users.verify(user, current_password):
            return jsonify({"error": "invalid_current_password"}), 403
        if not _store().users.set_password(user, new_password):
            return jsonify({"error": "user_not_found"}), 404
        _record_identity_event(
            user,
            role=_role_for_user(user),
            email=_email_for_user(user),
            provider="profile",
            meta={"source": "api_profile_password", "password_changed": True},
        )
        return jsonify({"status": "ok"})

    @app.route("/api/profile/mfa/totp/start", methods=["POST"])
    def api_profile_mfa_totp_start() -> Response:
        user = _current_user()
        auth_error = _validate_local_auth_security(user)
        if auth_error is not None:
            return auth_error
        secret = generate_totp_secret()
        enrolment = build_totp_enrolment(
            secret,
            issuer=settings.totp_issuer,
            account_name=str(user or ""),
        )
        _write_auth_challenge(
            _PENDING_TOTP_SETUP_SESSION_KEY,
            {
                "user": str(user or ""),
                "secret": secret,
            },
        )
        return jsonify(
            {
                "status": "ok",
                "totp": enrolment,
                "security": _user_security_payload(user, include_passkeys=True),
            }
        )

    @app.route("/api/profile/mfa/totp/verify", methods=["POST"])
    def api_profile_mfa_totp_verify() -> Response:
        user = _current_user()
        auth_error = _validate_local_auth_security(user)
        if auth_error is not None:
            return auth_error
        pending = _read_auth_challenge(_PENDING_TOTP_SETUP_SESSION_KEY)
        if not pending or str(pending.get("user") or "").strip() != str(user or "").strip():
            return jsonify({"error": "mfa_challenge_missing"}), 400
        secret = str(pending.get("secret") or "").strip()
        payload = request.get_json(force=True, silent=True) or {}
        code = payload.get("code") or payload.get("totp_code")
        if not verify_totp_code(secret, code):
            return jsonify({"error": "invalid_mfa_code"}), 401
        now_iso = _now_iso()
        security_state = _user_security_state(user)
        security_state["totp"] = {
            "enabled": True,
            "secret": secret,
            "enabled_at": str((security_state.get("totp") or {}).get("enabled_at") or now_iso),
            "last_verified_at": now_iso,
        }
        _update_user_security_state(str(user or ""), security_state)
        _clear_auth_challenges(_PENDING_TOTP_SETUP_SESSION_KEY)
        _record_identity_event(
            str(user or ""),
            role=_role_for_user(str(user or "")),
            email=_email_for_user(str(user or "")),
            provider="profile",
            meta={"source": "api_profile_mfa_totp_verify", "totp_enabled": True},
        )
        return jsonify(
            {
                "status": "ok",
                "security": _user_security_payload(user, include_passkeys=True),
            }
        )

    @app.route("/api/profile/mfa/totp/disable", methods=["POST"])
    def api_profile_mfa_totp_disable() -> Response:
        user = _current_user()
        auth_error = _validate_local_auth_security(user)
        if auth_error is not None:
            return auth_error
        security_state = _user_security_state(user)
        security_state["totp"] = {
            "enabled": False,
            "secret": None,
            "enabled_at": None,
            "last_verified_at": _now_iso(),
        }
        _update_user_security_state(str(user or ""), security_state)
        _clear_auth_challenges(_PENDING_TOTP_SETUP_SESSION_KEY)
        _record_identity_event(
            str(user or ""),
            role=_role_for_user(str(user or "")),
            email=_email_for_user(str(user or "")),
            provider="profile",
            meta={"source": "api_profile_mfa_totp_disable", "totp_enabled": False},
        )
        return jsonify(
            {
                "status": "ok",
                "security": _user_security_payload(user, include_passkeys=True),
            }
        )

    @app.route("/api/profile/passkeys/register/options", methods=["POST"])
    def api_profile_passkeys_register_options() -> Response:
        user = _current_user()
        auth_error = _validate_local_auth_security(user)
        if auth_error is not None:
            return auth_error
        payload = request.get_json(force=True, silent=True) or {}
        security_state = _user_security_state(user)
        security_state, user_id = ensure_passkey_user_id(security_state)
        _update_user_security_state(str(user or ""), security_state)
        options = passkey_registration_options(
            rp_id=_passkey_rp_id(),
            rp_name=_passkey_rp_name(),
            username=str(user or ""),
            user_id=user_id,
            exclude_credentials=security_state.get("passkeys", {}).get("credentials") or [],
        )
        _write_auth_challenge(
            _PENDING_PASSKEY_REGISTRATION_SESSION_KEY,
            {
                "user": str(user or ""),
                "challenge": str(options.get("challenge") or ""),
                "label": str(payload.get("label") or "").strip(),
            },
        )
        return jsonify(
            {
                "status": "ok",
                "public_key": options,
                "security": _user_security_payload(user, include_passkeys=True),
            }
        )

    @app.route("/api/profile/passkeys/register/verify", methods=["POST"])
    def api_profile_passkeys_register_verify() -> Response:
        user = _current_user()
        auth_error = _validate_local_auth_security(user)
        if auth_error is not None:
            return auth_error
        pending = _read_auth_challenge(_PENDING_PASSKEY_REGISTRATION_SESSION_KEY)
        if not pending or str(pending.get("user") or "").strip() != str(user or "").strip():
            return jsonify({"error": "passkey_challenge_missing"}), 400
        payload = request.get_json(force=True, silent=True) or {}
        credential = payload.get("credential") if isinstance(payload.get("credential"), dict) else payload
        label = str(payload.get("label") or pending.get("label") or "").strip() or None
        try:
            record = verify_passkey_registration(
                credential=dict(credential or {}),
                expected_challenge=str(pending.get("challenge") or ""),
                expected_rp_id=_passkey_rp_id(),
                expected_origins=_passkey_allowed_origins(),
                label=label,
                now_iso=_now_iso(),
            )
        except Exception as exc:
            logger.warning("passkey registration failed for %s: %s", user, exc)
            return jsonify({"error": "passkey_registration_failed"}), 400
        security_state = _user_security_state(user)
        credentials = list((security_state.get("passkeys") or {}).get("credentials") or [])
        index, _existing = find_passkey(credentials, record.get("credential_id"))
        if index >= 0:
            return jsonify({"error": "passkey_exists"}), 409
        if not record.get("label"):
            record["label"] = f"Passkey {len(credentials) + 1}"
        credentials.append(record)
        security_state["passkeys"] = {
            **dict(security_state.get("passkeys") or {}),
            "credentials": credentials,
        }
        _update_user_security_state(str(user or ""), security_state)
        _clear_auth_challenges(_PENDING_PASSKEY_REGISTRATION_SESSION_KEY)
        _record_identity_event(
            str(user or ""),
            role=_role_for_user(str(user or "")),
            email=_email_for_user(str(user or "")),
            provider="profile",
            meta={"source": "api_profile_passkeys_register_verify", "passkey_registered": True},
        )
        return (
            jsonify(
                {
                    "status": "ok",
                    "security": _user_security_payload(user, include_passkeys=True),
                }
            ),
            201,
        )

    @app.route("/api/profile/passkeys/<credential_id>", methods=["DELETE"])
    def api_profile_passkey_delete(credential_id: str) -> Response:
        user = _current_user()
        auth_error = _validate_local_auth_security(user)
        if auth_error is not None:
            return auth_error
        security_state = _user_security_state(user)
        credentials = list((security_state.get("passkeys") or {}).get("credentials") or [])
        index, _existing = find_passkey(credentials, credential_id)
        if index < 0:
            return jsonify({"error": "passkey_not_found"}), 404
        credentials.pop(index)
        security_state["passkeys"] = {
            **dict(security_state.get("passkeys") or {}),
            "credentials": credentials,
        }
        _update_user_security_state(str(user or ""), security_state)
        _record_identity_event(
            str(user or ""),
            role=_role_for_user(str(user or "")),
            email=_email_for_user(str(user or "")),
            provider="profile",
            meta={"source": "api_profile_passkey_delete", "passkey_removed": True},
        )
        return jsonify(
            {
                "status": "ok",
                "security": _user_security_payload(user, include_passkeys=True),
            }
        )

    @app.route("/api/passkeys/authenticate/options", methods=["POST"])
    def api_passkeys_authenticate_options() -> Response:
        if settings.auth_mode == "oidc":
            return jsonify({"error": "oidc_required"}), 403
        payload = request.get_json(force=True, silent=True) or {}
        username = str(payload.get("username") or "").strip()
        if not username:
            return jsonify({"error": "username_required"}), 400
        if not _user_has_local_password(username):
            return jsonify({"error": "passkey_sign_in_unavailable"}), 404
        security_state = _user_security_state(username)
        credentials = list((security_state.get("passkeys") or {}).get("credentials") or [])
        if not credentials:
            return jsonify({"error": "passkey_sign_in_unavailable"}), 404
        options = passkey_authentication_options(
            rp_id=_passkey_rp_id(),
            allow_credentials=credentials,
        )
        session.pop("user", None)
        _write_auth_challenge(
            _PENDING_PASSKEY_AUTHENTICATION_SESSION_KEY,
            {
                "user": username,
                "challenge": str(options.get("challenge") or ""),
            },
        )
        return jsonify({"status": "ok", "public_key": options})

    @app.route("/api/passkeys/authenticate/verify", methods=["POST"])
    def api_passkeys_authenticate_verify() -> Response:
        if settings.auth_mode == "oidc":
            return jsonify({"error": "oidc_required"}), 403
        pending = _read_auth_challenge(_PENDING_PASSKEY_AUTHENTICATION_SESSION_KEY)
        if not pending:
            return jsonify({"error": "passkey_challenge_missing"}), 400
        username = str(pending.get("user") or "").strip()
        if not username:
            _clear_auth_challenges(_PENDING_PASSKEY_AUTHENTICATION_SESSION_KEY)
            return jsonify({"error": "passkey_challenge_missing"}), 400
        payload = request.get_json(force=True, silent=True) or {}
        credential = payload.get("credential") if isinstance(payload.get("credential"), dict) else payload
        credential_id = str((credential or {}).get("id") or "").strip()
        if not credential_id:
            return jsonify({"error": "passkey_invalid"}), 401
        security_state = _user_security_state(username)
        credentials = list((security_state.get("passkeys") or {}).get("credentials") or [])
        index, stored_credential = find_passkey(credentials, credential_id)
        if index < 0 or stored_credential is None:
            return jsonify({"error": "passkey_invalid"}), 401
        try:
            updated_credential = verify_passkey_authentication(
                credential=dict(credential or {}),
                expected_challenge=str(pending.get("challenge") or ""),
                expected_rp_id=_passkey_rp_id(),
                expected_origins=_passkey_allowed_origins(),
                stored_credential=stored_credential,
                now_iso=_now_iso(),
            )
        except Exception as exc:
            logger.warning("passkey authentication failed for %s: %s", username, exc)
            return jsonify({"error": "passkey_invalid"}), 401
        credentials[index] = updated_credential
        security_state["passkeys"] = {
            **dict(security_state.get("passkeys") or {}),
            "credentials": credentials,
        }
        _update_user_security_state(username, security_state)
        _clear_auth_challenges(_PENDING_PASSKEY_AUTHENTICATION_SESSION_KEY)
        _finalize_login(username, auth_mode="passkey", provider="passkey", source="api_passkey_authenticate")
        return jsonify(_login_payload(username, source="api_passkey_authenticate"))

    @app.route("/api/users", methods=["GET", "POST"])
    def api_users() -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        if not _is_admin_user(actor):
            return jsonify({"error": "forbidden"}), 403
        if request.method == "GET":
            users_payload: List[Dict[str, Any]] = []
            for entry in _store().users.list_users():
                if _is_service_account_user_entry(entry):
                    continue
                username = str(entry.get("username") or "").strip()
                active_teams = _active_team_memberships_for_user(username)
                pending_invitations = _incoming_team_invitations_for_user(username)
                item = _user_record_payload(entry)
                item["active_team"] = active_teams[0] if active_teams else None
                item["team_count"] = len(active_teams)
                item["pending_invitation_count"] = len(pending_invitations)
                users_payload.append(item)
            return jsonify({"users": users_payload})
        payload = request.get_json(force=True, silent=True) or {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        confirm = str(payload.get("confirm") or payload.get("confirm_password") or "")
        role = str(payload.get("role") or "user").strip().lower() or "user"
        email_present = "email" in payload
        email = str(payload.get("email") or "").strip()
        if not username:
            return jsonify({"error": "username_required"}), 400
        if not USERNAME_RE.match(username):
            return (
                jsonify(
                    {
                        "error": "invalid_username",
                        "details": "Username must be 3-32 chars (letters, numbers, underscore, dash).",
                    }
                ),
                400,
            )
        if _is_service_account_principal(username):
            return jsonify({"error": "reserved_username"}), 409
        if role not in ALLOWED_USER_ROLES:
            return jsonify({"error": "invalid_role", "details": "Role must be one of admin, user."}), 400
        if email and not EMAIL_RE.match(email):
            return jsonify({"error": "invalid_email", "details": "Enter a valid email address."}), 400
        if password and len(password) < settings.password_min_length:
            return (
                jsonify(
                    {
                        "error": "password_too_short",
                        "details": f"Password must be at least {settings.password_min_length} characters.",
                    }
                ),
                400,
            )
        if confirm and confirm != password:
            return jsonify({"error": "password_mismatch", "details": "Passwords do not match."}), 400
        existing = _store().users.get_user(username)
        status_code = 200
        if existing:
            _store().users.ensure_user(username, role=role, email=existing.get("email"))
            if email_present:
                _store().users.set_email(username, email or None)
            if password:
                _store().users.set_password(username, password)
        else:
            if not password:
                return jsonify({"error": "password_required"}), 400
            _store().users.create_user(username, password, role=role, email=email or None)
            status_code = 201
        user_entry = _store().users.get_user(username) or {"username": username, "role": role, "email": email or None}
        _record_identity_event(
            username,
            role=str(user_entry.get("role") or role),
            email=str(user_entry.get("email") or "").strip() or None,
            provider="admin",
            meta={"source": "api_users", "actor": actor},
        )
        return jsonify({"status": "ok", "user_record": _user_record_payload(user_entry, include_access=True)}), status_code

    @app.route("/api/users/<username>/password", methods=["POST"])
    def api_user_password(username: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        if not _is_admin_user(actor):
            return jsonify({"error": "forbidden"}), 403
        target = str(username or "").strip()
        if not target:
            return jsonify({"error": "username_required"}), 400
        user_entry = _store().users.get_user(target)
        if _is_service_account_user_entry(user_entry):
            return jsonify({"error": "service_account_password_not_supported"}), 409
        if not user_entry:
            return jsonify({"error": "user_not_found"}), 404
        payload = request.get_json(force=True, silent=True) or {}
        validated, error_response = _validate_password_change_payload(payload, require_current=False)
        if error_response is not None:
            return error_response
        new_password = str((validated or {}).get("new_password") or "")
        if not _store().users.set_password(target, new_password):
            return jsonify({"error": "user_not_found"}), 404
        _record_identity_event(
            target,
            role=_role_for_user(target),
            email=_email_for_user(target),
            provider="admin",
            meta={"source": "api_user_password", "actor": actor, "password_changed": True},
        )
        return jsonify({"status": "ok", "user": target})

    @app.route("/api/services")
    def api_services() -> Response:
        identity = _current_request_identity()
        if identity:
            service_access = identity.get("service_access") if isinstance(identity.get("service_access"), dict) else {}
            services = [
                item
                for item in service_access.values()
                if isinstance(item, dict) and bool(item.get("visible"))
            ]
            services.sort(key=lambda item: str(item.get("service_key") or ""))
            authenticated = bool(identity.get("authenticated"))
            actor = str(identity.get("user") or "").strip() or None
            identity_type = str(identity.get("identity_type") or "").strip() or None
        else:
            services = [
                item
                for item in _service_access_records_for_user("")
                if bool(item.get("visible"))
            ]
            authenticated = False
            actor = None
            identity_type = None
        return jsonify(
            {
                "authenticated": authenticated,
                "user": actor,
                "identity_type": identity_type,
                "services": services,
                "visible_services": [str(item.get("service_key") or "").strip() for item in services],
            }
        )

    @app.route("/api/groups", methods=["GET", "POST"])
    def api_groups() -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        if request.method == "GET":
            visible_groups = _visible_group_records_for_user(actor)
            memberships = {
                str(item.get("group_key") or "").strip().lower(): item
                for item in _group_memberships_for_user(actor)
                if str(item.get("group_key") or "").strip()
            }
            manageable = set(_manageable_group_keys(actor))
            return jsonify(
                {
                    "groups": [
                        {
                            **group,
                            "can_manage": str(group.get("key") or "").strip().lower() in manageable,
                            "membership": memberships.get(str(group.get("key") or "").strip().lower()),
                        }
                        for group in visible_groups
                    ],
                    "visible_groups": sorted(str(item.get("key") or "").strip().lower() for item in visible_groups if item.get("key")),
                    "manageable_groups": sorted(manageable),
                }
            )
        payload = request.get_json(force=True, silent=True) or {}
        raw_key = payload.get("key") or payload.get("group_key")
        name = str(payload.get("name") or "").strip()
        raw_parent = payload.get("parent_key") or payload.get("parent")
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else None
        if _payload_bool(payload.get("system"), default=False):
            return jsonify({"error": "system_groups_reserved"}), 403
        try:
            group_key = normalize_group_key(raw_key)
        except ValueError:
            return jsonify({"error": "invalid_group_key"}), 400
        if _access_store().get_group(group_key):
            return jsonify({"error": "group_exists"}), 409
        parent_key = None
        parent_group = None
        if raw_parent not in (None, ""):
            try:
                parent_key = normalize_group_key(raw_parent)
            except ValueError:
                return jsonify({"error": "invalid_parent_group_key"}), 400
            parent_group = _access_store().get_group(parent_key)
            if not parent_group:
                return jsonify({"error": "parent_group_not_found"}), 404
            if bool(parent_group.get("system")) and not _is_admin_user(actor):
                return jsonify({"error": "forbidden"}), 403
            if not _is_admin_user(actor) and not _can_manage_group(actor, parent_key):
                return jsonify({"error": "forbidden"}), 403
        elif not _is_admin_user(actor):
            return jsonify({"error": "parent_group_required"}), 400
        try:
            group = _access_store().upsert_group(
                group_key,
                name=name or group_key,
                parent_key=parent_key,
                metadata=metadata,
            )
        except ValueError as exc:
            reason = str(exc)
            if reason == "parent_group_not_found":
                return jsonify({"error": "parent_group_not_found"}), 404
            if reason == "group_parent_cycle":
                return jsonify({"error": "group_parent_cycle"}), 409
            raise
        return jsonify({"status": "ok", "group": group, **_group_detail_payload(group_key, actor)}), 201

    @app.route("/api/groups/<group_key>")
    def api_group_detail(group_key: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        try:
            cleaned = normalize_group_key(group_key)
        except ValueError:
            return jsonify({"error": "invalid_group_key"}), 400
        if not _access_store().get_group(cleaned):
            return jsonify({"error": "group_not_found"}), 404
        if not _can_view_group(actor, cleaned):
            return jsonify({"error": "forbidden"}), 403
        return jsonify(_group_detail_payload(cleaned, actor))

    @app.route("/api/groups/<group_key>/members", methods=["POST"])
    def api_group_membership_upsert(group_key: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        try:
            cleaned_group = normalize_group_key(group_key)
        except ValueError:
            return jsonify({"error": "invalid_group_key"}), 400
        group = _access_store().get_group(cleaned_group)
        if not group:
            return jsonify({"error": "group_not_found"}), 404
        if bool(group.get("system")) and not _is_admin_user(actor):
            return jsonify({"error": "forbidden"}), 403
        if not _can_manage_group(actor, cleaned_group):
            return jsonify({"error": "forbidden"}), 403
        payload = request.get_json(force=True, silent=True) or {}
        username = str(payload.get("username") or payload.get("user") or "").strip()
        if not username:
            return jsonify({"error": "username_required"}), 400
        if not _store().users.get_user(username):
            return jsonify({"error": "user_not_found"}), 404
        raw_membership_role = payload.get("membership_role") or payload.get("role")
        if raw_membership_role in (None, "") and _payload_bool(payload.get("manager"), default=False):
            raw_membership_role = GROUP_MEMBERSHIP_ROLE_MANAGER
        if raw_membership_role in (None, ""):
            raw_membership_role = "member"
        try:
            membership_role = normalize_group_membership_role(raw_membership_role)
        except ValueError:
            return jsonify({"error": "invalid_group_membership_role"}), 400
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else None
        existing_membership = _group_membership_for_user(cleaned_group, username)
        try:
            membership = _access_store().upsert_group_membership(
                cleaned_group,
                username,
                membership_role=membership_role,
                metadata=metadata,
            )
        except ValueError as exc:
            reason = str(exc)
            if reason == "group_not_found":
                return jsonify({"error": "group_not_found"}), 404
            if reason == "user_not_found":
                return jsonify({"error": "user_not_found"}), 404
            if reason == "username_required":
                return jsonify({"error": "username_required"}), 400
            raise
        status_code = 200 if existing_membership else 201
        return jsonify({"status": "ok", "membership": membership, **_group_detail_payload(cleaned_group, actor)}), status_code

    @app.route("/api/groups/<group_key>/members/<username>", methods=["DELETE"])
    def api_group_membership_delete(group_key: str, username: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        try:
            cleaned_group = normalize_group_key(group_key)
        except ValueError:
            return jsonify({"error": "invalid_group_key"}), 400
        group = _access_store().get_group(cleaned_group)
        if not group:
            return jsonify({"error": "group_not_found"}), 404
        if bool(group.get("system")) and not _is_admin_user(actor):
            return jsonify({"error": "forbidden"}), 403
        if not _can_manage_group(actor, cleaned_group):
            return jsonify({"error": "forbidden"}), 403
        cleaned_user = str(username or "").strip()
        if not cleaned_user:
            return jsonify({"error": "username_required"}), 400
        if not _access_store().delete_group_membership(cleaned_group, cleaned_user):
            return jsonify({"error": "group_membership_not_found"}), 404
        return jsonify({"status": "ok", "group_key": cleaned_group, "username": cleaned_user, **_group_detail_payload(cleaned_group, actor)})

    @app.route("/api/groups/<group_key>/grants", methods=["POST"])
    def api_group_grant_upsert(group_key: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        try:
            cleaned_group = normalize_group_key(group_key)
        except ValueError:
            return jsonify({"error": "invalid_group_key"}), 400
        group = _access_store().get_group(cleaned_group)
        if not group:
            return jsonify({"error": "group_not_found"}), 404
        if bool(group.get("system")) and not _is_admin_user(actor):
            return jsonify({"error": "forbidden"}), 403
        if not _can_manage_group(actor, cleaned_group):
            return jsonify({"error": "forbidden"}), 403
        payload = request.get_json(force=True, silent=True) or {}
        try:
            service_key = normalize_service_key(payload.get("service_key") or payload.get("service"))
        except ValueError:
            return jsonify({"error": "invalid_service_key"}), 400
        if not _access_store().get_service(service_key):
            return jsonify({"error": "service_not_found"}), 404
        try:
            access_level = normalize_service_access_level(payload.get("access_level") or payload.get("level"))
        except ValueError:
            return jsonify({"error": "invalid_service_access_level"}), 400
        if access_level == SERVICE_ACCESS_NONE:
            deleted = _access_store().delete_group_service_grant(cleaned_group, service_key)
            return jsonify(
                {
                    "status": "deleted" if deleted else "noop",
                    "group_key": cleaned_group,
                    "service_key": service_key,
                    "grants": _group_effective_grants(cleaned_group),
                }
            )
        parent_limit = _parent_group_effective_access_level(cleaned_group, service_key)
        if parent_limit is not None and not service_access_at_least(parent_limit, access_level):
            return (
                jsonify(
                    {
                        "error": "grant_exceeds_parent",
                        "details": {
                            "group_key": cleaned_group,
                            "service_key": service_key,
                            "requested": access_level,
                            "parent_limit": parent_limit,
                        },
                    }
                ),
                409,
            )
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else None
        existing_grant = _access_store().get_group_service_grant(cleaned_group, service_key)
        try:
            grant = _access_store().upsert_group_service_grant(
                cleaned_group,
                service_key,
                access_level=access_level,
                granted_by=actor,
                metadata=metadata,
            )
        except ValueError as exc:
            reason = str(exc)
            if reason == "group_not_found":
                return jsonify({"error": "group_not_found"}), 404
            if reason == "service_not_found":
                return jsonify({"error": "service_not_found"}), 404
            raise
        return jsonify({"status": "ok", "grant": grant, "grants": _group_effective_grants(cleaned_group)}), 200 if existing_grant else 201

    @app.route("/api/groups/<group_key>/grants/<service_key>", methods=["DELETE"])
    def api_group_grant_delete(group_key: str, service_key: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        try:
            cleaned_group = normalize_group_key(group_key)
        except ValueError:
            return jsonify({"error": "invalid_group_key"}), 400
        group = _access_store().get_group(cleaned_group)
        if not group:
            return jsonify({"error": "group_not_found"}), 404
        if bool(group.get("system")) and not _is_admin_user(actor):
            return jsonify({"error": "forbidden"}), 403
        if not _can_manage_group(actor, cleaned_group):
            return jsonify({"error": "forbidden"}), 403
        try:
            cleaned_service = normalize_service_key(service_key)
        except ValueError:
            return jsonify({"error": "invalid_service_key"}), 400
        if not _access_store().delete_group_service_grant(cleaned_group, cleaned_service):
            return jsonify({"error": "group_service_grant_not_found"}), 404
        return jsonify({"status": "ok", "group_key": cleaned_group, "service_key": cleaned_service, "grants": _group_effective_grants(cleaned_group)})

    @app.route("/api/service-accounts", methods=["GET", "POST"])
    def api_service_accounts() -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        if request.method == "GET":
            accounts = []
            for account in _service_account_store().list_service_accounts(include_disabled=True):
                if not _can_view_service_account(actor, account):
                    continue
                accounts.append(_service_account_payload(account, actor=actor))
            return jsonify({"service_accounts": accounts})
        payload = request.get_json(force=True, silent=True) or {}
        try:
            service_account_id = normalize_service_account_id(
                payload.get("service_account_id") or payload.get("id") or payload.get("key")
            )
        except ValueError:
            return jsonify({"error": "invalid_service_account_id"}), 400
        if _service_account_record(service_account_id, include_disabled=True):
            return jsonify({"error": "service_account_exists"}), 409
        display_name = str(
            payload.get("display_name") or payload.get("name") or service_account_id
        ).strip() or service_account_id
        description = str(payload.get("description") or "").strip() or None
        raw_service_key = payload.get("service_key") or payload.get("service")
        service_key = None
        if raw_service_key not in (None, ""):
            try:
                service_key = normalize_service_key(raw_service_key)
            except ValueError:
                return jsonify({"error": "invalid_service_key"}), 400
            if not _access_store().get_service(service_key):
                return jsonify({"error": "service_not_found"}), 404
        group_keys = _service_account_group_keys_from_payload(payload)
        if not group_keys:
            return jsonify({"error": "group_keys_required"}), 400
        for group_key in group_keys:
            group = _access_store().get_group(group_key)
            if not group:
                return jsonify({"error": "group_not_found", "group_key": group_key}), 404
            if bool(group.get("system")) and not _is_admin_user(actor):
                return jsonify({"error": "forbidden"}), 403
            if not _can_manage_group(actor, group_key):
                return jsonify({"error": "forbidden"}), 403
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else None
        try:
            account = _service_account_store().upsert_service_account(
                service_account_id,
                display_name=display_name,
                description=description,
                service_key=service_key,
                created_by=actor,
                metadata=metadata,
            )
        except ValueError as exc:
            reason = str(exc)
            if reason == "service_not_found":
                return jsonify({"error": "service_not_found"}), 404
            if reason == "created_by_not_found":
                return jsonify({"error": "unauthorized"}), 401
            if reason == "principal_username_conflict":
                return jsonify({"error": "service_account_username_conflict"}), 409
            raise
        for group_key in group_keys:
            _access_store().upsert_group_membership(
                group_key,
                str(account.get("principal_username") or "").strip(),
                membership_role="member",
            )
        response_payload: Dict[str, Any] = {
            "status": "ok",
            "service_account": _service_account_payload(account, actor=actor, include_tokens=True),
        }
        if _payload_bool(payload.get("issue_token"), default=True):
            ttl_seconds = payload.get("token_ttl_seconds")
            if ttl_seconds not in (None, ""):
                try:
                    ttl_seconds = int(ttl_seconds)
                except Exception:
                    return jsonify({"error": "invalid_token_ttl_seconds"}), 400
            label = str(payload.get("token_label") or payload.get("label") or "service_account_create").strip() or None
            meta_payload = payload.get("token_meta") if isinstance(payload.get("token_meta"), dict) else {}
            issued = _issue_service_account_access_token(
                account,
                label=label,
                ttl_seconds=ttl_seconds,
                meta=meta_payload,
            )
            response_payload.update(issued)
            response_payload["service_account"] = _service_account_payload(account, actor=actor, include_tokens=True)
        return jsonify(response_payload), 201

    @app.route("/api/service-accounts/<service_account_id>")
    def api_service_account_detail(service_account_id: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        account = _service_account_record(service_account_id, include_disabled=True)
        if not account:
            return jsonify({"error": "service_account_not_found"}), 404
        if not _can_view_service_account(actor, account):
            return jsonify({"error": "forbidden"}), 403
        return jsonify(_service_account_payload(account, actor=actor, include_tokens=True))

    @app.route("/api/service-accounts/<service_account_id>/tokens", methods=["POST"])
    def api_service_account_tokens(service_account_id: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        account = _service_account_record(service_account_id, include_disabled=True)
        if not account:
            return jsonify({"error": "service_account_not_found"}), 404
        if not _can_manage_service_account(actor, account):
            return jsonify({"error": "forbidden"}), 403
        if bool(account.get("disabled")):
            return jsonify({"error": "service_account_disabled"}), 409
        payload = request.get_json(force=True, silent=True) or {}
        ttl_seconds = payload.get("ttl_seconds")
        if ttl_seconds not in (None, ""):
            try:
                ttl_seconds = int(ttl_seconds)
            except Exception:
                return jsonify({"error": "invalid_ttl_seconds"}), 400
        label = str(payload.get("label") or "service_account_issue").strip() or None
        meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else None
        issued = _issue_service_account_access_token(
            account,
            label=label,
            ttl_seconds=ttl_seconds,
            meta=meta,
        )
        return (
            jsonify(
                {
                    "status": "ok",
                    "service_account": _service_account_payload(account, actor=actor, include_tokens=True),
                    **issued,
                }
            ),
            201,
        )

    @app.route("/api/service-accounts/<service_account_id>/tokens/<token_id>", methods=["DELETE"])
    def api_service_account_token_delete(service_account_id: str, token_id: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        account = _service_account_record(service_account_id, include_disabled=True)
        if not account:
            return jsonify({"error": "service_account_not_found"}), 404
        if not _can_manage_service_account(actor, account):
            return jsonify({"error": "forbidden"}), 403
        principal_username = str(account.get("principal_username") or "").strip()
        allowed_ids = {
            str(item.get("id") or "").strip()
            for item in _store().access_tokens.list_tokens(principal_username)
            if str(item.get("id") or "").strip()
        }
        if token_id not in allowed_ids:
            return jsonify({"error": "token_not_found"}), 404
        if not _store().access_tokens.revoke(token_id):
            return jsonify({"error": "token_not_found"}), 404
        return jsonify(
            {
                "status": "revoked",
                "id": token_id,
                "service_account": _service_account_payload(account, actor=actor, include_tokens=True),
            }
        )

    @app.route("/api/service-accounts/<service_account_id>/disable", methods=["POST"])
    def api_service_account_disable(service_account_id: str) -> Response:
        actor = _current_user()
        if not actor:
            return jsonify({"error": "unauthorized"}), 401
        account = _service_account_record(service_account_id, include_disabled=True)
        if not account:
            return jsonify({"error": "service_account_not_found"}), 404
        if not _can_manage_service_account(actor, account):
            return jsonify({"error": "forbidden"}), 403
        payload = request.get_json(force=True, silent=True) or {}
        disabled = _payload_bool(payload.get("disabled"), default=True)
        updated = _service_account_store().set_disabled(service_account_id, disabled)
        if not updated:
            return jsonify({"error": "service_account_not_found"}), 404
        return jsonify(
            {
                "status": "disabled" if disabled else "enabled",
                "service_account": _service_account_payload(updated, actor=actor, include_tokens=True),
            }
        )

    @app.route("/api/teams", methods=["GET", "POST"])
    def api_teams() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        if request.method == "GET":
            memberships = _active_team_memberships_for_user(user)
            incoming = _incoming_team_invitations_for_user(user)
            outgoing = _team_store().list_invitations_sent_by(user, statuses=[TEAM_MEMBERSHIP_STATUS_PENDING])
            teams_payload = _visible_team_records_for_user(user)
            return jsonify(
                {
                    "teams": teams_payload,
                    "tree": _build_team_tree(teams_payload, memberships + incoming),
                    "memberships": memberships,
                    "incoming_invitations": incoming,
                    "outgoing_invitations": outgoing,
                }
            )
        payload = request.get_json(force=True, silent=True) or {}
        name = str(payload.get("name") or "").strip()
        parent_id = str(payload.get("parent_id") or "").strip() or None
        owner_username = str(payload.get("owner") or user).strip()
        if not owner_username:
            return jsonify({"error": "owner_required"}), 400
        if not _is_admin_user(user) and owner_username != user:
            return jsonify({"error": "forbidden"}), 403
        if parent_id and not (_is_admin_user(user) or _can_manage_team(user, parent_id)):
            return jsonify({"error": "forbidden"}), 403
        try:
            team = _team_store().create_team(name, owner_username=owner_username, parent_id=parent_id)
        except ValueError as exc:
            reason = str(exc)
            if reason == "user_not_found":
                return jsonify({"error": "user_not_found"}), 404
            if reason == "parent_team_not_found":
                return jsonify({"error": "parent_team_not_found"}), 404
            if reason == "user_already_in_team":
                return jsonify({"error": "user_already_in_team"}), 409
            if reason == "owner_required":
                return jsonify({"error": "owner_required"}), 400
            raise
        _record_identity_event(
            owner_username,
            role=_role_for_user(owner_username),
            email=_email_for_user(owner_username),
            provider="teams",
            meta={"source": "api_teams_create", "team_id": team.get("id"), "actor": user},
        )
        return jsonify(team), 201

    @app.route("/api/teams/<team_id>")
    def api_team_detail(team_id: str) -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        team = _team_store().get_team(team_id)
        if not team:
            return jsonify({"error": "team_not_found"}), 404
        if not _can_view_team(user, team_id):
            return jsonify({"error": "forbidden"}), 403
        active_members = _team_store().list_team_members(team_id, statuses=[TEAM_MEMBERSHIP_STATUS_ACTIVE])
        pending_members = _team_store().list_team_members(team_id, statuses=[TEAM_MEMBERSHIP_STATUS_PENDING])
        return jsonify({"team": team, "members": active_members, "pending_invitations": pending_members})

    @app.route("/api/teams/<team_id>/invite", methods=["POST"])
    def api_team_invite(team_id: str) -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        if not _can_manage_team(user, team_id):
            return jsonify({"error": "forbidden"}), 403
        payload = request.get_json(force=True, silent=True) or {}
        target_username = str(payload.get("username") or payload.get("user") or "").strip()
        if not target_username:
            return jsonify({"error": "username_required"}), 400
        try:
            invitation = _team_store().invite_user(team_id, target_username, invited_by=user)
        except ValueError as exc:
            reason = str(exc)
            if reason == "team_not_found":
                return jsonify({"error": "team_not_found"}), 404
            if reason == "user_not_found":
                return jsonify({"error": "user_not_found"}), 404
            if reason == "user_already_in_team":
                return jsonify({"error": "user_already_in_team"}), 409
            if reason == "username_required":
                return jsonify({"error": "username_required"}), 400
            raise
        return jsonify(invitation), 201

    @app.route("/api/team-invitations/<membership_id>/accept", methods=["POST"])
    def api_team_invitation_accept(membership_id: str) -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        invitation = _team_store().get_membership(membership_id)
        if not invitation:
            return jsonify({"error": "invitation_not_found"}), 404
        target_user = str(invitation.get("username") or "").strip()
        if target_user != user and not _is_admin_user(user):
            return jsonify({"error": "forbidden"}), 403
        try:
            updated = _team_store().respond_to_invitation(membership_id, target_user, accept=True)
        except ValueError as exc:
            reason = str(exc)
            if reason == "invitation_not_found":
                return jsonify({"error": "invitation_not_found"}), 404
            if reason == "invitation_not_pending":
                return jsonify({"error": "invitation_not_pending"}), 409
            if reason == "user_already_in_team":
                return jsonify({"error": "user_already_in_team"}), 409
            if reason == "invitation_not_owned":
                return jsonify({"error": "forbidden"}), 403
            raise
        _record_identity_event(
            target_user,
            role=_role_for_user(target_user),
            email=_email_for_user(target_user),
            provider="teams",
            meta={"source": "api_team_invitation_accept", "team_id": updated.get("team_id"), "actor": user},
        )
        return jsonify(updated)

    @app.route("/api/team-invitations/<membership_id>/reject", methods=["POST"])
    def api_team_invitation_reject(membership_id: str) -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        invitation = _team_store().get_membership(membership_id)
        if not invitation:
            return jsonify({"error": "invitation_not_found"}), 404
        target_user = str(invitation.get("username") or "").strip()
        if target_user != user and not _is_admin_user(user):
            return jsonify({"error": "forbidden"}), 403
        try:
            updated = _team_store().respond_to_invitation(membership_id, target_user, accept=False)
        except ValueError as exc:
            reason = str(exc)
            if reason == "invitation_not_found":
                return jsonify({"error": "invitation_not_found"}), 404
            if reason == "invitation_not_pending":
                return jsonify({"error": "invitation_not_pending"}), 409
            if reason == "invitation_not_owned":
                return jsonify({"error": "forbidden"}), 403
            raise
        _record_identity_event(
            target_user,
            role=_role_for_user(target_user),
            email=_email_for_user(target_user),
            provider="teams",
            meta={"source": "api_team_invitation_reject", "team_id": updated.get("team_id"), "actor": user},
        )
        return jsonify(updated)

    @app.route("/api/teams/<team_id>/leave", methods=["POST"])
    def api_team_leave(team_id: str) -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        try:
            left = _team_store().leave_team(team_id, user)
        except ValueError as exc:
            if str(exc) == "team_owner_cannot_leave":
                return jsonify({"error": "team_owner_cannot_leave"}), 409
            raise
        if not left:
            return jsonify({"error": "membership_not_found"}), 404
        _record_identity_event(
            user,
            role=_role_for_user(user),
            email=_email_for_user(user),
            provider="teams",
            meta={"source": "api_team_leave", "team_id": team_id},
        )
        return jsonify({"status": "ok", "team_id": team_id})

    @app.route("/api/voice/tokens", methods=["GET", "POST"])
    def api_voice_tokens() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        is_admin = _is_admin_user(user)
        if request.method == "GET":
            target = str(request.args.get("user") or "").strip() or None
            if target and not is_admin:
                return jsonify({"error": "forbidden"}), 403
            if not target and not is_admin:
                target = user
            return jsonify({"tokens": store.voice_tokens.list_tokens(target)})
        payload = request.get_json(force=True, silent=True) or {}
        target = str(payload.get("user") or user).strip()
        if target != user and not is_admin:
            return jsonify({"error": "forbidden"}), 403
        if store.users.has_users() and not _role_for_user(target):
            return jsonify({"error": "user_not_found"}), 404
        label = payload.get("label") if isinstance(payload.get("label"), str) else None
        issued = store.voice_tokens.issue(target, label=label)
        return jsonify(
            {
                "status": "ok",
                "token": issued.get("token"),
                "id": issued.get("id"),
                "user": issued.get("user"),
                "label": issued.get("label"),
                "created_at": issued.get("created_at"),
            }
        ), 201

    @app.route("/api/voice/tokens/<token_id>", methods=["DELETE"])
    def api_voice_token_delete(token_id: str) -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        if not _is_admin_user(user):
            allowed_ids = {item.get("id") for item in store.voice_tokens.list_tokens(user)}
            if token_id not in allowed_ids:
                return jsonify({"error": "forbidden"}), 403
        if not store.voice_tokens.revoke(token_id):
            return jsonify({"error": "not_found"}), 404
        return jsonify({"status": "revoked", "id": token_id})

    @app.route("/api/internal/voice/resolve", methods=["POST"])
    @require_app_token
    def api_internal_voice_resolve() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        token = str(payload.get("token") or "").strip()
        if not token:
            return jsonify({"error": "token_required"}), 400
        user = store.voice_tokens.verify(token)
        if not user:
            return jsonify({"authenticated": False, "user": None}), 404
        return jsonify({"authenticated": True, **_user_identity_payload(user)})

    @app.route("/api/internal/users/<username>", methods=["GET"])
    @require_app_token
    def api_internal_user_lookup(username: str) -> Response:
        cleaned = str(username or "").strip()
        if not cleaned:
            return jsonify({"error": "username_required"}), 400
        user_entry = store.users.get_user(cleaned)
        if _is_service_account_user_entry(user_entry):
            return jsonify({"error": "user_not_found"}), 404
        if not user_entry:
            return jsonify({"error": "user_not_found"}), 404
        return jsonify({"authenticated": True, "user_record": _user_record_payload(user_entry, include_access=True), **_user_identity_payload(cleaned)})

    @app.route("/api/internal/credentials/verify", methods=["POST"])
    @require_app_token
    def api_internal_credentials_verify() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if not username or not password:
            return jsonify({"error": "username_and_password_required"}), 400
        valid = store.users.verify(username, password)
        if not valid:
            return jsonify({"authenticated": False, "user": None, "role": None, "email": None})
        return jsonify({"authenticated": True, **_user_identity_payload(username)})

    return app


def main() -> None:
    logging.basicConfig(
        level=os.getenv("CUSTOMERS_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = create_app()
    settings = app.extensions["nm_settings"]
    app.run(host=settings.host, port=settings.port)
