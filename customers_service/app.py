from __future__ import annotations

import base64
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
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .config import Settings
from .nmchain_client import NmChainClient
from .store import create_central_store_from_env

logger = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LOGIN_MAX_ATTEMPTS = int(os.getenv("CUSTOMERS_LOGIN_MAX_ATTEMPTS") or "6")
LOGIN_WINDOW_SEC = int(os.getenv("CUSTOMERS_LOGIN_WINDOW_SEC") or "600")

_OIDC_CACHE: Dict[str, Any] = {"ts": 0.0, "config": None, "jwks": None}
_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
_LOGIN_ATTEMPTS_LOCK = threading.Lock()


def _settings() -> Settings:
    return current_app.extensions["nm_settings"]


def _store() -> Any:
    return current_app.extensions["nm_store"]


def _nmchain() -> Optional[NmChainClient]:
    return current_app.extensions.get("nmchain")


def _store_backend_name() -> str:
    store = _store()
    return getattr(store, "store_type", "postgres")


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


def require_app_token(view: Callable[..., Response]) -> Callable[..., Response]:
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Response:
        actor = _current_app_actor()
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


def _oidc_discovery() -> Optional[Dict[str, Any]]:
    settings = _settings()
    if not settings.oidc_enabled or not settings.oidc_issuer:
        return None
    now = time.time()
    cached = _OIDC_CACHE.get("config")
    if cached and (now - float(_OIDC_CACHE.get("ts", 0.0)) < settings.oidc_discovery_ttl):
        return cached
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    response = requests.get(url, timeout=12)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("oidc_discovery_invalid_json")
    issuer = str(data.get("issuer") or "").strip()
    if issuer and issuer.rstrip("/") != settings.oidc_issuer.rstrip("/"):
        raise RuntimeError("oidc_issuer_mismatch")
    _OIDC_CACHE["config"] = data
    _OIDC_CACHE["ts"] = now
    return data


def _oidc_jwks() -> Optional[Dict[str, Any]]:
    config = _oidc_discovery()
    if not config:
        return None
    settings = _settings()
    cached = _OIDC_CACHE.get("jwks")
    if cached and (time.time() - float(_OIDC_CACHE.get("ts", 0.0)) < settings.oidc_discovery_ttl):
        return cached
    jwks_uri = config.get("jwks_uri")
    if not jwks_uri:
        return None
    response = requests.get(jwks_uri, timeout=12)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        return None
    _OIDC_CACHE["jwks"] = data
    _OIDC_CACHE["ts"] = time.time()
    return data


def _verify_jwt(token: str, *, nonce: Optional[str]) -> Dict[str, Any]:
    settings = _settings()
    header, payload, signature, signing_input = _parse_jwt(token)
    if not settings.oidc_skip_jwt_verify:
        if header.get("alg") != "RS256":
            raise RuntimeError("unsupported_jwt_algorithm")
        jwks = _oidc_jwks() or {}
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


def _oidc_maybe_enrich_claims(
    claims: Dict[str, Any],
    access_token: Optional[str],
    *,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    settings = _settings()
    if not claims or not access_token:
        return claims
    if not (settings.oidc_use_userinfo or not claims.get(settings.oidc_email_claim)):
        return claims
    config = config or _oidc_discovery()
    userinfo_endpoint = config.get("userinfo_endpoint") if isinstance(config, dict) else None
    if not userinfo_endpoint:
        return claims
    try:
        response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=12,
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


def _role_for_user(user: str) -> Optional[str]:
    return _store().users.get_role(user)


def _email_for_user(user: str) -> Optional[str]:
    return _store().users.get_email(user)


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
    try:
        chain.upsert_identity(
            user,
            role=role,
            email=email,
            provider=provider,
            subject=subject,
            request_id=request_id,
            meta=meta or {},
        )
    except Exception as exc:
        logger.warning("nmchain identity upsert failed for %s: %s", user, exc)


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
    try:
        chain.observe_login(
            user,
            system="customers",
            auth_mode=auth_mode,
            session_id=session_id,
            remote_addr=_client_ip() or None,
            meta=details,
        )
    except Exception as exc:
        logger.warning("nmchain login event failed for %s: %s", user, exc)


def _current_user() -> Optional[str]:
    session_user = session.get("user")
    if isinstance(session_user, str) and session_user.strip():
        return session_user.strip()
    token = _extract_bearer_token(request.headers.get("Authorization") or request.headers.get("authorization"))
    if not token:
        return None
    if _current_app_actor():
        return None
    try:
        identity = _store().access_tokens.verify(token)
    except Exception as exc:
        logger.warning("access token verification failed: %s", exc)
        return None
    if not isinstance(identity, dict):
        return None
    user = identity.get("user")
    if isinstance(user, str) and user.strip():
        return user.strip()
    return None


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


def _login_payload(user: str, *, source: str) -> Dict[str, Any]:
    role = _role_for_user(user)
    return {
        "status": "ok",
        "user": user,
        "role": role,
        "sso_token": _issue_sso_token(user),
        "sso_expires_in": _settings().sso_ttl_seconds,
        **_issue_access_token_payload(user, source=source),
    }


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
        return jsonify(
            {
                "status": "ok",
                "service": settings.service_name,
                "version": settings.version,
                "store": _store_health(),
                "auth_mode": settings.auth_mode,
                "oidc_enabled": settings.oidc_enabled,
                "allow_setup": settings.allow_setup,
                "nmchain_enabled": bool(_nmchain()),
                "app_tokens_configured": sorted(settings.app_tokens.keys()),
            }
        )

    @app.route("/api/version")
    def api_version() -> Response:
        return jsonify({"service": settings.service_name, "version": settings.version})

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
        if request.method == "POST":
            username = str(request.form.get("username") or "").strip()
            password = str(request.form.get("password") or "")
            if _login_throttled(username):
                error = "Too many attempts. Please try again later."
            elif store.users.verify(username, password):
                _record_login_attempt(username, ok=True)
                _finalize_login(
                    username,
                    auth_mode="local",
                    provider="local",
                    source="login_form",
                )
                session.pop("login_next", None)
                return redirect(next_path)
            else:
                _record_login_attempt(username, ok=False)
                error = "Invalid username or password."
        return make_response(
            render_template(
                "login.html",
                error=error,
                api_base=settings.api_base,
                oidc_enabled=settings.oidc_enabled,
                oidc_label=settings.oidc_button_label,
                local_enabled=store.users.has_users(),
                next_path=next_path,
            )
        )

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
            error = str((body or {}).get("details") or (body or {}).get("error") or "Setup failed.")
        return make_response(render_template("setup.html", error=error, api_base=settings.api_base, next_path=next_path))

    @app.route("/logout")
    def logout() -> Response:
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
        token_response = requests.post(token_endpoint, data=token_payload, auth=auth, timeout=15)
        if token_response.status_code >= 400:
            return redirect(url_for("login"))
        token_data = token_response.json()
        id_token = str(token_data.get("id_token") or "")
        access_token = str(token_data.get("access_token") or "")
        if not id_token:
            return redirect(url_for("login"))
        try:
            claims = _verify_jwt(id_token, nonce=session.get("oidc_nonce"))
        except Exception:
            return redirect(url_for("login"))
        claims = _oidc_maybe_enrich_claims(claims, access_token, config=config)
        username = _oidc_username_from_claims(claims)
        if not username:
            return redirect(url_for("login"))
        email = claims.get(settings.oidc_email_claim) if isinstance(claims.get(settings.oidc_email_claim), str) else None
        role = _oidc_role_from_claims(claims)
        subject = claims.get("sub") if isinstance(claims.get("sub"), str) else None
        store.users.upsert_external_user(username, role=role, email=email, provider="oidc", subject=subject)
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
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        confirm = str(payload.get("confirm") or "")
        email = str(payload.get("email") or "").strip()
        if not username or not password:
            return jsonify({"error": "username_and_password_required"}), 400
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
        if len(password) < settings.password_min_length:
            return (
                jsonify(
                    {
                        "error": "password_too_short",
                        "details": f"Password must be at least {settings.password_min_length} characters.",
                    }
                ),
                400,
            )
        if confirm and password != confirm:
            return jsonify({"error": "password_mismatch", "details": "Passwords do not match."}), 400
        if email and not EMAIL_RE.match(email):
            return jsonify({"error": "invalid_email", "details": "Enter a valid email address."}), 400
        store.users.create_user(username, password, role="admin", email=email or None)
        _finalize_login(
            username,
            auth_mode="setup",
            provider="setup",
            source=source,
            role="admin",
            email=email or None,
        )
        return jsonify(_login_payload(username, source=source)), 201

    @app.route("/api/setup", methods=["POST"])
    def api_setup() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        response, status = _handle_setup_payload(payload, source="api_setup")
        return response, status

    @app.route("/api/login", methods=["POST"])
    def api_login() -> Response:
        if not store.users.has_users():
            return jsonify({"error": "setup_required"}), 400
        if settings.auth_mode == "oidc":
            return jsonify({"error": "oidc_required"}), 403
        payload = request.get_json(force=True, silent=True) or {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if not username or not password:
            return jsonify({"error": "username_and_password_required"}), 400
        if _login_throttled(username):
            return jsonify({"error": "too_many_attempts"}), 429
        if not store.users.verify(username, password):
            _record_login_attempt(username, ok=False)
            return jsonify({"error": "invalid_credentials"}), 401
        _record_login_attempt(username, ok=True)
        _finalize_login(username, auth_mode="local", provider="local", source="api_login")
        session.pop("login_next", None)
        return jsonify(_login_payload(username, source="api_login"))

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
        if code:
            if client_id and client_id != settings.oidc_client_id:
                return jsonify({"error": "client_id_mismatch"}), 400
            config = _oidc_discovery() or {}
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
            token_response = requests.post(token_endpoint, data=token_payload, auth=auth, timeout=15)
            if token_response.status_code >= 400:
                return jsonify({"error": "token_exchange_failed"}), 401
            token_data = token_response.json()
            id_token = str(token_data.get("id_token") or "").strip()
            access_token = str(token_data.get("access_token") or "").strip()
        if not id_token:
            return jsonify({"error": "id_token_required"}), 400
        try:
            claims = _verify_jwt(id_token, nonce=None)
        except Exception:
            return jsonify({"error": "invalid_id_token"}), 401
        claims = _oidc_maybe_enrich_claims(claims, access_token, config=_oidc_discovery())
        username = _oidc_username_from_claims(claims)
        if not username:
            return jsonify({"error": "username_missing"}), 400
        email = claims.get(settings.oidc_email_claim) if isinstance(claims.get(settings.oidc_email_claim), str) else None
        role = _oidc_role_from_claims(claims)
        subject = claims.get("sub") if isinstance(claims.get("sub"), str) else None
        store.users.upsert_external_user(username, role=role, email=email, provider="oidc", subject=subject)
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
        return jsonify(
            {
                "status": "ok",
                "token": _issue_sso_token(user),
                "expires_in": settings.sso_ttl_seconds,
                "user": user,
                "role": _role_for_user(user),
            }
        )

    @app.route("/api/logout", methods=["POST"])
    def api_logout() -> Response:
        session.pop("user", None)
        session.pop("login_next", None)
        return jsonify({"status": "ok"})

    @app.route("/api/session")
    def api_session() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"authenticated": False, "user": None}), 200
        return jsonify({"authenticated": True, "user": user, "role": _role_for_user(user)})

    @app.route("/api/authz/nginx")
    def api_authz_nginx() -> Response:
        user = _current_user()
        if not user:
            response = make_response("", 401)
            response.headers["Cache-Control"] = "no-store"
            return response
        response = make_response("", 204)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Auth-Request-User"] = user
        role = _role_for_user(user)
        if role:
            response.headers["X-Auth-Request-Role"] = role
        return response

    @app.route("/api/profile", methods=["GET", "POST"])
    def api_profile() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        if request.method == "GET":
            return jsonify({"user": user, "role": _role_for_user(user), "email": _email_for_user(user)})
        payload = request.get_json(force=True, silent=True) or {}
        email = str(payload.get("email") or "").strip()
        if email and not EMAIL_RE.match(email):
            return jsonify({"error": "invalid_email", "details": "Enter a valid email address."}), 400
        store.users.set_email(user, email or None)
        _record_identity_event(
            user,
            role=_role_for_user(user),
            email=_email_for_user(user),
            provider="profile",
            meta={"source": "api_profile"},
        )
        return jsonify({"status": "ok", "email": _email_for_user(user)})

    @app.route("/api/voice/tokens", methods=["GET", "POST"])
    def api_voice_tokens() -> Response:
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        role = _role_for_user(user) or "user"
        if request.method == "GET":
            target = str(request.args.get("user") or "").strip() or None
            if target and role != "admin":
                return jsonify({"error": "forbidden"}), 403
            if not target and role != "admin":
                target = user
            return jsonify({"tokens": store.voice_tokens.list_tokens(target)})
        payload = request.get_json(force=True, silent=True) or {}
        target = str(payload.get("user") or user).strip()
        if target != user and role != "admin":
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
        role = _role_for_user(user) or "user"
        if role != "admin":
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
        return jsonify({"authenticated": True, "user": user, "role": _role_for_user(user)})

    @app.route("/api/internal/credentials/verify", methods=["POST"])
    @require_app_token
    def api_internal_credentials_verify() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if not username or not password:
            return jsonify({"error": "username_and_password_required"}), 400
        valid = store.users.verify(username, password)
        return jsonify(
            {
                "authenticated": bool(valid),
                "user": username if valid else None,
                "role": _role_for_user(username) if valid else None,
                "email": _email_for_user(username) if valid else None,
            }
        )

    return app


def main() -> None:
    logging.basicConfig(
        level=os.getenv("CUSTOMERS_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = create_app()
    settings = app.extensions["nm_settings"]
    app.run(host=settings.host, port=settings.port)
