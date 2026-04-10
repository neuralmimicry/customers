"""Thin HTTP client for the private nmchain service."""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)


class NmChainError(RuntimeError):
    """Raised when the nmchain service cannot satisfy a request."""


class NmChainClient:
    def __init__(
        self,
        base_url: str,
        *,
        app_id: str = "customers",
        api_token: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.app_id = app_id.strip() or "refiner"
        self.api_token = (api_token or "").strip() or None
        self.timeout = max(1.0, float(timeout))
        self._session = requests.Session()

    @classmethod
    def from_env(cls) -> Optional["NmChainClient"]:
        base_url = _env_first("CUSTOMERS_CHAIN_API_BASE", "NMCHAIN_API_BASE")
        if not base_url:
            return None
        timeout_raw = _env_first("CUSTOMERS_CHAIN_TIMEOUT", "NMCHAIN_TIMEOUT", default="10")
        try:
            timeout = float(timeout_raw)
        except Exception:
            timeout = 10.0
        return cls(
            base_url,
            app_id=_env_first("CUSTOMERS_CHAIN_APP_ID", "NMCHAIN_APP_ID", default="customers"),
            api_token=_env_first("CUSTOMERS_CHAIN_API_TOKEN", "NMCHAIN_API_TOKEN"),
            timeout=timeout,
        )

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health", require_auth=False)

    def upsert_identity(
        self,
        user_id: str,
        *,
        role: Optional[str] = None,
        email: Optional[str] = None,
        provider: Optional[str] = None,
        subject: Optional[str] = None,
        request_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/events/identity",
            json_body={
                "request_id": request_id,
                "user_id": user_id,
                "role": role,
                "email": email,
                "provider": provider,
                "subject": subject,
                "meta": meta or {},
            },
        )

    def observe_login(
        self,
        user_id: str,
        *,
        system: str,
        auth_mode: Optional[str] = None,
        session_id: Optional[str] = None,
        remote_addr: Optional[str] = None,
        request_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/events/login",
            json_body={
                "request_id": request_id,
                "user_id": user_id,
                "system": system,
                "auth_mode": auth_mode,
                "session_id": session_id,
                "remote_addr": remote_addr,
                "meta": meta or {},
            },
        )

    def capture_payment(
        self,
        user_id: str,
        *,
        tokens: int,
        amount_minor: Optional[int] = None,
        currency: Optional[str] = None,
        provider: Optional[str] = None,
        payment_id: Optional[str] = None,
        checkout_flow: Optional[str] = None,
        request_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/events/payment",
            json_body={
                "request_id": request_id,
                "user_id": user_id,
                "tokens": int(tokens),
                "amount_minor": amount_minor,
                "currency": currency,
                "provider": provider,
                "payment_id": payment_id,
                "checkout_flow": checkout_flow,
                "meta": meta or {},
            },
        )

    def apply_token(
        self,
        scope: str,
        account_id: str,
        *,
        entry_type: str,
        delta: int,
        request_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/events/token",
            json_body={
                "request_id": request_id,
                "account_scope": scope,
                "account_id": account_id,
                "entry_type": entry_type,
                "delta": int(delta),
                "meta": meta or {},
            },
        )

    def account_snapshot(self, scope: str, account_id: str) -> Dict[str, Any]:
        return self._request(
            "GET",
            f"/api/accounts/{quote(scope.strip())}/{quote(account_id.strip())}",
        )

    def ledger_entries(self, scope: str, account_id: str, *, limit: int = 50) -> Dict[str, Any]:
        limit_val = max(1, min(int(limit), 500))
        return self._request(
            "GET",
            f"/api/accounts/{quote(scope.strip())}/{quote(account_id.strip())}/ledger",
            params={"limit": limit_val},
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        require_auth: bool = True,
    ) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_token and require_auth:
            headers["Authorization"] = f"Bearer {self.api_token}"

        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        try:
            response = self._session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=json_body,
                params=params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise NmChainError(f"nmchain request failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError:
            payload = {"error": response.text or "invalid_json_response"}

        if not response.ok:
            message = None
            if isinstance(payload, dict):
                message = payload.get("error") or payload.get("message")
            raise NmChainError(str(message or f"nmchain returned {response.status_code}"))

        if not isinstance(payload, dict):
            raise NmChainError("nmchain response was not a JSON object")
        return payload


def _env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        value = value.strip()
        if value:
            return value
    return default
