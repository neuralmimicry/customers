from __future__ import annotations

import base64
import hashlib
import json
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

SECURITY_METADATA_KEY = "security"


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def b64url_decode(value: str) -> bytes:
    cleaned = str(value or "").strip()
    if not cleaned:
        return b""
    padding = "=" * (-len(cleaned) % 4)
    return base64.urlsafe_b64decode(cleaned + padding)


def _fernet(secret_key: str) -> Fernet:
    digest = hashlib.sha256((secret_key or "").encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _clean_string(value: Any) -> Optional[str]:
    cleaned = str(value or "").strip()
    return cleaned or None


def _clean_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _clean_string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    cleaned: List[str] = []
    seen = set()
    for item in value:
        entry = str(item or "").strip()
        if not entry or entry in seen:
            continue
        seen.add(entry)
        cleaned.append(entry)
    return cleaned


def _credential_device_type(value: Any) -> Optional[str]:
    if value is None:
        return None
    if hasattr(value, "value"):
        return str(getattr(value, "value") or "").strip() or None
    return _clean_string(value)


def security_state_from_metadata(metadata: Optional[Mapping[str, Any]], *, secret_key: str) -> Dict[str, Any]:
    """Return a normalised internal security state for a user metadata record."""
    source = dict(metadata or {})
    raw_security = source.get(SECURITY_METADATA_KEY)
    raw_security = dict(raw_security) if isinstance(raw_security, Mapping) else {}

    raw_totp = raw_security.get("totp")
    raw_totp = dict(raw_totp) if isinstance(raw_totp, Mapping) else {}
    encrypted_secret = _clean_string(raw_totp.get("secret"))
    secret = None
    if encrypted_secret:
        try:
            secret = _fernet(secret_key).decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError, TypeError):
            secret = None
    totp_enabled = _clean_bool(raw_totp.get("enabled")) and bool(secret)

    raw_passkeys = raw_security.get("passkeys")
    raw_passkeys = dict(raw_passkeys) if isinstance(raw_passkeys, Mapping) else {}
    passkeys: List[Dict[str, Any]] = []
    for item in raw_passkeys.get("credentials") if isinstance(raw_passkeys.get("credentials"), list) else []:
        record = dict(item) if isinstance(item, Mapping) else {}
        credential_id = _clean_string(record.get("credential_id") or record.get("id"))
        public_key = _clean_string(record.get("public_key"))
        if not credential_id or not public_key:
            continue
        passkeys.append(
            {
                "credential_id": credential_id,
                "public_key": public_key,
                "label": _clean_string(record.get("label")),
                "sign_count": int(record.get("sign_count") or 0),
                "created_at": _clean_string(record.get("created_at")),
                "last_used_at": _clean_string(record.get("last_used_at")),
                "aaguid": _clean_string(record.get("aaguid")),
                "attestation_format": _clean_string(record.get("attestation_format")),
                "credential_type": _clean_string(record.get("credential_type")),
                "authenticator_attachment": _clean_string(record.get("authenticator_attachment")),
                "credential_device_type": _clean_string(record.get("credential_device_type")),
                "credential_backed_up": _clean_bool(record.get("credential_backed_up")),
                "user_verified": _clean_bool(record.get("user_verified")),
                "transports": _clean_string_list(record.get("transports")),
            }
        )
    passkeys.sort(key=lambda item: (str(item.get("created_at") or ""), str(item.get("credential_id") or "")))

    return {
        "totp": {
            "enabled": totp_enabled,
            "secret": secret,
            "enabled_at": _clean_string(raw_totp.get("enabled_at")),
            "last_verified_at": _clean_string(raw_totp.get("last_verified_at")),
        },
        "passkeys": {
            "user_id": _clean_string(raw_passkeys.get("user_id")),
            "credentials": passkeys,
        },
    }


def metadata_with_security_state(
    metadata: Optional[Mapping[str, Any]],
    security_state: Mapping[str, Any],
    *,
    secret_key: str,
) -> Dict[str, Any]:
    """Persist a normalised security state back into user metadata."""
    updated = dict(metadata or {})
    state = dict(security_state or {})

    raw_totp = state.get("totp")
    raw_totp = dict(raw_totp) if isinstance(raw_totp, Mapping) else {}
    secret = _clean_string(raw_totp.get("secret"))
    totp_payload = {
        "enabled": _clean_bool(raw_totp.get("enabled")) and bool(secret),
        "enabled_at": _clean_string(raw_totp.get("enabled_at")),
        "last_verified_at": _clean_string(raw_totp.get("last_verified_at")),
    }
    if secret:
        totp_payload["secret"] = _fernet(secret_key).encrypt(secret.encode("utf-8")).decode("utf-8")
    else:
        totp_payload["secret"] = None

    raw_passkeys = state.get("passkeys")
    raw_passkeys = dict(raw_passkeys) if isinstance(raw_passkeys, Mapping) else {}
    credential_payloads: List[Dict[str, Any]] = []
    for item in raw_passkeys.get("credentials") if isinstance(raw_passkeys.get("credentials"), list) else []:
        record = dict(item) if isinstance(item, Mapping) else {}
        credential_id = _clean_string(record.get("credential_id"))
        public_key = _clean_string(record.get("public_key"))
        if not credential_id or not public_key:
            continue
        credential_payloads.append(
            {
                "credential_id": credential_id,
                "public_key": public_key,
                "label": _clean_string(record.get("label")),
                "sign_count": int(record.get("sign_count") or 0),
                "created_at": _clean_string(record.get("created_at")),
                "last_used_at": _clean_string(record.get("last_used_at")),
                "aaguid": _clean_string(record.get("aaguid")),
                "attestation_format": _clean_string(record.get("attestation_format")),
                "credential_type": _clean_string(record.get("credential_type")),
                "authenticator_attachment": _clean_string(record.get("authenticator_attachment")),
                "credential_device_type": _clean_string(record.get("credential_device_type")),
                "credential_backed_up": _clean_bool(record.get("credential_backed_up")),
                "user_verified": _clean_bool(record.get("user_verified")),
                "transports": _clean_string_list(record.get("transports")),
            }
        )
    credential_payloads.sort(key=lambda item: (str(item.get("created_at") or ""), str(item.get("credential_id") or "")))

    updated[SECURITY_METADATA_KEY] = {
        "totp": totp_payload,
        "passkeys": {
            "user_id": _clean_string(raw_passkeys.get("user_id")),
            "credentials": credential_payloads,
        },
    }
    return updated


def security_summary(
    security_state: Mapping[str, Any],
    *,
    totp_supported: bool,
    passkeys_supported: bool,
    include_passkeys: bool,
) -> Dict[str, Any]:
    """Return a client-safe security summary."""
    state = dict(security_state or {})
    raw_totp = state.get("totp")
    raw_totp = dict(raw_totp) if isinstance(raw_totp, Mapping) else {}
    raw_passkeys = state.get("passkeys")
    raw_passkeys = dict(raw_passkeys) if isinstance(raw_passkeys, Mapping) else {}
    credentials = raw_passkeys.get("credentials") if isinstance(raw_passkeys.get("credentials"), list) else []
    summary = {
        "totp_supported": bool(totp_supported),
        "totp_enabled": bool(raw_totp.get("enabled")),
        "passkeys_supported": bool(passkeys_supported),
        "passkey_count": len(credentials),
    }
    if include_passkeys:
        summary["passkeys"] = [
            {
                "credential_id": _clean_string(item.get("credential_id")),
                "label": _clean_string(item.get("label")),
                "created_at": _clean_string(item.get("created_at")),
                "last_used_at": _clean_string(item.get("last_used_at")),
                "credential_device_type": _clean_string(item.get("credential_device_type")),
                "credential_backed_up": _clean_bool(item.get("credential_backed_up")),
                "transports": _clean_string_list(item.get("transports")),
            }
            for item in credentials
            if isinstance(item, Mapping) and _clean_string(item.get("credential_id"))
        ]
    return summary


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_totp_enrolment(secret: str, *, issuer: str, account_name: str) -> Dict[str, str]:
    cleaned_secret = str(secret or "").strip()
    if not cleaned_secret:
        raise ValueError("totp_secret_required")
    totp = pyotp.TOTP(cleaned_secret)
    return {
        "secret": cleaned_secret,
        "issuer": str(issuer or "").strip() or "NeuralMimicry",
        "account_name": str(account_name or "").strip(),
        "provisioning_uri": totp.provisioning_uri(
            name=str(account_name or "").strip(),
            issuer_name=str(issuer or "").strip() or "NeuralMimicry",
        ),
    }


def verify_totp_code(secret: str, code: Any) -> bool:
    cleaned_secret = str(secret or "").strip()
    cleaned_code = str(code or "").replace(" ", "").strip()
    if not cleaned_secret or not cleaned_code:
        return False
    return bool(pyotp.TOTP(cleaned_secret).verify(cleaned_code, valid_window=1))


def ensure_passkey_user_id(security_state: Mapping[str, Any]) -> Tuple[Dict[str, Any], str]:
    state = dict(security_state or {})
    passkeys = state.get("passkeys")
    passkeys = dict(passkeys) if isinstance(passkeys, Mapping) else {}
    user_id = _clean_string(passkeys.get("user_id"))
    if not user_id:
        user_id = b64url_encode(uuid.uuid4().bytes)
    passkeys["user_id"] = user_id
    state["passkeys"] = passkeys
    return state, user_id


def passkey_registration_options(
    *,
    rp_id: str,
    rp_name: str,
    username: str,
    user_id: str,
    exclude_credentials: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build WebAuthn registration options ready for JSON transport."""
    descriptors = [
        PublicKeyCredentialDescriptor(id=b64url_decode(str(item.get("credential_id") or "")))
        for item in exclude_credentials
        if str(item.get("credential_id") or "").strip()
    ]
    options = generate_registration_options(
        rp_id=str(rp_id or "").strip(),
        rp_name=str(rp_name or "").strip() or "NeuralMimicry",
        user_name=str(username or "").strip(),
        user_id=b64url_decode(user_id),
        user_display_name=str(username or "").strip(),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            require_resident_key=False,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=descriptors,
    )
    return json.loads(options_to_json(options))


def verify_passkey_registration(
    *,
    credential: Mapping[str, Any],
    expected_challenge: str,
    expected_rp_id: str,
    expected_origins: Sequence[str],
    label: Optional[str],
    now_iso: str,
) -> Dict[str, Any]:
    verified = verify_registration_response(
        credential=dict(credential or {}),
        expected_challenge=b64url_decode(expected_challenge),
        expected_rp_id=str(expected_rp_id or "").strip(),
        expected_origin=list(expected_origins),
        require_user_presence=True,
        require_user_verification=True,
    )
    transports = _clean_string_list((credential or {}).get("transports"))
    return {
        "credential_id": b64url_encode(verified.credential_id),
        "public_key": b64url_encode(verified.credential_public_key),
        "label": _clean_string(label) or "Passkey",
        "sign_count": int(verified.sign_count or 0),
        "created_at": _clean_string(now_iso),
        "last_used_at": None,
        "aaguid": _clean_string(getattr(verified, "aaguid", None)),
        "attestation_format": _credential_device_type(getattr(verified, "fmt", None)),
        "credential_type": _credential_device_type(getattr(verified, "credential_type", None)),
        "authenticator_attachment": _clean_string((credential or {}).get("authenticatorAttachment")),
        "credential_device_type": _credential_device_type(getattr(verified, "credential_device_type", None)),
        "credential_backed_up": bool(getattr(verified, "credential_backed_up", False)),
        "user_verified": bool(getattr(verified, "user_verified", False)),
        "transports": transports,
    }


def passkey_authentication_options(
    *,
    rp_id: str,
    allow_credentials: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build WebAuthn authentication options ready for JSON transport."""
    descriptors = [
        PublicKeyCredentialDescriptor(id=b64url_decode(str(item.get("credential_id") or "")))
        for item in allow_credentials
        if str(item.get("credential_id") or "").strip()
    ]
    options = generate_authentication_options(
        rp_id=str(rp_id or "").strip(),
        allow_credentials=descriptors,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options))


def verify_passkey_authentication(
    *,
    credential: Mapping[str, Any],
    expected_challenge: str,
    expected_rp_id: str,
    expected_origins: Sequence[str],
    stored_credential: Mapping[str, Any],
    now_iso: str,
) -> Dict[str, Any]:
    verified = verify_authentication_response(
        credential=dict(credential or {}),
        expected_challenge=b64url_decode(expected_challenge),
        expected_rp_id=str(expected_rp_id or "").strip(),
        expected_origin=list(expected_origins),
        credential_public_key=b64url_decode(str(stored_credential.get("public_key") or "")),
        credential_current_sign_count=int(stored_credential.get("sign_count") or 0),
        require_user_verification=True,
    )
    updated = dict(stored_credential or {})
    updated["sign_count"] = int(getattr(verified, "new_sign_count", 0) or 0)
    updated["last_used_at"] = _clean_string(now_iso)
    updated["credential_device_type"] = _credential_device_type(getattr(verified, "credential_device_type", None))
    updated["credential_backed_up"] = bool(getattr(verified, "credential_backed_up", False))
    updated["user_verified"] = bool(getattr(verified, "user_verified", False))
    return updated


def find_passkey(
    credentials: Sequence[Mapping[str, Any]],
    credential_id: Any,
) -> Tuple[int, Optional[Dict[str, Any]]]:
    cleaned = str(credential_id or "").strip()
    if not cleaned:
        return -1, None
    for index, item in enumerate(credentials):
        record = dict(item) if isinstance(item, Mapping) else {}
        if str(record.get("credential_id") or "").strip() == cleaned:
            return index, record
    return -1, None
