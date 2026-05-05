"""Validated profile settings shared with the Refiner public contract.

Customers stores these settings under ``nm_users.metadata`` so proxied
``/api/profile`` and ``/api/session`` responses keep the same schema as the
standalone Refiner deployment. The module intentionally mirrors Refiner's
settings contract because these services are deployed independently.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

SETTINGS_METADATA_KEY = "settings"
SETTINGS_UPDATED_AT_KEY = "settings_updated_at"
SETTINGS_VERSION = 1

ALLOWED_REASONING_EFFORTS = {"none", "low", "medium", "high", "xhigh"}
ALLOWED_ASSISTANT_PROFILES = {"requirements", "marketing"}
ALLOWED_COMMAND_POLICY_MODES = {"standard", "strict"}
ALLOWED_LLM_PROVIDER_ACCESS_MODES = {"service", "user_key"}
ALLOWED_LLM_PROVIDER_ACCESS_PROVIDERS = {"openai", "gemini", "nvidia"}

_DEFAULT_SETTINGS: Dict[str, Any] = {
    "version": SETTINGS_VERSION,
    "llm": {
        "default_provider": None,
        "default_model": None,
        "default_reasoning_effort": "medium",
        "provider_access": {
            "openai": {"mode": "service", "acknowledged": False},
            "gemini": {"mode": "service", "acknowledged": False},
            "nvidia": {"mode": "service", "acknowledged": False},
        },
    },
    "assistant": {
        "default_profile": "requirements",
        "use_memory": True,
    },
    "solver": {
        "command_policy_mode": "standard",
    },
    "ui": {
        "show_solver_replay": True,
    },
}


class SettingsValidationError(ValueError):
    """Raised when an API-facing settings payload fails validation."""

    def __init__(self, issues: List[str]):
        self.issues = [str(issue) for issue in issues if str(issue).strip()]
        super().__init__("; ".join(self.issues) or "invalid settings")


def default_settings() -> Dict[str, Any]:
    return copy.deepcopy(_DEFAULT_SETTINGS)


def _normalize_optional_text(value: Any, *, max_length: int, allowed_chars: str) -> Optional[str]:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned:
        return None
    if len(cleaned) > max_length:
        raise ValueError(f"value exceeds {max_length} characters")
    for ch in cleaned:
        if ch not in allowed_chars:
            raise ValueError(f"unsupported character '{ch}'")
    return cleaned


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    cleaned = str(value).strip().lower()
    if cleaned in {"1", "true", "yes", "on", "y"}:
        return True
    if cleaned in {"0", "false", "no", "off", "n"}:
        return False
    raise ValueError("expected a boolean value")


def _normalize_llm_provider_key(value: Any) -> str:
    cleaned = str(value or "").strip().lower()
    if cleaned in {"gpt", "chatgpt"}:
        return "openai"
    if cleaned == "google":
        return "gemini"
    if cleaned in {"nim", "nvidia_nim"}:
        return "nvidia"
    return cleaned


def _strict_group(value: Any, path: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SettingsValidationError([f"{path} must be an object"])
    return value


def _apply_llm_settings(target: Dict[str, Any], raw: Dict[str, Any], *, issues: List[str], strict: bool) -> None:
    allowed = {"default_provider", "default_model", "default_reasoning_effort", "provider_access"}
    for key, value in raw.items():
        if key not in allowed:
            if strict:
                issues.append(f"llm.{key} is not supported")
            continue
        try:
            if key == "default_provider":
                target["llm"]["default_provider"] = _normalize_optional_text(
                    value,
                    max_length=64,
                    allowed_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-",
                )
            elif key == "default_model":
                target["llm"]["default_model"] = _normalize_optional_text(
                    value,
                    max_length=128,
                    allowed_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-/+",
                )
            elif key == "provider_access":
                if not isinstance(value, dict):
                    raise ValueError("expected an object")
                for provider_key, provider_value in value.items():
                    normalized_provider = _normalize_llm_provider_key(provider_key)
                    if normalized_provider not in ALLOWED_LLM_PROVIDER_ACCESS_PROVIDERS:
                        raise ValueError(
                            "provider must be one of "
                            f"{sorted(ALLOWED_LLM_PROVIDER_ACCESS_PROVIDERS)}"
                        )
                    if not isinstance(provider_value, dict):
                        raise ValueError(f"{normalized_provider} must be an object")
                    supported_provider_fields = {"mode", "acknowledged"}
                    for provider_field, provider_field_value in provider_value.items():
                        if provider_field not in supported_provider_fields:
                            raise ValueError(
                                f"{normalized_provider}.{provider_field} is not supported"
                            )
                        if provider_field == "mode":
                            cleaned_mode = str(provider_field_value or "").strip().lower()
                            if cleaned_mode not in ALLOWED_LLM_PROVIDER_ACCESS_MODES:
                                raise ValueError(
                                    f"{normalized_provider}.mode expected one of "
                                    f"{sorted(ALLOWED_LLM_PROVIDER_ACCESS_MODES)}"
                                )
                            target["llm"]["provider_access"][normalized_provider]["mode"] = cleaned_mode
                        else:
                            target["llm"]["provider_access"][normalized_provider]["acknowledged"] = _normalize_bool(
                                provider_field_value
                            )
            else:
                cleaned = str(value).strip().lower() if value is not None else ""
                if cleaned not in ALLOWED_REASONING_EFFORTS:
                    raise ValueError(f"expected one of {sorted(ALLOWED_REASONING_EFFORTS)}")
                target["llm"]["default_reasoning_effort"] = cleaned
        except Exception as exc:
            if strict:
                issues.append(f"llm.{key}: {exc}")


def _apply_assistant_settings(target: Dict[str, Any], raw: Dict[str, Any], *, issues: List[str], strict: bool) -> None:
    allowed = {"default_profile", "use_memory"}
    for key, value in raw.items():
        if key not in allowed:
            if strict:
                issues.append(f"assistant.{key} is not supported")
            continue
        try:
            if key == "default_profile":
                cleaned = str(value).strip().lower() if value is not None else ""
                if cleaned not in ALLOWED_ASSISTANT_PROFILES:
                    raise ValueError(f"expected one of {sorted(ALLOWED_ASSISTANT_PROFILES)}")
                target["assistant"]["default_profile"] = cleaned
            else:
                target["assistant"]["use_memory"] = _normalize_bool(value)
        except Exception as exc:
            if strict:
                issues.append(f"assistant.{key}: {exc}")


def _apply_solver_settings(target: Dict[str, Any], raw: Dict[str, Any], *, issues: List[str], strict: bool) -> None:
    allowed = {"command_policy_mode"}
    for key, value in raw.items():
        if key not in allowed:
            if strict:
                issues.append(f"solver.{key} is not supported")
            continue
        try:
            cleaned = str(value).strip().lower() if value is not None else ""
            if cleaned not in ALLOWED_COMMAND_POLICY_MODES:
                raise ValueError(f"expected one of {sorted(ALLOWED_COMMAND_POLICY_MODES)}")
            target["solver"]["command_policy_mode"] = cleaned
        except Exception as exc:
            if strict:
                issues.append(f"solver.{key}: {exc}")


def _apply_ui_settings(target: Dict[str, Any], raw: Dict[str, Any], *, issues: List[str], strict: bool) -> None:
    allowed = {"show_solver_replay"}
    for key, value in raw.items():
        if key not in allowed:
            if strict:
                issues.append(f"ui.{key} is not supported")
            continue
        try:
            target["ui"]["show_solver_replay"] = _normalize_bool(value)
        except Exception as exc:
            if strict:
                issues.append(f"ui.{key}: {exc}")


def _apply_settings(raw: Any, *, current: Optional[Dict[str, Any]] = None, strict: bool) -> Dict[str, Any]:
    base = default_settings()
    if isinstance(current, dict):
        base = _apply_settings(current, current=None, strict=False)

    payload = raw if isinstance(raw, dict) else {}
    issues: List[str] = []
    allowed_groups = {"llm", "assistant", "solver", "ui", "version"}

    for key, value in payload.items():
        if key not in allowed_groups:
            if strict:
                issues.append(f"{key} is not a supported settings group")
            continue
        if key == "version":
            continue
        try:
            group = _strict_group(value, key)
        except SettingsValidationError as exc:
            if strict:
                issues.extend(exc.issues)
            continue
        if key == "llm":
            _apply_llm_settings(base, group, issues=issues, strict=strict)
        elif key == "assistant":
            _apply_assistant_settings(base, group, issues=issues, strict=strict)
        elif key == "solver":
            _apply_solver_settings(base, group, issues=issues, strict=strict)
        elif key == "ui":
            _apply_ui_settings(base, group, issues=issues, strict=strict)

    base["version"] = SETTINGS_VERSION
    if strict and issues:
        raise SettingsValidationError(issues)
    return base


def normalize_stored_settings(raw: Any) -> Dict[str, Any]:
    return _apply_settings(raw, strict=False)


def validate_settings_patch(raw: Any, *, current: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if raw is None:
        return normalize_stored_settings(current)
    if not isinstance(raw, dict):
        raise SettingsValidationError(["settings must be an object"])
    return _apply_settings(raw, current=current, strict=True)


def settings_from_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    payload = metadata if isinstance(metadata, dict) else {}
    return normalize_stored_settings(payload.get(SETTINGS_METADATA_KEY))


def metadata_with_settings(
    metadata: Optional[Dict[str, Any]],
    settings: Dict[str, Any],
    *,
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    merged = dict(metadata or {})
    merged[SETTINGS_METADATA_KEY] = normalize_stored_settings(settings)
    if updated_at:
        merged[SETTINGS_UPDATED_AT_KEY] = str(updated_at)
    return merged


def llm_provider_access_from_settings(settings: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    normalized = normalize_stored_settings(settings)
    llm_cfg = normalized.get("llm") if isinstance(normalized.get("llm"), dict) else {}
    raw_access = llm_cfg.get("provider_access") if isinstance(llm_cfg.get("provider_access"), dict) else {}
    access: Dict[str, Dict[str, Any]] = {}
    for provider in sorted(ALLOWED_LLM_PROVIDER_ACCESS_PROVIDERS):
        entry = raw_access.get(provider) if isinstance(raw_access.get(provider), dict) else {}
        mode = str(entry.get("mode") or "service").strip().lower()
        if mode not in ALLOWED_LLM_PROVIDER_ACCESS_MODES:
            mode = "service"
        access[provider] = {
            "mode": mode,
            "acknowledged": bool(entry.get("acknowledged", False)),
        }
    return access
