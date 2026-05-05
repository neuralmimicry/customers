"""Shared authorization contract for groups, services, and delegated access.

The Customers service remains the source of truth for identity. This module
adds a small, explicit authorization model on top:

- built-in groups (`user`, `admin`)
- a service catalog with public visibility metadata
- group-scoped grants with bounded delegation through parent groups

Consumers receive pre-resolved access in session/profile payloads so they do
not need to replicate hierarchy logic.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

GROUP_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
SERVICE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")

GROUP_MEMBERSHIP_ROLE_MEMBER = "member"
GROUP_MEMBERSHIP_ROLE_MANAGER = "manager"
GROUP_MEMBERSHIP_ROLES = frozenset(
    {
        GROUP_MEMBERSHIP_ROLE_MEMBER,
        GROUP_MEMBERSHIP_ROLE_MANAGER,
    }
)

SERVICE_ACCESS_NONE = "none"
SERVICE_ACCESS_REQUEST = "request"
SERVICE_ACCESS_OBSERVE = "observe"
SERVICE_ACCESS_USE = "use"
SERVICE_ACCESS_CONTROL = "control"

SERVICE_ACCESS_LEVELS = (
    SERVICE_ACCESS_NONE,
    SERVICE_ACCESS_REQUEST,
    SERVICE_ACCESS_OBSERVE,
    SERVICE_ACCESS_USE,
    SERVICE_ACCESS_CONTROL,
)
SERVICE_ACCESS_ORDER = {
    SERVICE_ACCESS_NONE: 0,
    SERVICE_ACCESS_REQUEST: 1,
    SERVICE_ACCESS_OBSERVE: 2,
    SERVICE_ACCESS_USE: 3,
    SERVICE_ACCESS_CONTROL: 4,
}

DEFAULT_GROUPS: Sequence[Dict[str, Any]] = (
    {
        "key": "user",
        "name": "User",
        "parent_key": None,
        "system": True,
        "metadata": {"kind": "builtin"},
    },
    {
        "key": "admin",
        "name": "Admin",
        "parent_key": None,
        "system": True,
        "metadata": {"kind": "builtin"},
    },
)

DEFAULT_SERVICE_CATALOG: Sequence[Dict[str, Any]] = (
    {
        "service_key": "refiner",
        "display_name": "Refiner",
        "description": "Research, planning, and delivery workflows.",
        "public_access_level": SERVICE_ACCESS_REQUEST,
        "dashboard_url": "/",
        "marketing_url": "/refiner",
        "metadata": {"category": "product"},
    },
    {
        "service_key": "billing",
        "display_name": "Billing",
        "description": "Token balances, settlement, and billing dashboards.",
        "public_access_level": SERVICE_ACCESS_NONE,
        "dashboard_url": "/billing",
        "marketing_url": "/tokens",
        "metadata": {"category": "commercial"},
    },
    {
        "service_key": "continuum",
        "display_name": "Continuum",
        "description": "Hybrid control plane dashboards and operational APIs.",
        "public_access_level": SERVICE_ACCESS_OBSERVE,
        "dashboard_url": "https://api.neuralmimicry.ai/services/health/monitoring",
        "marketing_url": "/continuum",
        "metadata": {"category": "platform"},
    },
    {
        "service_key": "tracey",
        "display_name": "Tracey",
        "description": "Resilience and fleet telemetry surfaces.",
        "public_access_level": SERVICE_ACCESS_OBSERVE,
        "dashboard_url": "https://api.neuralmimicry.ai/services/health/monitoring#tracey-network",
        "marketing_url": "/tracey",
        "metadata": {"category": "platform"},
    },
    {
        "service_key": "aarnn",
        "display_name": "AARNN",
        "description": "Neuromorphic runtime and control surfaces.",
        "public_access_level": SERVICE_ACCESS_REQUEST,
        "dashboard_url": "https://aarnn.neuralmimicry.ai",
        "marketing_url": "/aarnn-neuroscience",
        "metadata": {"category": "product"},
    },
    {
        "service_key": "webots",
        "display_name": "Webots",
        "description": "Embodied AARNN browser worlds.",
        "public_access_level": SERVICE_ACCESS_REQUEST,
        "dashboard_url": "/webots",
        "marketing_url": "/webots",
        "metadata": {"category": "product"},
    },
    {
        "service_key": "gail",
        "display_name": "Gail",
        "description": "Shared model middleware service.",
        "public_access_level": SERVICE_ACCESS_NONE,
        "dashboard_url": "https://gail.neuralmimicry.ai",
        "marketing_url": "/about",
        "metadata": {"category": "internal"},
    },
    {
        "service_key": "gail_trading",
        "display_name": "Gail Trading",
        "description": "Gail-managed trading bridge status and controls.",
        "public_access_level": SERVICE_ACCESS_NONE,
        "dashboard_url": "https://api.neuralmimicry.ai/services/health/monitoring#gail-trading",
        "marketing_url": "/gail",
        "metadata": {"category": "platform"},
    },
    {
        "service_key": "nmstt",
        "display_name": "nmstt",
        "description": "Speech-to-text runtime service.",
        "public_access_level": SERVICE_ACCESS_NONE,
        "dashboard_url": None,
        "marketing_url": "/about",
        "metadata": {"category": "internal"},
    },
    {
        "service_key": "conductor",
        "display_name": "Conductor",
        "description": "Estate planning and control dashboard.",
        "public_access_level": SERVICE_ACCESS_NONE,
        "dashboard_url": "https://conductor.neuralmimicry.ai",
        "marketing_url": "/about",
        "metadata": {"category": "internal"},
    },
    {
        "service_key": "customers",
        "display_name": "Customers",
        "description": "Identity, group, and session control service.",
        "public_access_level": SERVICE_ACCESS_NONE,
        "dashboard_url": "/login",
        "marketing_url": "/login",
        "metadata": {"category": "internal"},
    },
    {
        "service_key": "nmchain",
        "display_name": "nmchain",
        "description": "Ledger and audit service.",
        "public_access_level": SERVICE_ACCESS_NONE,
        "dashboard_url": None,
        "marketing_url": "/about",
        "metadata": {"category": "internal"},
    },
)

DEFAULT_GROUP_SERVICE_GRANTS: Sequence[Dict[str, Any]] = (
    {
        "group_key": "user",
        "service_key": "refiner",
        "access_level": SERVICE_ACCESS_USE,
    },
    {
        "group_key": "user",
        "service_key": "billing",
        "access_level": SERVICE_ACCESS_USE,
    },
    {
        "group_key": "user",
        "service_key": "aarnn",
        "access_level": SERVICE_ACCESS_REQUEST,
    },
    {
        "group_key": "user",
        "service_key": "webots",
        "access_level": SERVICE_ACCESS_REQUEST,
    },
)


def normalize_group_key(value: Any) -> str:
    cleaned = str(value or "").strip().lower()
    if not GROUP_KEY_RE.match(cleaned):
        raise ValueError("invalid_group_key")
    return cleaned


def normalize_service_key(value: Any) -> str:
    cleaned = str(value or "").strip().lower()
    if not SERVICE_KEY_RE.match(cleaned):
        raise ValueError("invalid_service_key")
    return cleaned


def normalize_group_membership_role(value: Any) -> str:
    cleaned = str(value or GROUP_MEMBERSHIP_ROLE_MEMBER).strip().lower() or GROUP_MEMBERSHIP_ROLE_MEMBER
    if cleaned not in GROUP_MEMBERSHIP_ROLES:
        raise ValueError("invalid_group_membership_role")
    return cleaned


def normalize_service_access_level(value: Any, *, default: str = SERVICE_ACCESS_NONE) -> str:
    cleaned = str(value or default).strip().lower() or default
    if cleaned not in SERVICE_ACCESS_ORDER:
        raise ValueError("invalid_service_access_level")
    return cleaned


def service_access_at_least(current: Any, required: Any) -> bool:
    try:
        current_level = normalize_service_access_level(current)
        required_level = normalize_service_access_level(required)
    except ValueError:
        return False
    return SERVICE_ACCESS_ORDER[current_level] >= SERVICE_ACCESS_ORDER[required_level]


def max_service_access_level(*values: Any) -> str:
    best = SERVICE_ACCESS_NONE
    for value in values:
        if value in (None, ""):
            continue
        try:
            candidate = normalize_service_access_level(value)
        except ValueError:
            continue
        if SERVICE_ACCESS_ORDER[candidate] > SERVICE_ACCESS_ORDER[best]:
            best = candidate
    return best


def min_service_access_level(left: Any, right: Any) -> str:
    try:
        normalized_left = normalize_service_access_level(left)
        normalized_right = normalize_service_access_level(right)
    except ValueError:
        return SERVICE_ACCESS_NONE
    if SERVICE_ACCESS_ORDER[normalized_left] <= SERVICE_ACCESS_ORDER[normalized_right]:
        return normalized_left
    return normalized_right


def service_access_flags(access_level: Any, public_access_level: Any = SERVICE_ACCESS_NONE) -> Dict[str, bool]:
    granted = normalize_service_access_level(access_level)
    public_level = normalize_service_access_level(public_access_level)
    visible_level = max_service_access_level(granted, public_level)
    return {
        "can_request": service_access_at_least(visible_level, SERVICE_ACCESS_REQUEST),
        "can_observe": service_access_at_least(visible_level, SERVICE_ACCESS_OBSERVE),
        "can_use": service_access_at_least(granted, SERVICE_ACCESS_USE),
        "can_control": service_access_at_least(granted, SERVICE_ACCESS_CONTROL),
        "visible": visible_level != SERVICE_ACCESS_NONE,
    }


def default_admin_group_grants(
    services: Optional[Sequence[Mapping[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    catalog = services or DEFAULT_SERVICE_CATALOG
    grants: List[Dict[str, Any]] = []
    for service in catalog:
        service_key = str(service.get("service_key") or "").strip().lower()
        if not service_key:
            continue
        grants.append(
            {
                "group_key": "admin",
                "service_key": service_key,
                "access_level": SERVICE_ACCESS_CONTROL,
            }
        )
    return grants


def _coerce_mapping(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _coerce_list(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _load_json_env(*names: str) -> Any:
    for name in names:
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            continue
        try:
            return json.loads(raw)
        except Exception:
            return None
    return None


def _merge_records(
    defaults: Sequence[Mapping[str, Any]],
    overrides: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for source in (defaults, overrides):
        for raw in source:
            record = dict(raw)
            key = tuple(str(record.get(field) or "").strip().lower() for field in key_fields)
            if not all(key):
                continue
            current = merged.get(key, {})
            merged[key] = {**current, **record}
    return list(merged.values())


def bootstrap_authorization_contract() -> Dict[str, List[Dict[str, Any]]]:
    groups = _merge_records(
        DEFAULT_GROUPS,
        _coerce_list(
            _load_json_env("CUSTOMERS_BOOTSTRAP_GROUPS", "CUSTOMERS_GROUPS_JSON")
        ),
        key_fields=("key",),
    )
    services = _merge_records(
        DEFAULT_SERVICE_CATALOG,
        _coerce_list(
            _load_json_env(
                "CUSTOMERS_BOOTSTRAP_SERVICE_CATALOG",
                "CUSTOMERS_SERVICE_CATALOG_JSON",
            )
        ),
        key_fields=("service_key",),
    )
    grants = _merge_records(
        tuple(DEFAULT_GROUP_SERVICE_GRANTS) + tuple(default_admin_group_grants(services)),
        _coerce_list(
            _load_json_env(
                "CUSTOMERS_BOOTSTRAP_GROUP_SERVICE_GRANTS",
                "CUSTOMERS_GROUP_SERVICE_GRANTS_JSON",
            )
        ),
        key_fields=("group_key", "service_key"),
    )
    return {
        "groups": groups,
        "services": services,
        "grants": grants,
    }


def build_group_index(groups: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for raw in groups:
        key = str(raw.get("key") or raw.get("group_key") or "").strip().lower()
        if not key:
            continue
        index[key] = {
            "key": key,
            "name": str(raw.get("name") or key).strip() or key,
            "parent_key": str(raw.get("parent_key") or raw.get("parent_id") or "").strip().lower() or None,
            "system": bool(raw.get("system")),
            "metadata": _coerce_mapping(raw.get("metadata")),
        }
    return index


def build_service_index(services: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for raw in services:
        service_key = str(raw.get("service_key") or raw.get("key") or "").strip().lower()
        if not service_key:
            continue
        public_access_level = max_service_access_level(
            raw.get("public_access_level"),
            SERVICE_ACCESS_NONE,
        )
        index[service_key] = {
            "service_key": service_key,
            "display_name": str(raw.get("display_name") or raw.get("name") or service_key).strip() or service_key,
            "description": str(raw.get("description") or "").strip() or None,
            "public_access_level": public_access_level,
            "dashboard_url": str(raw.get("dashboard_url") or "").strip() or None,
            "marketing_url": str(raw.get("marketing_url") or "").strip() or None,
            "metadata": _coerce_mapping(raw.get("metadata")),
        }
    return index


def build_group_membership_index(
    memberships: Sequence[Mapping[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    index: Dict[str, List[Dict[str, Any]]] = {}
    for raw in memberships:
        username = str(raw.get("username") or raw.get("user") or "").strip()
        group_key = str(raw.get("group_key") or raw.get("key") or "").strip().lower()
        if not username or not group_key:
            continue
        normalized = {
            "username": username,
            "group_key": group_key,
            "group_name": str(raw.get("group_name") or raw.get("name") or group_key).strip() or group_key,
            "membership_role": normalize_group_membership_role(raw.get("membership_role")),
            "parent_key": str(raw.get("parent_key") or raw.get("group_parent_key") or "").strip().lower() or None,
            "system": bool(raw.get("system")),
            "created_at": raw.get("created_at"),
            "updated_at": raw.get("updated_at"),
        }
        index.setdefault(username, []).append(normalized)
    for values in index.values():
        values.sort(key=lambda item: (item["group_key"], item["membership_role"]))
    return index


def build_group_grant_index(
    grants: Sequence[Mapping[str, Any]],
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    index: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for raw in grants:
        group_key = str(raw.get("group_key") or "").strip().lower()
        service_key = str(raw.get("service_key") or "").strip().lower()
        if not group_key or not service_key:
            continue
        try:
            access_level = normalize_service_access_level(raw.get("access_level"))
        except ValueError:
            continue
        entry = {
            "group_key": group_key,
            "service_key": service_key,
            "access_level": access_level,
            "granted_by": str(raw.get("granted_by") or "").strip() or None,
            "created_at": raw.get("created_at"),
            "updated_at": raw.get("updated_at"),
            "metadata": _coerce_mapping(raw.get("metadata")),
        }
        index.setdefault(group_key, {})[service_key] = entry
    return index


def resolve_group_effective_grants(
    groups: Sequence[Mapping[str, Any]],
    grants: Sequence[Mapping[str, Any]],
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    groups_by_key = build_group_index(groups)
    direct_grants = build_group_grant_index(grants)
    memo: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def resolve(group_key: str, stack: Optional[set[str]] = None) -> Dict[str, Dict[str, Any]]:
        normalized_key = str(group_key or "").strip().lower()
        if not normalized_key:
            return {}
        if normalized_key in memo:
            return memo[normalized_key]
        if stack is None:
            stack = set()
        if normalized_key in stack:
            memo[normalized_key] = {}
            return {}
        stack.add(normalized_key)
        current_group = groups_by_key.get(normalized_key) or {}
        parent_key = str(current_group.get("parent_key") or "").strip().lower() or None
        parent_effective = resolve(parent_key, stack) if parent_key else {}
        current_effective: Dict[str, Dict[str, Any]] = {}
        for service_key, direct_entry in (direct_grants.get(normalized_key) or {}).items():
            direct_access = direct_entry.get("access_level") or SERVICE_ACCESS_NONE
            effective_access = direct_access
            if parent_key:
                parent_entry = parent_effective.get(service_key) or {}
                effective_access = min_service_access_level(
                    direct_access,
                    parent_entry.get("effective_access_level") or SERVICE_ACCESS_NONE,
                )
            current_effective[service_key] = {
                **direct_entry,
                "direct_access_level": direct_access,
                "effective_access_level": effective_access,
                "bounded_by_group": parent_key,
            }
        stack.remove(normalized_key)
        memo[normalized_key] = current_effective
        return current_effective

    for group_key in groups_by_key:
        resolve(group_key)
    return memo


def descendant_group_keys(
    groups: Sequence[Mapping[str, Any]],
    root_keys: Iterable[str],
) -> List[str]:
    children: Dict[str, List[str]] = {}
    normalized_roots = {str(key or "").strip().lower() for key in root_keys if str(key or "").strip()}
    for group in groups:
        group_key = str(group.get("key") or group.get("group_key") or "").strip().lower()
        parent_key = str(group.get("parent_key") or group.get("parent_id") or "").strip().lower()
        if group_key and parent_key:
            children.setdefault(parent_key, []).append(group_key)
    resolved: List[str] = []
    pending = list(normalized_roots)
    seen = set(pending)
    while pending:
        current = pending.pop()
        resolved.append(current)
        for child in children.get(current, []):
            if child in seen:
                continue
            seen.add(child)
            pending.append(child)
    return sorted(set(resolved))


def ancestor_group_keys(
    groups: Sequence[Mapping[str, Any]],
    group_keys: Iterable[str],
) -> List[str]:
    groups_by_key = build_group_index(groups)
    resolved: set[str] = set()
    pending = [str(key or "").strip().lower() for key in group_keys if str(key or "").strip()]
    while pending:
        current = pending.pop()
        if not current or current in resolved:
            continue
        resolved.add(current)
        parent_key = str((groups_by_key.get(current) or {}).get("parent_key") or "").strip().lower()
        if parent_key and parent_key not in resolved:
            pending.append(parent_key)
    return sorted(resolved)


def manageable_group_keys_for_user(
    *,
    role: Any,
    groups: Sequence[Mapping[str, Any]],
    group_memberships: Sequence[Mapping[str, Any]],
) -> List[str]:
    normalized_role = str(role or "").strip().lower()
    if normalized_role == "admin":
        return sorted(build_group_index(groups).keys())
    roots = [
        str(item.get("group_key") or "").strip().lower()
        for item in group_memberships
        if str(item.get("membership_role") or "").strip().lower() == GROUP_MEMBERSHIP_ROLE_MANAGER
    ]
    return descendant_group_keys(groups, roots)


def visible_group_keys_for_user(
    *,
    role: Any,
    groups: Sequence[Mapping[str, Any]],
    group_memberships: Sequence[Mapping[str, Any]],
) -> List[str]:
    if str(role or "").strip().lower() == "admin":
        return sorted(build_group_index(groups).keys())
    member_keys = {
        str(item.get("group_key") or "").strip().lower()
        for item in group_memberships
        if str(item.get("group_key") or "").strip()
    }
    manageable = set(
        manageable_group_keys_for_user(
            role=role,
            groups=groups,
            group_memberships=group_memberships,
        )
    )
    return ancestor_group_keys(groups, member_keys | manageable)


def resolve_user_service_access(
    *,
    role: Any,
    group_memberships: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
    services: Sequence[Mapping[str, Any]],
    grants: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    normalized_role = str(role or "").strip().lower() or None
    groups_by_key = build_group_index(groups)
    services_by_key = build_service_index(services)
    group_effective_grants = resolve_group_effective_grants(groups, grants)
    explicit_group_keys = [
        str(item.get("group_key") or "").strip().lower()
        for item in group_memberships
        if str(item.get("group_key") or "").strip()
    ]
    group_keys: List[str] = []
    seen_groups: set[str] = set()
    candidates: List[str] = []
    if normalized_role:
        candidates.append(normalized_role)
    candidates.extend(explicit_group_keys)
    for candidate in candidates:
        if not candidate or candidate in seen_groups:
            continue
        seen_groups.add(candidate)
        group_keys.append(candidate)

    all_service_keys = sorted(
        set(services_by_key.keys())
        | {service_key for values in group_effective_grants.values() for service_key in values.keys()}
    )
    resolved: List[Dict[str, Any]] = []
    for service_key in all_service_keys:
        service = services_by_key.get(service_key) or {
            "service_key": service_key,
            "display_name": service_key,
            "description": None,
            "public_access_level": SERVICE_ACCESS_NONE,
            "dashboard_url": None,
            "marketing_url": None,
            "metadata": {},
        }
        source_groups: List[str] = []
        granted_access = SERVICE_ACCESS_NONE
        for group_key in group_keys:
            grant_entry = (group_effective_grants.get(group_key) or {}).get(service_key) or {}
            candidate_access = grant_entry.get("effective_access_level") or SERVICE_ACCESS_NONE
            if candidate_access != SERVICE_ACCESS_NONE:
                source_groups.append(group_key)
            granted_access = max_service_access_level(granted_access, candidate_access)
        if normalized_role == "admin":
            granted_access = max_service_access_level(granted_access, SERVICE_ACCESS_CONTROL)
            if "admin" not in source_groups:
                source_groups.insert(0, "admin")
        public_access = service.get("public_access_level") or SERVICE_ACCESS_NONE
        visible_access = max_service_access_level(granted_access, public_access)
        flags = service_access_flags(granted_access, public_access)
        resolved.append(
            {
                "service_key": service_key,
                "display_name": service.get("display_name") or service_key,
                "description": service.get("description"),
                "dashboard_url": service.get("dashboard_url"),
                "marketing_url": service.get("marketing_url"),
                "public_access_level": public_access,
                "access_level": granted_access,
                "visible_access_level": visible_access,
                "source_groups": source_groups,
                "granted": granted_access != SERVICE_ACCESS_NONE,
                "metadata": _coerce_mapping(service.get("metadata")),
                **flags,
            }
        )
    resolved.sort(key=lambda item: item["service_key"])
    return resolved
