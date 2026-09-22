"""Shared password and refund cooling-off rules."""
import os
import re
from datetime import datetime, timedelta, timezone


def valid_password(password, minimum=12):
    return isinstance(password, str) and len(password) >= max(12, minimum) and all(
        re.search(pattern, password) for pattern in (r"[A-Z]", r"[a-z]", r"[0-9]", r"[^\w\s]")
    )


def password_message(minimum=12):
    return f"Use at least {max(12, minimum)} characters, including uppercase and lowercase letters, a number and a symbol."


def sensitive_change_metadata(metadata, kind, *, requires_password_change=None):
    updated = dict(metadata)
    policy = dict(updated.get("account_policy") or {})
    timestamp = datetime.now(timezone.utc)
    try:
        hold_hours = max(1, int(os.getenv("CUSTOMERS_REFUND_HOLD_HOURS", "48")))
    except ValueError:
        hold_hours = 48
    policy.update(sensitive_details_changed_at=timestamp.isoformat(),
                  sensitive_change_kind=kind,
                  refund_hold_until=(timestamp + timedelta(hours=hold_hours)).isoformat())
    if requires_password_change is not None:
        policy["requires_password_change"] = requires_password_change
    updated["account_policy"] = policy
    return updated
