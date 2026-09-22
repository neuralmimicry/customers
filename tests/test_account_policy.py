from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from customers_service.account_policy import valid_password
from test_app import _build_app, _setup_admin, _login


@pytest.mark.parametrize("value", ["short1!Aa", "lowercase123!", "UPPERCASE123!", "NoNumbersHere!", "NoSymbolsHere123", "abcdefghijkL"])
def test_password_requires_length_and_all_character_classes(value):
    assert not valid_password(value)


def test_valid_password_can_be_longer_than_twelve_characters():
    assert valid_password("A good passphrase 123!")


def test_signup_rejects_weak_password_and_does_not_create_user(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path, self_registration=True)
    _setup_admin(app.test_client())
    response = app.test_client().post('/api/register', json={"username": "newcustomer", "email": "new@example.com", "password": "weak password 123", "confirm": "weak password 123"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "password_too_weak"
    assert app.extensions["nm_store"].users.get_user("newcustomer") is None


def test_system_password_requires_change_before_service_access(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin = app.test_client()
    _setup_admin(admin)
    assert admin.post('/api/users', json={"username": "newcustomer", "password": "Temporary1!pass", "email": "new@example.com"}).status_code == 201
    customer = app.test_client()
    login = _login(customer, "newcustomer", "Temporary1!pass")
    assert login.status_code == 200
    payload = login.get_json()
    assert payload["requires_password_change"] is True
    assert "access_token" not in payload and "sso_token" not in payload
    assert all(value["access_level"] == "none" for value in payload["service_access"].values())
    assert customer.post('/api/sso/issue', json={}).status_code == 403
    assert customer.post('/api/teams', json={"name": "Bypass"}).status_code == 403
    assert customer.post('/api/profile', json={"email": "changed@example.com"}).status_code == 403
    unchanged = customer.post('/api/profile/password', json={"current_password": "Temporary1!pass", "new_password": "Temporary1!pass", "confirm": "Temporary1!pass"})
    assert unchanged.status_code == 400
    changed = customer.post('/api/profile/password', json={"current_password": "Temporary1!pass", "new_password": "My personal passphrase 2!", "confirm": "My personal passphrase 2!"})
    assert changed.status_code == 200
    assert changed.get_json()["requires_password_change"] is False
    assert changed.get_json().get("access_token")
    assert customer.post('/api/sso/issue', json={}).status_code == 200
    assert _login(app.test_client(), "newcustomer", "Temporary1!pass").status_code == 401


def test_email_and_payment_detail_changes_start_refund_hold(monkeypatch, tmp_path):
    monkeypatch.setenv("CUSTOMERS_REFUND_HOLD_HOURS", "48")
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()
    _setup_admin(client)
    assert client.get('/api/profile').get_json()["refund_hold_until"] is None
    response = client.post('/api/profile', json={"email": "changed@example.com"})
    hold = response.get_json()["refund_hold_until"]
    assert datetime.fromisoformat(hold) > datetime.now(timezone.utc) + timedelta(hours=47)
    unchanged = client.post('/api/profile', json={"email": "changed@example.com"})
    assert unchanged.get_json()["refund_hold_until"] == hold
    assert client.post('/api/internal/users/alice/payment-details-changed', json={}).status_code == 403
    notification = client.post('/api/internal/users/alice/payment-details-changed', json={"event_id": "purchase-1"}, headers={"Authorization": "Bearer test-refiner-token"})
    assert notification.status_code == 200
    assert notification.get_json()["sensitive_change_kind"] == "payment_details"
    assert client.get('/api/session').get_json()["refund_hold_until"] >= hold
    duplicate = client.post('/api/internal/users/alice/payment-details-changed', json={"event_id": "purchase-1"}, headers={"Authorization": "Bearer test-refiner-token"})
    assert duplicate.get_json()["refund_hold_until"] == notification.get_json()["refund_hold_until"]


def test_mfa_cannot_be_disabled_without_current_code(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()
    _setup_admin(client)
    secret = client.post('/api/profile/mfa/totp/start', json={}).get_json()["totp"]["secret"]
    assert client.post('/api/profile/mfa/totp/verify', json={"code": pyotp.TOTP(secret).now()}).status_code == 200
    assert client.post('/api/profile/mfa/totp/start', json={}).status_code == 409
    assert client.post('/api/profile/mfa/totp/disable', json={}).status_code == 401
    assert client.get('/api/profile').get_json()["security"]["totp_enabled"] is True


def test_mfa_guessing_is_throttled(monkeypatch, tmp_path):
    import customers_service.app as module
    module._LOGIN_ATTEMPTS.clear()
    monkeypatch.setattr(module, "LOGIN_MAX_ATTEMPTS", 3)
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()
    _setup_admin(client, username="mfatest")
    secret = client.post('/api/profile/mfa/totp/start', json={}).get_json()["totp"]["secret"]
    client.post('/api/profile/mfa/totp/verify', json={"code": pyotp.TOTP(secret).now()})
    client.post('/api/logout')
    assert _login(client, "mfatest", "Correct horse battery staple 12!").status_code == 202
    for _ in range(3):
        # Restarting the password step must not reset failed second-factor attempts.
        assert _login(client, "mfatest", "Correct horse battery staple 12!").status_code == 202
        assert client.post('/api/login/mfa/totp', json={"code": "invalid"}).status_code == 401
    assert client.post('/api/login/mfa/totp', json={"code": pyotp.TOTP(secret).now()}).status_code == 429
    assert _login(client, "mfatest", "Correct horse battery staple 12!").status_code == 429
    module._LOGIN_ATTEMPTS.clear()


def test_minimum_length_cannot_be_configured_below_twelve(monkeypatch, tmp_path):
    monkeypatch.setenv("CUSTOMERS_PASSWORD_MIN_LENGTH", "8")
    app = _build_app(monkeypatch, tmp_path)
    assert app.test_client().get('/api/auth/config').get_json()["password_min_length"] == 12
