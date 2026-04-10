from __future__ import annotations

from customers_service.app import create_app


def _build_app(monkeypatch, tmp_path):
    monkeypatch.setenv("CUSTOMERS_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("CUSTOMERS_APP_TOKENS", "refiner=test-refiner-token,billing=test-billing-token")
    monkeypatch.setenv("CUSTOMERS_STATE_DIR", str(tmp_path / "customers-state"))
    monkeypatch.setenv("CUSTOMERS_ALLOW_SETUP", "1")
    monkeypatch.setenv("CUSTOMERS_SECURE_COOKIES", "0")
    monkeypatch.setenv("CUSTOMERS_ENFORCE_HTTPS", "0")
    return create_app()


def test_health_reports_service_state(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()

    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["service"] == "customers"
    assert sorted(payload["app_tokens_configured"]) == ["billing", "refiner"]


def test_setup_creates_session_and_supports_internal_identity_routes(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()

    setup_response = client.post(
        "/api/setup",
        json={
            "username": "alice",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
            "email": "alice@example.com",
        },
    )
    assert setup_response.status_code == 201
    setup_payload = setup_response.get_json()
    assert setup_payload["status"] == "ok"
    assert setup_payload["user"] == "alice"

    session_response = client.get("/api/session")
    assert session_response.status_code == 200
    assert session_response.get_json()["user"] == "alice"

    issue_response = client.post("/api/voice/tokens", json={"label": "pytest-token"})
    assert issue_response.status_code == 201
    token_payload = issue_response.get_json()
    assert token_payload["user"] == "alice"
    assert token_payload["token"]

    verify_response = client.post(
        "/api/internal/credentials/verify",
        headers={"Authorization": "Bearer test-billing-token"},
        json={"username": "alice", "password": "correct horse battery staple"},
    )
    assert verify_response.status_code == 200
    assert verify_response.get_json()["authenticated"] is True

    resolve_response = client.post(
        "/api/internal/voice/resolve",
        headers={"Authorization": "Bearer test-refiner-token"},
        json={"token": token_payload["token"]},
    )
    assert resolve_response.status_code == 200
    resolve_payload = resolve_response.get_json()
    assert resolve_payload["authenticated"] is True
    assert resolve_payload["user"] == "alice"
