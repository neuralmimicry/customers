from __future__ import annotations

import pyotp

import customers_service.app as customers_app
from customers_service.app import create_app


def _build_app(monkeypatch, tmp_path, *, self_registration=False):
    monkeypatch.setenv("CUSTOMERS_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("CUSTOMERS_APP_TOKENS", "refiner=test-refiner-token,billing=test-billing-token")
    monkeypatch.setenv("CUSTOMERS_STATE_DIR", str(tmp_path / "customers-state"))
    monkeypatch.setenv("CUSTOMERS_ALLOW_SETUP", "1")
    monkeypatch.setenv("CUSTOMERS_SELF_REGISTRATION_ENABLED", "1" if self_registration else "0")
    monkeypatch.setenv("CUSTOMERS_SECURE_COOKIES", "0")
    monkeypatch.setenv("CUSTOMERS_ENFORCE_HTTPS", "0")
    return create_app()


def _setup_admin(client, username="alice", password="correct horse battery staple"):
    response = client.post(
        "/api/setup",
        json={
            "username": username,
            "password": password,
            "confirm": password,
            "email": f"{username}@example.com",
        },
    )
    assert response.status_code == 201
    return response.get_json()


def _admin_create_user(client, username, password, *, role="user", email=None):
    response = client.post(
        "/api/users",
        json={
            "username": username,
            "password": password,
            "confirm": password,
            "role": role,
            "email": email or f"{username}@example.com",
        },
    )
    assert response.status_code == 201
    return response.get_json()


def _create_group(client, key, *, name=None, parent_key=None):
    payload = {"key": key, "name": name or key.replace("-", " ").title()}
    if parent_key is not None:
        payload["parent_key"] = parent_key
    response = client.post("/api/groups", json=payload)
    assert response.status_code == 201
    return response.get_json()


def _grant_group_service(client, group_key, service_key, access_level):
    response = client.post(
        f"/api/groups/{group_key}/grants",
        json={"service_key": service_key, "access_level": access_level},
    )
    assert response.status_code in {200, 201}
    return response.get_json()


def _add_group_member(client, group_key, username, *, membership_role="member"):
    response = client.post(
        f"/api/groups/{group_key}/members",
        json={"username": username, "membership_role": membership_role},
    )
    assert response.status_code in {200, 201}
    return response.get_json()


def _login(client, username, password):
    return client.post("/api/login", json={"username": username, "password": password})


def test_health_reports_service_state(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()

    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["service"] == "customers"
    assert payload["has_users"] is False
    assert payload["setup_available"] is True
    assert payload["self_registration_enabled"] is False
    assert sorted(payload["app_tokens_configured"]) == ["billing", "refiner"]


def test_auth_config_and_self_registration_create_workspace(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path, self_registration=True)
    setup_client = app.test_client()

    pre_setup_response = setup_client.get("/api/auth/config")
    assert pre_setup_response.status_code == 200
    pre_setup_payload = pre_setup_response.get_json()
    assert pre_setup_payload["has_users"] is False
    assert pre_setup_payload["setup_available"] is True
    assert pre_setup_payload["self_registration_enabled"] is False
    assert pre_setup_payload["team_provisioning_available"] is True
    assert pre_setup_payload["totp_supported"] is True
    assert pre_setup_payload["passkeys_supported"] is True

    _setup_admin(setup_client)

    auth_config_response = app.test_client().get("/api/auth/config")
    assert auth_config_response.status_code == 200
    auth_config_payload = auth_config_response.get_json()
    assert auth_config_payload["has_users"] is True
    assert auth_config_payload["local_login_enabled"] is True
    assert auth_config_payload["self_registration_enabled"] is True
    assert auth_config_payload["totp_supported"] is True
    assert auth_config_payload["passkeys_supported"] is True

    register_client = app.test_client()
    register_response = register_client.post(
        "/api/register",
        json={
            "username": "bob",
            "email": "bob@example.com",
            "password": "bob password 123",
            "confirm": "bob password 123",
            "create_team": True,
            "workspace_name": "Bob Workspace",
        },
    )
    assert register_response.status_code == 201
    register_payload = register_response.get_json()
    assert register_payload["user"] == "bob"
    assert register_payload["role"] == "user"
    assert register_payload["workspace_provisioned"] is True
    assert register_payload["active_team"]["team_name"] == "Bob Workspace"
    assert register_payload["team_count"] == 1

    session_response = register_client.get("/api/session")
    assert session_response.status_code == 200
    session_payload = session_response.get_json()
    assert session_payload["authenticated"] is True
    assert session_payload["user"] == "bob"
    assert session_payload["active_team"]["team_name"] == "Bob Workspace"

    relogin_client = app.test_client()
    relogin_response = _login(relogin_client, "bob", "bob password 123")
    assert relogin_response.status_code == 200
    assert relogin_response.get_json()["active_team"]["team_name"] == "Bob Workspace"


def test_login_and_registration_pages_include_totp_and_passkey_options(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path, self_registration=True)

    setup_page = app.test_client().get("/setup")
    assert setup_page.status_code == 200
    setup_html = setup_page.get_data(as_text=True)
    assert "Optional sign-in security" in setup_html
    assert "Enable authenticator-app 2FA after setup" in setup_html
    assert "Register a passkey on this device" in setup_html

    setup_client = app.test_client()
    _setup_admin(setup_client)

    login_page = app.test_client().get("/login")
    assert login_page.status_code == 200
    login_html = login_page.get_data(as_text=True)
    assert "Use a passkey" in login_html
    assert "Authenticator code" in login_html
    assert "Create one" in login_html

    register_page = app.test_client().get("/register")
    assert register_page.status_code == 200
    register_html = register_page.get_data(as_text=True)
    assert "Enable authenticator-app 2FA after registration" in register_html
    assert "Register a passkey on this device" in register_html


def test_totp_setup_and_login_flow(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)
    _admin_create_user(admin_client, "bob", "bob password 123", email="bob@example.com")

    bob_client = app.test_client()
    assert _login(bob_client, "bob", "bob password 123").status_code == 200

    start_response = bob_client.post("/api/profile/mfa/totp/start", json={})
    assert start_response.status_code == 200
    start_payload = start_response.get_json()
    secret = start_payload["totp"]["secret"]
    assert start_payload["security"]["totp_enabled"] is False
    assert start_payload["security"]["passkeys_supported"] is True

    verify_response = bob_client.post(
        "/api/profile/mfa/totp/verify",
        json={"code": pyotp.TOTP(secret).now()},
    )
    assert verify_response.status_code == 200
    verify_payload = verify_response.get_json()
    assert verify_payload["security"]["totp_enabled"] is True

    logout_response = bob_client.post("/api/logout")
    assert logout_response.status_code == 200

    pending_login_response = _login(bob_client, "bob", "bob password 123")
    assert pending_login_response.status_code == 202
    pending_payload = pending_login_response.get_json()
    assert pending_payload["status"] == "mfa_required"
    assert pending_payload["mfa"]["type"] == "totp"

    pending_session_response = bob_client.get("/api/session")
    assert pending_session_response.status_code == 200
    assert pending_session_response.get_json() == {"authenticated": False, "user": None}

    invalid_code_response = bob_client.post(
        "/api/login/mfa/totp",
        json={"code": "000000"},
    )
    assert invalid_code_response.status_code == 401
    assert invalid_code_response.get_json()["error"] == "invalid_mfa_code"

    completed_login_response = bob_client.post(
        "/api/login/mfa/totp",
        json={"code": pyotp.TOTP(secret).now()},
    )
    assert completed_login_response.status_code == 200
    completed_payload = completed_login_response.get_json()
    assert completed_payload["user"] == "bob"
    assert completed_payload["security"]["totp_enabled"] is True

    disable_response = bob_client.post("/api/profile/mfa/totp/disable", json={})
    assert disable_response.status_code == 200
    disable_payload = disable_response.get_json()
    assert disable_payload["security"]["totp_enabled"] is False

    assert bob_client.post("/api/logout").status_code == 200
    final_login_response = _login(bob_client, "bob", "bob password 123")
    assert final_login_response.status_code == 200


def test_passkey_registration_and_authentication_flow(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path, self_registration=True)
    setup_client = app.test_client()
    _setup_admin(setup_client)

    register_client = app.test_client()
    register_response = register_client.post(
        "/api/register",
        json={
            "username": "bob",
            "email": "bob@example.com",
            "password": "bob password 123",
            "confirm": "bob password 123",
        },
    )
    assert register_response.status_code == 201

    register_options_response = register_client.post("/api/profile/passkeys/register/options", json={})
    assert register_options_response.status_code == 200
    register_options_payload = register_options_response.get_json()
    register_challenge = register_options_payload["public_key"]["challenge"]
    assert register_challenge

    def fake_verify_registration(**kwargs):
        assert kwargs["expected_challenge"] == register_challenge
        assert kwargs["expected_rp_id"]
        assert kwargs["expected_origins"]
        return {
            "credential_id": "cred-1",
            "public_key": "public-key-1",
            "label": "Workstation passkey",
            "sign_count": 0,
            "created_at": kwargs["now_iso"],
            "last_used_at": None,
            "credential_device_type": "single_device",
            "credential_backed_up": False,
            "user_verified": True,
            "transports": ["internal"],
        }

    monkeypatch.setattr(customers_app, "verify_passkey_registration", fake_verify_registration)

    register_verify_response = register_client.post(
        "/api/profile/passkeys/register/verify",
        json={
            "credential": {
                "id": "cred-1",
                "rawId": "cred-1",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "AQ",
                    "attestationObject": "AQ",
                },
                "transports": ["internal"],
            }
        },
    )
    assert register_verify_response.status_code == 201
    register_verify_payload = register_verify_response.get_json()
    assert register_verify_payload["security"]["passkey_count"] == 1
    assert register_verify_payload["security"]["passkeys"][0]["credential_id"] == "cred-1"

    assert register_client.post("/api/logout").status_code == 200

    auth_options_response = register_client.post(
        "/api/passkeys/authenticate/options",
        json={"username": "bob"},
    )
    assert auth_options_response.status_code == 200
    auth_options_payload = auth_options_response.get_json()
    auth_challenge = auth_options_payload["public_key"]["challenge"]
    assert auth_challenge

    def fake_verify_authentication(**kwargs):
        assert kwargs["expected_challenge"] == auth_challenge
        assert kwargs["expected_rp_id"]
        assert kwargs["expected_origins"]
        stored = dict(kwargs["stored_credential"])
        stored["sign_count"] = 9
        stored["last_used_at"] = kwargs["now_iso"]
        return stored

    monkeypatch.setattr(customers_app, "verify_passkey_authentication", fake_verify_authentication)

    auth_verify_response = register_client.post(
        "/api/passkeys/authenticate/verify",
        json={
            "credential": {
                "id": "cred-1",
                "rawId": "cred-1",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "AQ",
                    "authenticatorData": "AQ",
                    "signature": "AQ",
                },
            }
        },
    )
    assert auth_verify_response.status_code == 200
    auth_verify_payload = auth_verify_response.get_json()
    assert auth_verify_payload["user"] == "bob"
    assert auth_verify_payload["security"]["passkey_count"] == 1

    profile_response = register_client.get("/api/profile")
    assert profile_response.status_code == 200
    profile_payload = profile_response.get_json()
    assert profile_payload["security"]["passkeys"][0]["credential_id"] == "cred-1"
    assert profile_payload["security"]["passkeys"][0]["last_used_at"] is not None


def test_setup_creates_session_and_supports_internal_identity_routes(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()

    setup_payload = _setup_admin(client)
    assert setup_payload["status"] == "ok"
    assert setup_payload["user"] == "alice"

    session_response = client.get("/api/session")
    assert session_response.status_code == 200
    session_payload = session_response.get_json()
    assert session_payload["user"] == "alice"
    assert session_payload["groups"] == ["admin"]
    assert session_payload["active_team"] is None

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
    assert resolve_payload["groups"] == ["admin"]

    lookup_response = client.get(
        "/api/internal/users/alice",
        headers={"Authorization": "Bearer test-billing-token"},
    )
    assert lookup_response.status_code == 200
    lookup_payload = lookup_response.get_json()
    assert lookup_payload["authenticated"] is True
    assert lookup_payload["user"] == "alice"
    assert lookup_payload["user_record"]["username"] == "alice"


def test_internal_user_lookup_returns_404_for_missing_user(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()
    _setup_admin(client)

    response = client.get(
        "/api/internal/users/unknown",
        headers={"Authorization": "Bearer test-billing-token"},
    )

    assert response.status_code == 404
    assert response.get_json()["error"] == "user_not_found"


def test_admin_can_manage_users_and_reset_passwords(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)

    create_payload = _admin_create_user(
        admin_client,
        "bob",
        "temporary password 123",
        role="user",
        email="bob@example.com",
    )
    assert create_payload["user_record"]["username"] == "bob"
    assert create_payload["user_record"]["role"] == "user"

    list_response = admin_client.get("/api/users")
    assert list_response.status_code == 200
    users = {item["username"]: item for item in list_response.get_json()["users"]}
    assert users["alice"]["groups"] == ["admin"]
    assert users["bob"]["groups"] == ["user"]

    bob_client = app.test_client()
    login_response = _login(bob_client, "bob", "temporary password 123")
    assert login_response.status_code == 200
    assert login_response.get_json()["groups"] == ["user"]

    reset_response = admin_client.post(
        "/api/users/bob/password",
        json={"password": "replacement password 456", "confirm": "replacement password 456"},
    )
    assert reset_response.status_code == 200

    bob_old_password_client = app.test_client()
    old_login_response = _login(bob_old_password_client, "bob", "temporary password 123")
    assert old_login_response.status_code == 401

    bob_new_password_client = app.test_client()
    new_login_response = _login(bob_new_password_client, "bob", "replacement password 456")
    assert new_login_response.status_code == 200

    verify_response = admin_client.post(
        "/api/internal/credentials/verify",
        headers={"Authorization": "Bearer test-billing-token"},
        json={"username": "bob", "password": "replacement password 456"},
    )
    assert verify_response.status_code == 200
    verify_payload = verify_response.get_json()
    assert verify_payload["authenticated"] is True
    assert verify_payload["groups"] == ["user"]
    assert verify_payload["active_team"] is None


def test_team_hierarchy_invites_acceptance_and_leave(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)

    _admin_create_user(admin_client, "bob", "bob password 123", email="bob@example.com")
    _admin_create_user(admin_client, "carol", "carol password 123", email="carol@example.com")
    _admin_create_user(admin_client, "erin", "erin password 123", email="erin@example.com")

    bob_client = app.test_client()
    assert _login(bob_client, "bob", "bob password 123").status_code == 200

    create_team_response = bob_client.post("/api/teams", json={"name": "Bob Team"})
    assert create_team_response.status_code == 201
    bob_team = create_team_response.get_json()
    bob_team_id = bob_team["id"]

    child_team_response = admin_client.post(
        "/api/teams",
        json={"name": "Erin Squad", "owner": "erin", "parent_id": bob_team_id},
    )
    assert child_team_response.status_code == 201
    child_team = child_team_response.get_json()
    assert child_team["parent_id"] == bob_team_id

    admin_teams_response = admin_client.get("/api/teams")
    assert admin_teams_response.status_code == 200
    admin_tree = admin_teams_response.get_json()["tree"]
    root = next(item for item in admin_tree if item["id"] == bob_team_id)
    assert [child["id"] for child in root["children"]] == [child_team["id"]]

    invite_response = bob_client.post(f"/api/teams/{bob_team_id}/invite", json={"username": "carol"})
    assert invite_response.status_code == 201
    invitation = invite_response.get_json()
    assert invitation["status"] == "pending"
    assert invitation["team_id"] == bob_team_id

    carol_client = app.test_client()
    assert _login(carol_client, "carol", "carol password 123").status_code == 200

    profile_before_accept = carol_client.get("/api/profile")
    assert profile_before_accept.status_code == 200
    profile_before_payload = profile_before_accept.get_json()
    assert profile_before_payload["active_team"] is None
    assert profile_before_payload["pending_invitation_count"] == 1

    accept_response = carol_client.post(f"/api/team-invitations/{invitation['id']}/accept")
    assert accept_response.status_code == 200
    accepted = accept_response.get_json()
    assert accepted["status"] == "active"
    assert accepted["membership_role"] == "member"

    profile_after_accept = carol_client.get("/api/profile")
    assert profile_after_accept.status_code == 200
    profile_after_payload = profile_after_accept.get_json()
    assert profile_after_payload["active_team"]["team_id"] == bob_team_id
    assert profile_after_payload["team_count"] == 1
    assert profile_after_payload["pending_invitation_count"] == 0

    team_detail_response = bob_client.get(f"/api/teams/{bob_team_id}")
    assert team_detail_response.status_code == 200
    team_detail_payload = team_detail_response.get_json()
    active_members = {(item["username"], item["membership_role"]) for item in team_detail_payload["members"]}
    assert ("bob", "owner") in active_members
    assert ("carol", "member") in active_members

    leave_response = carol_client.post(f"/api/teams/{bob_team_id}/leave")
    assert leave_response.status_code == 200

    profile_after_leave = carol_client.get("/api/profile")
    assert profile_after_leave.status_code == 200
    leave_payload = profile_after_leave.get_json()
    assert leave_payload["active_team"] is None
    assert leave_payload["team_count"] == 0

    relogin_client = app.test_client()
    relogin_response = _login(relogin_client, "carol", "carol password 123")
    assert relogin_response.status_code == 200
    assert relogin_response.get_json()["user"] == "carol"


def test_user_can_reject_invite_and_change_own_password(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)

    _admin_create_user(admin_client, "bob", "bob password 123", email="bob@example.com")
    _admin_create_user(admin_client, "dave", "dave password 123", email="dave@example.com")

    bob_client = app.test_client()
    assert _login(bob_client, "bob", "bob password 123").status_code == 200
    team_response = bob_client.post("/api/teams", json={"name": "Bob Team"})
    assert team_response.status_code == 201
    team_id = team_response.get_json()["id"]

    invite_response = bob_client.post(f"/api/teams/{team_id}/invite", json={"username": "dave"})
    assert invite_response.status_code == 201
    invitation_id = invite_response.get_json()["id"]

    dave_client = app.test_client()
    assert _login(dave_client, "dave", "dave password 123").status_code == 200

    reject_response = dave_client.post(f"/api/team-invitations/{invitation_id}/reject")
    assert reject_response.status_code == 200
    assert reject_response.get_json()["status"] == "rejected"

    profile_response = dave_client.get("/api/profile")
    assert profile_response.status_code == 200
    profile_payload = profile_response.get_json()
    assert profile_payload["active_team"] is None
    assert profile_payload["pending_invitation_count"] == 0

    password_change_response = dave_client.post(
        "/api/profile/password",
        json={
            "current_password": "dave password 123",
            "new_password": "dave replacement password 456",
            "confirm": "dave replacement password 456",
        },
    )
    assert password_change_response.status_code == 200

    dave_old_password_client = app.test_client()
    assert _login(dave_old_password_client, "dave", "dave password 123").status_code == 401

    dave_new_password_client = app.test_client()
    assert _login(dave_new_password_client, "dave", "dave replacement password 456").status_code == 200


def test_profile_settings_roundtrip_preserves_email(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()
    _setup_admin(client)

    profile_response = client.get("/api/profile")
    assert profile_response.status_code == 200
    profile_payload = profile_response.get_json()
    assert profile_payload["authenticated"] is True
    assert profile_payload["email"] == "alice@example.com"
    assert profile_payload["settings"]["assistant"]["use_memory"] is True

    update_response = client.post(
        "/api/profile",
        json={
            "settings": {
                "assistant": {"use_memory": False},
                "llm": {
                    "provider_access": {
                        "openai": {"mode": "user_key", "acknowledged": True},
                    }
                },
                "solver": {"command_policy_mode": "strict"},
            }
        },
    )
    assert update_response.status_code == 200
    update_payload = update_response.get_json()
    assert update_payload["email"] == "alice@example.com"
    assert update_payload["settings"]["assistant"]["use_memory"] is False
    assert update_payload["settings"]["llm"]["provider_access"]["openai"] == {
        "mode": "user_key",
        "acknowledged": True,
    }
    assert update_payload["settings"]["solver"]["command_policy_mode"] == "strict"

    session_response = client.get("/api/session")
    assert session_response.status_code == 200
    session_payload = session_response.get_json()
    assert session_payload["settings"]["assistant"]["use_memory"] is False
    assert session_payload["settings"]["llm"]["provider_access"]["openai"] == {
        "mode": "user_key",
        "acknowledged": True,
    }
    assert session_payload["settings"]["solver"]["command_policy_mode"] == "strict"

    invalid_response = client.post(
        "/api/profile",
        json={"settings": {"solver": {"command_policy_mode": "invalid"}}},
    )
    assert invalid_response.status_code == 400
    invalid_payload = invalid_response.get_json()
    assert invalid_payload["error"] == "invalid_settings"
    assert invalid_payload["details"]

    invalid_provider_access_response = client.post(
        "/api/profile",
        json={"settings": {"llm": {"provider_access": {"openai": {"mode": "invalid"}}}}},
    )
    assert invalid_provider_access_response.status_code == 400
    invalid_provider_access_payload = invalid_provider_access_response.get_json()
    assert invalid_provider_access_payload["error"] == "invalid_settings"
    assert invalid_provider_access_payload["details"]


def test_default_session_exposes_service_access_contract(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)
    _admin_create_user(admin_client, "bob", "bob password 123", email="bob@example.com")

    bob_client = app.test_client()
    login_response = _login(bob_client, "bob", "bob password 123")
    assert login_response.status_code == 200
    login_payload = login_response.get_json()

    assert login_payload["groups"] == ["user"]
    assert login_payload["group_memberships"] == []
    assert login_payload["manageable_groups"] == []
    assert login_payload["can_manage_access"] is False
    assert set(login_payload["visible_services"]) >= {"aarnn", "billing", "continuum", "refiner", "tracey", "webots"}
    assert login_payload["service_access"]["billing"]["access_level"] == "use"
    assert login_payload["service_access"]["refiner"]["can_use"] is True
    assert login_payload["service_access"]["continuum"]["access_level"] == "none"
    assert login_payload["service_access"]["continuum"]["visible"] is True
    assert login_payload["service_access"]["continuum"]["can_observe"] is True
    assert login_payload["service_access"]["gail"]["visible"] is False
    assert login_payload["service_access"]["gail_trading"]["visible"] is False


def test_services_and_groups_apis_reflect_visibility(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()
    _setup_admin(client)

    public_services_response = app.test_client().get("/api/services")
    assert public_services_response.status_code == 200
    public_services = {
        item["service_key"]: item
        for item in public_services_response.get_json()["services"]
    }
    assert set(public_services) >= {"aarnn", "continuum", "refiner", "tracey", "webots"}
    assert "billing" not in public_services
    assert public_services["refiner"]["public_access_level"] == "request"

    groups_response = client.get("/api/groups")
    assert groups_response.status_code == 200
    groups_payload = groups_response.get_json()
    assert set(groups_payload["visible_groups"]) == {"admin", "user"}
    assert set(groups_payload["manageable_groups"]) == {"admin", "user"}

    services_response = client.get("/api/services")
    assert services_response.status_code == 200
    services_payload = services_response.get_json()
    assert services_payload["authenticated"] is True
    service_keys = {item["service_key"] for item in services_payload["services"]}
    assert "billing" in service_keys


def test_delegated_group_manager_can_manage_child_scope_with_parent_bounded_grants(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)

    _admin_create_user(admin_client, "bob", "bob password 123", email="bob@example.com")
    _admin_create_user(admin_client, "carol", "carol password 123", email="carol@example.com")

    _create_group(admin_client, "ops", parent_key="admin")
    _grant_group_service(admin_client, "ops", "billing", "control")
    _add_group_member(admin_client, "ops", "bob", membership_role="manager")

    bob_client = app.test_client()
    assert _login(bob_client, "bob", "bob password 123").status_code == 200

    bob_groups_response = bob_client.get("/api/groups")
    assert bob_groups_response.status_code == 200
    bob_groups_payload = bob_groups_response.get_json()
    assert set(bob_groups_payload["visible_groups"]) == {"admin", "ops"}
    assert set(bob_groups_payload["manageable_groups"]) == {"ops"}

    child_group_response = bob_client.post(
        "/api/groups",
        json={"key": "ops-team", "name": "Ops Team", "parent_key": "ops"},
    )
    assert child_group_response.status_code == 201

    child_grant_response = bob_client.post(
        "/api/groups/ops-team/grants",
        json={"service_key": "billing", "access_level": "control"},
    )
    assert child_grant_response.status_code == 201

    forbidden_grant_response = bob_client.post(
        "/api/groups/ops-team/grants",
        json={"service_key": "customers", "access_level": "control"},
    )
    assert forbidden_grant_response.status_code == 409
    forbidden_grant_payload = forbidden_grant_response.get_json()
    assert forbidden_grant_payload["error"] == "grant_exceeds_parent"
    assert forbidden_grant_payload["details"]["parent_limit"] == "none"

    _add_group_member(bob_client, "ops-team", "carol")

    bob_group_detail = bob_client.get("/api/groups/ops-team")
    assert bob_group_detail.status_code == 200
    bob_group_payload = bob_group_detail.get_json()
    assert bob_group_payload["can_manage"] is True
    effective_billing_grant = next(
        item for item in bob_group_payload["grants"] if item["service_key"] == "billing"
    )
    assert effective_billing_grant["effective_access_level"] == "control"
    assert effective_billing_grant["bounded_by_group"] == "ops"

    carol_client = app.test_client()
    carol_login_response = _login(carol_client, "carol", "carol password 123")
    assert carol_login_response.status_code == 200
    carol_payload = carol_login_response.get_json()
    assert carol_payload["is_admin"] is False
    assert carol_payload["groups"] == ["user", "ops-team"]
    assert carol_payload["service_access"]["billing"]["access_level"] == "control"
    assert carol_payload["service_access"]["customers"]["access_level"] == "none"
    assert "billing" in carol_payload["visible_services"]

    system_group_response = bob_client.post(
        "/api/groups/user/grants",
        json={"service_key": "billing", "access_level": "control"},
    )
    assert system_group_response.status_code == 403


def test_public_services_exclude_user_default_grants(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)

    response = app.test_client().get("/api/services")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["authenticated"] is False
    assert payload["identity_type"] is None
    service_keys = {item["service_key"] for item in payload["services"]}
    assert "billing" not in service_keys
    assert "refiner" in service_keys


def test_service_account_session_and_token_lifecycle(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)

    _create_group(admin_client, "partners", parent_key="admin")
    _grant_group_service(admin_client, "partners", "tracey", "observe")

    create_response = admin_client.post(
        "/api/service-accounts",
        json={
            "service_account_id": "tracey-sync",
            "display_name": "Tracey Sync",
            "service_key": "tracey",
            "group_keys": ["partners"],
            "issue_token": True,
            "token_label": "initial-sync-token",
        },
    )
    assert create_response.status_code == 201
    create_payload = create_response.get_json()
    token = create_payload["access_token"]
    service_account = create_payload["service_account"]
    principal_username = service_account["principal_username"]
    initial_token_id = create_payload["access_token_record"]["id"]

    session_response = app.test_client().get(
        "/api/session",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert session_response.status_code == 200
    session_payload = session_response.get_json()
    assert session_payload["authenticated"] is True
    assert session_payload["identity_type"] == "service_account"
    assert session_payload["role"] == "service_account"
    assert session_payload["user"] == "tracey-sync"
    assert session_payload["groups"] == ["partners"]
    assert session_payload["group_memberships"][0]["principal_type"] == "service_account"
    assert session_payload["group_memberships"][0]["principal_username"] == principal_username
    assert session_payload["service_access"]["tracey"]["access_level"] == "observe"
    assert session_payload["service_access"]["billing"]["access_level"] == "none"
    assert "billing" not in session_payload["visible_services"]

    users_response = admin_client.get("/api/users")
    assert users_response.status_code == 200
    usernames = {item["username"] for item in users_response.get_json()["users"]}
    assert principal_username not in usernames

    issue_response = admin_client.post(
        "/api/service-accounts/tracey-sync/tokens",
        json={"label": "follow-up-token"},
    )
    assert issue_response.status_code == 201
    issue_payload = issue_response.get_json()
    issued_token_id = issue_payload["access_token_record"]["id"]
    token_ids = {item["id"] for item in issue_payload["service_account"]["access_tokens"]}
    assert {initial_token_id, issued_token_id}.issubset(token_ids)

    revoke_response = admin_client.delete(
        f"/api/service-accounts/tracey-sync/tokens/{issued_token_id}"
    )
    assert revoke_response.status_code == 200
    revoke_payload = revoke_response.get_json()
    revoked = {
        item["id"]: item
        for item in revoke_payload["service_account"]["access_tokens"]
    }
    assert revoked[issued_token_id]["disabled"] is True
    assert revoked[initial_token_id]["disabled"] is False

    disable_response = admin_client.post(
        "/api/service-accounts/tracey-sync/disable",
        json={"disabled": True},
    )
    assert disable_response.status_code == 200
    assert disable_response.get_json()["service_account"]["disabled"] is True

    disabled_session_response = app.test_client().get(
        "/api/session",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert disabled_session_response.status_code == 200
    assert disabled_session_response.get_json() == {"authenticated": False, "user": None}


def test_service_account_creation_respects_delegated_group_scope(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)

    _admin_create_user(admin_client, "bob", "bob password 123", email="bob@example.com")
    _create_group(admin_client, "ops", parent_key="admin")
    _create_group(admin_client, "ops-team", parent_key="ops")
    _create_group(admin_client, "sales", parent_key="admin")
    _add_group_member(admin_client, "ops", "bob", membership_role="manager")
    _grant_group_service(admin_client, "ops", "continuum", "observe")
    _grant_group_service(admin_client, "sales", "continuum", "observe")

    bob_client = app.test_client()
    assert _login(bob_client, "bob", "bob password 123").status_code == 200

    allowed_response = bob_client.post(
        "/api/service-accounts",
        json={
            "service_account_id": "ops-bot",
            "display_name": "Ops Bot",
            "group_keys": ["ops-team"],
            "service_key": "continuum",
            "issue_token": False,
        },
    )
    assert allowed_response.status_code == 201
    allowed_payload = allowed_response.get_json()
    assert allowed_payload["service_account"]["groups"] == ["ops-team"]
    assert allowed_payload["service_account"]["can_manage"] is True

    forbidden_response = bob_client.post(
        "/api/service-accounts",
        json={
            "service_account_id": "sales-bot",
            "display_name": "Sales Bot",
            "group_keys": ["sales"],
            "service_key": "continuum",
            "issue_token": False,
        },
    )
    assert forbidden_response.status_code == 403
    assert forbidden_response.get_json()["error"] == "forbidden"


def test_internal_routes_accept_trusted_service_account_tokens(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    admin_client = app.test_client()
    _setup_admin(admin_client)

    create_response = admin_client.post(
        "/api/service-accounts",
        json={
            "service_account_id": "billing-sync",
            "display_name": "Billing Sync",
            "service_key": "billing",
            "group_keys": ["admin"],
            "issue_token": True,
        },
    )
    assert create_response.status_code == 201
    trusted_token = create_response.get_json()["access_token"]

    user_response = app.test_client().get(
        "/api/internal/users/alice",
        headers={"Authorization": f"Bearer {trusted_token}"},
    )
    assert user_response.status_code == 200
    assert user_response.get_json()["user_record"]["username"] == "alice"

    verify_response = app.test_client().post(
        "/api/internal/credentials/verify",
        headers={"Authorization": f"Bearer {trusted_token}"},
        json={"username": "alice", "password": "correct horse battery staple"},
    )
    assert verify_response.status_code == 200
    assert verify_response.get_json()["authenticated"] is True

    denied_response = admin_client.post(
        "/api/service-accounts",
        json={
            "service_account_id": "tracey-sync",
            "display_name": "Tracey Sync",
            "service_key": "tracey",
            "group_keys": ["admin"],
            "issue_token": True,
        },
    )
    assert denied_response.status_code == 201
    denied_token = denied_response.get_json()["access_token"]

    forbidden_response = app.test_client().get(
        "/api/internal/users/alice",
        headers={"Authorization": f"Bearer {denied_token}"},
    )
    assert forbidden_response.status_code == 403
    assert forbidden_response.get_json()["error"] == "forbidden"


def test_setup_rejects_reserved_service_account_username(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "CUSTOMERS_BOOTSTRAP_SERVICE_ACCOUNTS",
        '[{"service_account_id":"setup-bot","display_name":"Setup Bot","groups":["admin"]}]',
    )
    app = _build_app(monkeypatch, tmp_path)
    client = app.test_client()

    response = client.post(
        "/api/setup",
        json={
            "username": "svc_setup-bot",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
            "email": "setup@example.com",
        },
    )

    assert response.status_code == 409
    assert response.get_json()["error"] == "reserved_username"
