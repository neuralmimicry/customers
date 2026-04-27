from __future__ import annotations

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

    _setup_admin(setup_client)

    auth_config_response = app.test_client().get("/api/auth/config")
    assert auth_config_response.status_code == 200
    auth_config_payload = auth_config_response.get_json()
    assert auth_config_payload["has_users"] is True
    assert auth_config_payload["local_login_enabled"] is True
    assert auth_config_payload["self_registration_enabled"] is True

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
                "solver": {"command_policy_mode": "strict"},
            }
        },
    )
    assert update_response.status_code == 200
    update_payload = update_response.get_json()
    assert update_payload["email"] == "alice@example.com"
    assert update_payload["settings"]["assistant"]["use_memory"] is False
    assert update_payload["settings"]["solver"]["command_policy_mode"] == "strict"

    session_response = client.get("/api/session")
    assert session_response.status_code == 200
    session_payload = session_response.get_json()
    assert session_payload["settings"]["assistant"]["use_memory"] is False
    assert session_payload["settings"]["solver"]["command_policy_mode"] == "strict"

    invalid_response = client.post(
        "/api/profile",
        json={"settings": {"solver": {"command_policy_mode": "invalid"}}},
    )
    assert invalid_response.status_code == 400
    invalid_payload = invalid_response.get_json()
    assert invalid_payload["error"] == "invalid_settings"
    assert invalid_payload["details"]
