"""Admin user view + per-account password management tests."""
import json

from sqlalchemy import delete, func, select

from app.models.user import User


def _create_user(db, email: str, password_hash: str = "") -> User:
    from app.services.auth_service import get_or_create_role
    user = User(email=email, full_name="Test Person", organization="Test Org",
                password_hash=password_hash, is_verified=True)
    role = get_or_create_role(db, "SECURITY_ANALYST")
    user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_admin_lists_users_with_signin_metadata(client, admin_headers, db_session):
    r = client.get("/api/auth/users", headers=admin_headers)
    assert r.status_code == 200, r.text
    users = r.json()
    assert isinstance(users, list)
    assert len(users) >= 4  # seeded admin/analyst/viewer/sso.demo
    by_email = {u["email"]: u for u in users}
    sso = by_email["sso.demo@cybersentinel.io"]
    assert sso["oauth_provider"] is None
    assert sso["has_password"] is False  # SSO-only account
    assert "created_at" in sso
    admin_user = by_email["admin@cybersentinel.io"]
    assert admin_user["has_password"] is True
    assert "ADMIN" in admin_user["roles"]


def test_non_admin_cannot_list_users(client, analyst_headers):
    r = client.get("/api/auth/users", headers=analyst_headers)
    assert r.status_code == 403


def test_unauthenticated_cannot_list_users(client):
    r = client.get("/api/auth/users")
    assert r.status_code == 401


def test_password_change_requires_current_password(client, admin_headers):
    r = client.post("/api/auth/me/password", headers=admin_headers, json={
        "new_password": "Changed123",
        "confirm_password": "Changed123",
    })
    assert r.status_code == 400
    assert "Current password" in r.json()["detail"]

    r = client.post("/api/auth/me/password", headers=admin_headers, json={
        "current_password": "not-the-password",
        "new_password": "Changed123",
        "confirm_password": "Changed123",
    })
    assert r.status_code == 400
    assert "Current password" in r.json()["detail"]


def test_password_change_works_with_correct_current(client, admin_headers):
    # admin@cybersentinel.io starts with Admin@2026 (seeded). Change it, then
    # restore it so later tests keep working.
    r = client.post("/api/auth/me/password", headers=admin_headers, json={
        "current_password": "Admin@2026",
        "new_password": "TempNew456",
        "confirm_password": "TempNew456",
    })
    assert r.status_code == 200, r.text
    assert r.json()["has_password"] is True

    # Old password no longer works; new one does
    old = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "Admin@2026"})
    assert old.status_code == 401
    new = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "TempNew456"})
    assert new.status_code == 200

    # Restore the seeded password
    r = client.post("/api/auth/me/password", headers=admin_headers, json={
        "current_password": "TempNew456",
        "new_password": "Admin@2026",
        "confirm_password": "Admin@2026",
    })
    assert r.status_code == 200


def test_weak_password_rejected(client, admin_headers):
    r = client.post("/api/auth/me/password", headers=admin_headers, json={
        "current_password": "Admin@2026",
        "new_password": "short",
        "confirm_password": "short",
    })
    assert r.status_code == 422

    r = client.post("/api/auth/me/password", headers=admin_headers, json={
        "current_password": "Admin@2026",
        "new_password": "noDigitsHere",
        "confirm_password": "noDigitsHere",
    })
    assert r.status_code == 422


def test_mismatched_confirm_rejected(client, admin_headers):
    r = client.post("/api/auth/me/password", headers=admin_headers, json={
        "current_password": "Admin@2026",
        "new_password": "Both12345",
        "confirm_password": "Different99",
    })
    assert r.status_code == 422


def test_sso_only_set_password_end_to_end(client, db_session):
    """The full flow: SSO-only account → set password → login with it."""
    email = "sso.set.test@cybersentinel.io"
    user = _create_user(db_session, email, password_hash="")

    # No token yet: reject
    r = client.post("/api/auth/me/password", json={
        "new_password": "NewPass123",
        "confirm_password": "NewPass123",
    })
    assert r.status_code == 401

    # The user object needs a token — reuse the SSO account via the app's own
    # token builder (mirrors what the OAuth callback does on success).
    from app.services.auth_service import build_tokens
    tokens = build_tokens(user)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    # Before: no password
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["has_password"] is False

    # Set a password (no current_password needed for SSO-only)
    r = client.post("/api/auth/me/password", headers=headers, json={
        "new_password": "NewPass123",
        "confirm_password": "NewPass123",
    })
    assert r.status_code == 200, r.text
    assert r.json()["has_password"] is True

    # Now password login works
    login = client.post("/api/auth/login", json={"email": email, "password": "NewPass123"})
    assert login.status_code == 200, login.text
    assert login.json()["user"]["has_password"] is True

    # And /me reflects it
    me = client.get("/api/auth/me", headers=headers)
    assert me.json()["has_password"] is True

    # Cleanup so the shared session DB stays tidy for other tests
    db_session.delete(user)
    db_session.commit()


def test_seeded_sso_user_has_no_password(db_session):
    from app.models.user import User
    sso = db_session.scalar(select(User).where(User.email == "sso.demo@cybersentinel.io"))
    assert sso is not None
    assert sso.password_hash == ""
    assert sso.has_password is False


def _user_id(client, admin_headers, email):
    users = client.get("/api/auth/users", headers=admin_headers).json()
    return next(u["id"] for u in users if u["email"] == email)


def test_admin_disables_and_reenables_user(client, admin_headers):
    uid = str(_user_id(client, admin_headers, "viewer@cybersentinel.io"))

    r = client.post(f"/api/auth/users/{uid}/status", headers=admin_headers, json={"is_active": False})
    assert r.status_code == 200, r.text
    assert r.json()["is_active"] is False

    # Disabled account cannot sign in
    r = client.post("/api/auth/login", json={"email": "viewer@cybersentinel.io", "password": "Viewer@2026"})
    assert r.status_code == 403

    # Re-enable and it works again
    r = client.post(f"/api/auth/users/{uid}/status", headers=admin_headers, json={"is_active": True})
    assert r.status_code == 200
    r = client.post("/api/auth/login", json={"email": "viewer@cybersentinel.io", "password": "Viewer@2026"})
    assert r.status_code == 200


def test_admin_cannot_disable_self(client, admin_headers):
    uid = _user_id(client, admin_headers, "admin@cybersentinel.io")
    r = client.post(f"/api/auth/users/{uid}/status", headers=admin_headers, json={"is_active": False})
    assert r.status_code == 400
    assert "own account" in r.json()["detail"]


def test_admin_resets_user_password(client, admin_headers):
    uid = _user_id(client, admin_headers, "viewer@cybersentinel.io")
    r = client.post(f"/api/auth/users/{uid}/password", headers=admin_headers,
                    json={"new_password": "Forced@456"})
    assert r.status_code == 200, r.text
    assert r.json()["has_password"] is True

    old = client.post("/api/auth/login", json={"email": "viewer@cybersentinel.io", "password": "Viewer@2026"})
    assert old.status_code == 401
    new = client.post("/api/auth/login", json={"email": "viewer@cybersentinel.io", "password": "Forced@456"})
    assert new.status_code == 200

    # Restore the seeded password so later tests keep working
    client.post(f"/api/auth/users/{uid}/password", headers=admin_headers,
                json={"new_password": "Viewer@2026"})


def test_admin_updates_roles(client, admin_headers):
    uid = _user_id(client, admin_headers, "viewer@cybersentinel.io")
    r = client.put(f"/api/auth/users/{uid}/roles", headers=admin_headers,
                   json={"roles": ["SECURITY_ANALYST", "VIEWER"]})
    assert r.status_code == 200, r.text
    assert set(r.json()["roles"]) == {"SECURITY_ANALYST", "VIEWER"}

    # Restore
    client.put(f"/api/auth/users/{uid}/roles", headers=admin_headers, json={"roles": ["VIEWER"]})


def test_admin_cannot_demote_self(client, admin_headers):
    uid = _user_id(client, admin_headers, "admin@cybersentinel.io")
    r = client.put(f"/api/auth/users/{uid}/roles", headers=admin_headers,
                   json={"roles": ["SECURITY_ANALYST"]})
    assert r.status_code == 400
    assert "own ADMIN" in r.json()["detail"]


def test_admin_rejects_unknown_role(client, admin_headers):
    uid = _user_id(client, admin_headers, "viewer@cybersentinel.io")
    r = client.put(f"/api/auth/users/{uid}/roles", headers=admin_headers,
                   json={"roles": ["SUPERUSER"]})
    assert r.status_code == 400
    assert "Unknown roles" in r.json()["detail"]


def test_analyst_cannot_use_admin_user_endpoints(client, analyst_headers):
    # The user list itself is admin-only
    r = client.get("/api/auth/users", headers=analyst_headers)
    assert r.status_code == 403
    # Need a valid user id: use the analyst's own id from /me
    me = client.get("/api/auth/me", headers=analyst_headers).json()
    uid = me["id"]
    for method, path in [
        ("post", f"/api/auth/users/{uid}/status"),
        ("post", f"/api/auth/users/{uid}/password"),
        ("put", f"/api/auth/users/{uid}/roles"),
    ]:
        r = getattr(client, method)(path, headers=analyst_headers,
                                    json={"is_active": True} if "status" in path
                                    else ({"new_password": "Xyz@12345"} if "password" in path
                                          else {"roles": ["VIEWER"]}))
        assert r.status_code == 403, (method, path, r.text)


def test_admin_endpoint_unknown_user_404(client, admin_headers):
    import uuid as _uuid
    r = client.post(f"/api/auth/users/{_uuid.uuid4()}/status", headers=admin_headers, json={"is_active": False})
    assert r.status_code == 404


def test_export_json_bundle(client, admin_headers, db_session):
    """GDPR-style export returns profile + devices + audit trail + incidents."""
    from app.models.investigation import ActionLog
    from app.models.security import Incident
    from app.models.user import Device

    admin = db_session.scalar(select(User).where(User.email == "admin@cybersentinel.io"))
    db_session.add(Device(device_id="dev-export-1", user_id=admin.id, device_name="Test Laptop",
                          os="macOS", browser="Chrome", ip_address="10.0.0.9", is_trusted=True))
    db_session.add(ActionLog(actor="admin@cybersentinel.io", action="AUTH.TEST_RECORD",
                             target_type="user", target_id="x", detail={"k": "v"}, ip_address="10.0.0.9"))
    db_session.add(Incident(incident_id="INC-EXPORT-TEST", title="Export Test Incident",
                            created_by="admin@cybersentinel.io"))
    db_session.commit()
    try:
        r = client.get("/api/auth/me/export", headers=admin_headers)
        assert r.status_code == 200, r.text
        assert "attachment" in r.headers["content-disposition"]
        assert "cybersentinel-account-admin.json" in r.headers["content-disposition"]
        body = r.json()
        assert body["account"]["email"] == "admin@cybersentinel.io"
        assert body["account"]["roles"] == ["ADMIN"]
        assert body["account"]["has_password"] is True
        assert any(d["device_id"] == "dev-export-1" for d in body["devices"])
        assert any(a["action"] == "AUTH.TEST_RECORD" for a in body["audit_events"])
        assert any(i["incident_id"] == "INC-EXPORT-TEST" for i in body["incidents"])
    finally:
        db_session.execute(delete(Device).where(Device.device_id == "dev-export-1"))
        db_session.execute(delete(ActionLog).where(ActionLog.action == "AUTH.TEST_RECORD"))
        db_session.execute(delete(Incident).where(Incident.incident_id == "INC-EXPORT-TEST"))
        db_session.commit()

    # The export itself is audited
    from app.models.investigation import ActionLog as AL
    count = db_session.scalar(select(func.count()).select_from(AL).where(
        AL.actor == "admin@cybersentinel.io", AL.action == "AUTH.DATA_EXPORT"))
    assert count and count >= 1


def test_export_csv(client, admin_headers):
    r = client.get("/api/auth/me/export?fmt=csv", headers=admin_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "cybersentinel-audit-admin.csv" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("created_at,action")
    assert any("AUTH.DATA_EXPORT" in line for line in lines)


def test_export_requires_auth(client):
    r = client.get("/api/auth/me/export")
    assert r.status_code == 401


def test_export_rejects_bad_format(client, admin_headers):
    r = client.get("/api/auth/me/export?fmt=xml", headers=admin_headers)
    assert r.status_code == 422


def test_export_zip_bundle(client, admin_headers):
    import io
    import zipfile
    r = client.get("/api/auth/me/export?fmt=zip", headers=admin_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/zip")
    assert "cybersentinel-bundle-admin.zip" in r.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        names = set(zf.namelist())
        assert {"account.json", "audit.csv", "evidence.json", "summary.html"} <= names
        summary = zf.read("summary.html").decode()
        assert "account data export" in summary.lower()
        account = json.loads(zf.read("account.json"))
        assert account["account"]["email"] == "admin@cybersentinel.io"


def test_deprovision_revokes_sessions_and_restore(client, admin_headers, db_session):
    """Deprovisioning archives the account and revokes ALL outstanding tokens;
    restore re-enables it but old sessions stay dead."""
    from app.core.security import hash_password
    from app.models.investigation import ActionLog
    user = _create_user(db_session, "depro.test@cybersentinel.io", hash_password("Depro@2026"))
    uid = str(user.id)
    try:
        r = client.post("/api/auth/login", json={"email": "depro.test@cybersentinel.io", "password": "Depro@2026"})
        assert r.status_code == 200, r.text
        tok, refresh = r.json()["tokens"]["access_token"], r.json()["tokens"]["refresh_token"]
        headers = {"Authorization": f"Bearer {tok}"}
        assert client.get("/api/auth/me", headers=headers).status_code == 200

        # Deprovision: archive + revoke
        r = client.post(f"/api/auth/users/{uid}/deprovision", headers=admin_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["is_active"] is False and body["sso_blocked"] is True

        # Existing access token is dead
        assert client.get("/api/auth/me", headers=headers).status_code == 401
        # Existing refresh token is dead
        assert client.post("/api/auth/refresh", json={"refresh_token": refresh}).status_code == 401
        # Password login is blocked
        assert client.post("/api/auth/login",
                           json={"email": "depro.test@cybersentinel.io", "password": "Depro@2026"}).status_code == 403

        # Admin cannot deprovision self
        me = client.get("/api/auth/me", headers=admin_headers).json()
        assert client.post(f"/api/auth/users/{me['id']}/deprovision", headers=admin_headers).status_code == 400

        # Signed audit record
        rec = db_session.scalar(select(ActionLog).where(
            ActionLog.action == "AUTH.USER_DEPROVISIONED", ActionLog.target_id == uid))
        assert rec is not None
        assert rec.detail and rec.detail.get("_sig") and rec.detail.get("_signed_at")

        # Restore re-enables; fresh login works; old tokens stay revoked
        r = client.post(f"/api/auth/users/{uid}/restore", headers=admin_headers)
        assert r.status_code == 200
        assert r.json()["is_active"] is True and r.json()["sso_blocked"] is False
        assert client.get("/api/auth/me", headers=headers).status_code == 401  # old token still dead
        r = client.post("/api/auth/login",
                        json={"email": "depro.test@cybersentinel.io", "password": "Depro@2026"})
        assert r.status_code == 200, r.text
    finally:
        db_session.execute(delete(ActionLog).where(ActionLog.target_id == uid))
        db_session.execute(delete(User).where(User.id == user.id))
        db_session.commit()


def test_sso_block_toggle(client, admin_headers, db_session):
    from app.core.security import hash_password
    user = _create_user(db_session, "sso.toggle@example.com", hash_password("Toggle@2026"))
    uid = str(user.id)
    try:
        r = client.post(f"/api/auth/users/{uid}/sso-block", headers=admin_headers, json={"blocked": True})
        assert r.status_code == 200
        assert r.json()["sso_blocked"] is True
        # password login still works while SSO is blocked
        assert client.post("/api/auth/login",
                           json={"email": "sso.toggle@example.com", "password": "Toggle@2026"}).status_code == 200
        # unblock
        r = client.post(f"/api/auth/users/{uid}/sso-block", headers=admin_headers, json={"blocked": False})
        assert r.status_code == 200 and r.json()["sso_blocked"] is False
    finally:
        db_session.execute(delete(User).where(User.id == user.id))
        db_session.commit()
