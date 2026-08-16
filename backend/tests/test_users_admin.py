"""Admin user view + per-account password management tests."""

from sqlalchemy import select

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
