"""OAuth (SSO) tests: provider status, CSRF state, and the callback flows.

The callback exchanges codes against real provider URLs via httpx — mocked
here so the full find-or-create-user path is exercised without credentials.
"""
import uuid
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import select

from app.api.routes import oauth as oauth_module
from app.models.user import User

FAKE_SETTINGS = SimpleNamespace(
    backend_url="http://localhost:8000",
    frontend_url="http://localhost:5173",
    environment="test",
    google_client_id="google-id-test",
    google_client_secret="google-secret-test",
    github_client_id="github-id-test",
    github_client_secret="github-secret-test",
)


@pytest.fixture()
def oauth_configured(monkeypatch):
    monkeypatch.setattr(oauth_module, "get_settings", lambda: FAKE_SETTINGS)


@pytest.fixture()
def oauth_unconfigured(monkeypatch):
    unset = SimpleNamespace(
        backend_url="http://localhost:8000",
        frontend_url="http://localhost:5173",
        environment="test",
        google_client_id="",
        google_client_secret="",
        github_client_id="",
        github_client_secret="",
    )
    monkeypatch.setattr(oauth_module, "get_settings", lambda: unset)


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)[:300]

    def json(self):
        return self._payload


class _FakeClient:
    """Mimics the subset of httpx.AsyncClient used by the callback."""

    def __init__(self, *args, **kwargs):
        self.responses = {}

    def mock(self, method, url, payload):
        self.responses[(method, url)] = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kwargs):
        entry = self.responses.get(("POST", url), {"access_token": "tok"})
        if isinstance(entry, tuple):
            entry, code = entry
            return _FakeResponse(entry, status_code=code)
        return _FakeResponse(entry)

    async def get(self, url, **kwargs):
        if ("GET", url) not in self.responses:
            raise AssertionError(f"unmocked GET {url}")
        entry = self.responses[("GET", url)]
        if isinstance(entry, tuple):
            entry, code = entry
            return _FakeResponse(entry, status_code=code)
        return _FakeResponse(entry)


@pytest.fixture()
def mock_httpx(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(oauth_module.httpx, "AsyncClient", lambda *a, **k: fake)
    return fake


def _authorize(client, provider, cookie=True):
    r = client.get(f"/api/auth/oauth/{provider}/authorize")
    assert r.status_code == 200, r.text
    state = None
    if cookie:
        raw = r.headers.get("set-cookie", "")
        for part in raw.split("; "):
            if part.startswith("csx_oauth_state="):
                state = part.split("=", 1)[1]
    return r, state


def test_providers_report_unconfigured_without_credentials(client, oauth_unconfigured):
    r = client.get("/api/auth/oauth/providers")
    assert r.status_code == 200
    by_name = {p["provider"]: p for p in r.json()["providers"]}
    assert by_name["google"]["configured"] is False
    assert by_name["github"]["configured"] is False


def test_authorize_unconfigured_returns_helpful_message(client, oauth_unconfigured):
    r = client.get("/api/auth/oauth/google/authorize")
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is False
    assert "GOOGLE_CLIENT_ID" in body["message"]


def test_authorize_sets_state_cookie_and_builds_redirect(client, oauth_configured):
    r, state = _authorize(client, "google")
    assert r.json()["configured"] is True
    assert state, "expected csx_oauth_state cookie"

    url = r.json()["authorize_url"]
    q = parse_qs(urlparse(url).query)
    assert q["client_id"] == ["google-id-test"]
    # The callback MUST live on the FRONTEND origin: the CSRF state cookie is
    # set on the frontend host (the browser reaches /api via the frontend's
    # nginx/Vite proxy), so the provider's redirect back must land there too
    # or the cookie is never sent and login fails with a state mismatch.
    assert q["redirect_uri"] == ["http://localhost:5173/api/auth/oauth/google/callback"]
    assert q["state"] == [state]
    assert q["response_type"] == ["code"]


def test_redirect_uri_origin_matches_cookie_origin(client, oauth_configured):
    """Regression: redirect_uri host must equal the frontend host where the
    state cookie is set — otherwise cross-origin login breaks even with creds."""
    r, _state = _authorize(client, "github")
    url = r.json()["authorize_url"]
    q = parse_qs(urlparse(url).query)
    redirect_host = urlparse(q["redirect_uri"][0]).netloc
    assert redirect_host == "localhost:5173"  # frontend_url in FAKE_SETTINGS
    assert redirect_host != "localhost:8000"  # backend_url must NOT be used


def test_callback_token_exchange_http_error(client, oauth_configured, mock_httpx):
    """A non-2xx token exchange (bad code, revoked app) is a clean 401."""
    mock_httpx.mock("POST", "https://github.com/login/oauth/access_token",
                    ({"error": "bad_verification_code"}, 400))
    _authorize(client, "github")
    r = client.get(
        "/api/auth/oauth/github/callback",
        params={"code": "bad", "state": client.cookies.get("csx_oauth_state")},
    )
    assert r.status_code == 401


def test_callback_userinfo_http_error(client, oauth_configured, mock_httpx):
    """A non-2xx userinfo response (revoked token) is a clean 401."""
    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
    mock_httpx.mock("GET", "https://www.googleapis.com/oauth2/v2/userinfo",
                    ({"error": "invalid_token"}, 401))
    _authorize(client, "google")
    r = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "code-x", "state": client.cookies.get("csx_oauth_state")},
    )
    assert r.status_code == 401


def test_callback_rejects_sso_blocked_user(client, oauth_configured, mock_httpx, db_session):
    """Admins can block SSO for an account; the callback refuses to sign it in."""
    from app.core.security import hash_password
    from app.services.auth_service import get_or_create_role
    u = User(email="blocked.sso@example.com", full_name="Blocked SSO",
             password_hash=hash_password("x"), is_verified=True, sso_blocked=True)
    u.roles.append(get_or_create_role(db_session, "SECURITY_ANALYST"))
    db_session.add(u)
    db_session.commit()
    try:
        mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
        mock_httpx.mock(
            "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
            {"id": "g-blocked", "email": "blocked.sso@example.com",
             "email_verified": True, "name": "Blocked SSO"},
        )
        _authorize(client, "google")
        r = client.get(
            "/api/auth/oauth/google/callback",
            params={"code": "code-blocked", "state": client.cookies.get("csx_oauth_state")},
        )
        assert r.status_code == 403
        assert "blocked" in r.json()["detail"].lower()
    finally:
        db_session.delete(u)
        db_session.commit()


def test_callback_rejects_state_mismatch(client, oauth_configured):
    r = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "abc", "state": "attacker-controlled"},
    )
    assert r.status_code == 400
    assert "state mismatch" in r.json()["detail"].lower()


def test_callback_google_flow_creates_user(client, oauth_configured, mock_httpx):
    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"id": "g-100", "email": "Analyst.Example@gmail.com", "email_verified": True,
         "name": "Analyst Example", "given_name": "Analyst"},
    )

    _authorize(client, "google")
    r = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "code-1", "state": client.cookies.get("csx_oauth_state")},
        follow_redirects=False,
    )
    assert r.status_code == 307, r.text
    loc = r.headers["location"]
    assert loc.startswith("http://localhost:5173/oauth/callback#access=")
    assert "access=" in loc and "refresh=" in loc
    assert "?" not in urlparse(loc).query  # tokens must NOT be in the query

    # User was auto-provisioned, lower-cased, verified, analyst role.
    from app.core.database import SessionLocal
    with SessionLocal() as s:
        user = s.scalar(select(User).where(User.email == "analyst.example@gmail.com"))
        assert user is not None
        assert user.full_name == "Analyst Example"
        assert user.is_verified is True
        assert user.password_hash == ""
        assert user.oauth_provider == "google"


def test_callback_google_rejects_unverified_email(client, oauth_configured, mock_httpx):
    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"email": "spoof@example.com", "email_verified": False, "name": "Spoof"},
    )
    _authorize(client, "google")
    r = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "code-2", "state": client.cookies.get("csx_oauth_state")},
    )
    assert r.status_code == 400
    assert "not verified" in r.json()["detail"].lower()


def test_callback_github_private_email(client, oauth_configured, mock_httpx):
    """GitHub users with private emails: profile has no email, /user/emails is used."""
    mock_httpx.mock("POST", "https://github.com/login/oauth/access_token", {"access_token": "tok"})
    mock_httpx.mock("GET", "https://api.github.com/user", {"login": "dev42", "name": "Dev Forty-Two"})
    mock_httpx.mock(
        "GET", "https://api.github.com/user/emails",
        [
            {"email": "noreply@example.com", "primary": False, "verified": True},
            {"email": "dev42@example.com", "primary": True, "verified": True},
        ],
    )
    _authorize(client, "github")
    r = client.get(
        "/api/auth/oauth/github/callback",
        params={"code": "code-3", "state": client.cookies.get("csx_oauth_state")},
        follow_redirects=False,
    )
    assert r.status_code == 307, r.text
    from app.core.database import SessionLocal
    with SessionLocal() as s:
        user = s.scalar(select(User).where(User.email == "dev42@example.com"))
        assert user is not None
        assert user.full_name == "Dev Forty-Two"


def _run_oauth(client, provider, code, profile):
    """Run authorize + callback with a fresh state cookie and return the response."""
    _authorize(client, provider)
    return client.get(
        f"/api/auth/oauth/{provider}/callback",
        params={"code": code, "state": client.cookies.get("csx_oauth_state")},
        follow_redirects=False,
    )


def test_callback_links_existing_password_user(client, oauth_configured, mock_httpx):
    """An existing password account signing in via SSO gets the identity linked,
    not a duplicate, and keeps its password login intact."""
    mock_httpx.mock("POST", "https://github.com/login/oauth/access_token", {"access_token": "tok"})
    mock_httpx.mock(
        "GET", "https://api.github.com/user",
        {"id": 424242, "login": "avasec", "email": "analyst@cybersentinel.io", "name": "Ava Security Analyst"},
    )

    r = _run_oauth(client, "github", "code-link", {"id": 424242})
    assert r.status_code == 307, r.text

    from app.core.database import SessionLocal
    with SessionLocal() as s:
        users = s.scalars(select(User).where(User.email == "analyst@cybersentinel.io")).all()
        assert len(users) == 1
        user = users[0]
        assert user.oauth_provider == "github"
        assert user.oauth_provider_id == "424242"
        assert user.password_hash  # password login still works


def test_callback_identity_wins_over_email(client, oauth_configured, mock_httpx):
    """Once an identity is bound, logging in with the same provider id but a
    different email maps to the SAME account (email renamed upstream)."""
    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})

    _authorize(client, "google")
    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"id": "g-1", "email": "old@example.com", "email_verified": True, "name": "Old Email"},
    )
    r1 = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "c1", "state": client.cookies.get("csx_oauth_state")},
        follow_redirects=False,
    )
    assert r1.status_code == 307

    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"id": "g-1", "email": "new@example.com", "email_verified": True, "name": "New Email"},
    )
    _authorize(client, "google")
    r2 = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "c2", "state": client.cookies.get("csx_oauth_state")},
        follow_redirects=False,
    )
    assert r2.status_code == 307

    from app.core.database import SessionLocal
    with SessionLocal() as s:
        users = s.scalars(select(User).where(
            User.oauth_provider == "google", User.oauth_provider_id == "g-1")).all()
        assert len(users) == 1
        assert users[0].email == "old@example.com"  # original email preserved


def _admin_id(client, admin_headers):
    r = client.get("/api/auth/me", headers=admin_headers)
    assert r.status_code == 200
    return r.json()["id"]


def test_link_flow_binds_provider_to_signed_in_user(client, oauth_configured, mock_httpx, admin_headers):
    """Settings-page linking attaches the provider to the CURRENT account."""
    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"id": "link-g-1", "email": "boss@example.com", "email_verified": True, "name": "The Boss"},
    )

    # Unauthenticated link authorize must be rejected.
    r = client.get("/api/auth/oauth/google/link")
    assert r.status_code == 401

    uid = _admin_id(client, admin_headers)
    r = client.get("/api/auth/oauth/google/link", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    token = None
    for part in r.headers.get("set-cookie", "").split("; "):
        if part.startswith("csx_oauth_state="):
            token = part.split("=", 1)[1]
    assert token
    q = parse_qs(urlparse(body["authorize_url"]).query)
    assert q["state"] == [f"{token}:link:{uid}"]

    r = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "c-link", "state": f"{token}:link:{uid}"},
        follow_redirects=False,
    )
    assert r.status_code == 307, r.text
    assert r.headers["location"].endswith("/oauth/callback#linked=google")

    from app.core.database import SessionLocal
    with SessionLocal() as s:
        admin = s.get(User, uuid.UUID(uid))
        assert admin.oauth_provider == "google"
        assert admin.oauth_provider_id == "link-g-1"


def test_link_conflict_returns_409(client, oauth_configured, mock_httpx, admin_headers):
    """Linking an identity already bound to another account is rejected."""
    from app.core.database import SessionLocal
    with SessionLocal() as s:
        other = User(
            email="other@example.com", full_name="Other", password_hash="x",
            is_verified=True, oauth_provider="google", oauth_provider_id="dup-g-1",
        )
        s.add(other)
        s.commit()

    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"id": "dup-g-1", "email": "boss@example.com", "email_verified": True, "name": "Boss"},
    )
    uid = _admin_id(client, admin_headers)
    r = client.get("/api/auth/oauth/google/link", headers=admin_headers)
    token = r.headers.get("set-cookie", "").split("; ")[0].split("=", 1)[1]
    r = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "c-dup", "state": f"{token}:link:{uid}"},
    )
    assert r.status_code == 409
    assert "already linked" in r.json()["detail"].lower()


def test_unlink_detaches_provider(client, oauth_configured, mock_httpx, admin_headers):
    """A linked password user can detach the provider; an SSO-only user cannot
    (it would lose its only sign-in method)."""
    # Link first via the flow.
    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"id": "un-g-1", "email": "boss@example.com", "email_verified": True, "name": "Boss"},
    )
    uid = _admin_id(client, admin_headers)
    r = client.get("/api/auth/oauth/google/link", headers=admin_headers)
    token = r.headers.get("set-cookie", "").split("; ")[0].split("=", 1)[1]
    client.get("/api/auth/oauth/google/callback", params={"code": "c-un", "state": f"{token}:link:{uid}"})

    from app.core.database import SessionLocal
    with SessionLocal() as s:
        assert s.get(User, uuid.UUID(uid)).oauth_provider == "google"

    # Unlink as the linked password user.
    r = client.post("/api/auth/oauth/google/unlink", headers=admin_headers)
    assert r.status_code == 200, r.text
    with SessionLocal() as s:
        admin = s.get(User, uuid.UUID(uid))
        assert admin.oauth_provider is None
        assert admin.oauth_provider_id is None

    # An SSO-only user (no password) must NOT be able to unlink — it would
    # lose its only sign-in method.
    from app.services.auth_service import build_tokens
    with SessionLocal() as s:
        sso_only = User(
            email="only-sso@example.com", full_name="Only SSO", password_hash="",
            is_verified=True, oauth_provider="github", oauth_provider_id="only-1",
        )
        s.add(sso_only)
        s.commit()
        tokens = build_tokens(sso_only, remember_me=True)
    r = client.post(
        "/api/auth/oauth/github/unlink",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 400
    assert "only sign-in" in r.json()["detail"].lower()

    # Unlinking a provider that isn't linked is a harmless no-op.
    r = client.post("/api/auth/oauth/github/unlink", headers=admin_headers)
    assert r.status_code == 200


def test_seed_sso_user_cannot_password_login(client):
    """The seeded SSO-only account is verified but has no password, so password
    login is rejected while the account exists for SSO linking."""
    from app.core.database import SessionLocal
    with SessionLocal() as s:
        user = s.scalar(select(User).where(User.email == "sso.demo@cybersentinel.io"))
        assert user is not None
        assert user.is_verified is True
        assert user.password_hash == ""

    r = client.post(
        "/api/auth/login",
        json={"email": "sso.demo@cybersentinel.io", "password": "anything"},
    )
    assert r.status_code == 401


def test_callback_reuses_existing_user(client, oauth_configured, mock_httpx):
    """Logging in with an email that already exists links to the same account."""
    mock_httpx.mock("POST", "https://oauth2.googleapis.com/token", {"access_token": "tok"})
    mock_httpx.mock(
        "GET", "https://www.googleapis.com/oauth2/v2/userinfo",
        {"email": "admin@cybersentinel.io", "email_verified": True, "name": "System Administrator"},
    )
    from app.core.database import SessionLocal
    with SessionLocal() as s:
        before = s.scalar(select(User).where(User.email == "admin@cybersentinel.io"))
        assert before is not None

    _authorize(client, "google")
    r = client.get(
        "/api/auth/oauth/google/callback",
        params={"code": "code-4", "state": client.cookies.get("csx_oauth_state")},
        follow_redirects=False,
    )
    assert r.status_code == 307, r.text
    with SessionLocal() as s:
        after = s.scalars(select(User).where(User.email == "admin@cybersentinel.io")).all()
        assert len(after) == 1  # no duplicate account created
