"""OAuth (SSO) tests: provider status, CSRF state, and the callback flows.

The callback exchanges codes against real provider URLs via httpx — mocked
here so the full find-or-create-user path is exercised without credentials.
"""
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
    def __init__(self, payload):
        self._payload = payload

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
        return _FakeResponse(self.responses.get(("POST", url), {"access_token": "tok"}))

    async def get(self, url, **kwargs):
        if ("GET", url) not in self.responses:
            raise AssertionError(f"unmocked GET {url}")
        return _FakeResponse(self.responses[("GET", url)])


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
    assert q["redirect_uri"] == ["http://localhost:8000/api/auth/oauth/google/callback"]
    assert q["state"] == [state]
    assert q["response_type"] == ["code"]


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
        {"email": "Analyst.Example@gmail.com", "email_verified": True,
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
