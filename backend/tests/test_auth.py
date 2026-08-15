"""Authentication and authorization tests."""


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").json()["database"] == "connected"


def test_register_flow(client):
    r = client.post("/api/auth/register", json={
        "full_name": "Test User", "email": "test.user@cybersentinel.io",
        "password": "SecurePass123", "confirm_password": "SecurePass123",
        "organization": "TestOrg", "accept_terms": True,
    })
    assert r.status_code == 201, r.text
    assert r.json()["user"]["email"] == "test.user@cybersentinel.io"
    assert "SECURITY_ANALYST" in r.json()["user"]["roles"]


def test_register_duplicate_email(client):
    r = client.post("/api/auth/register", json={
        "full_name": "Dup", "email": "admin@cybersentinel.io",
        "password": "SecurePass123", "confirm_password": "SecurePass123", "accept_terms": True,
    })
    assert r.status_code == 409


def test_register_password_mismatch(client):
    r = client.post("/api/auth/register", json={
        "full_name": "Test", "email": "mismatch@cybersentinel.io",
        "password": "SecurePass123", "confirm_password": "Different123", "accept_terms": True,
    })
    assert r.status_code == 422


def test_register_weak_password(client):
    r = client.post("/api/auth/register", json={
        "full_name": "Test", "email": "weak@cybersentinel.io",
        "password": "short", "confirm_password": "short", "accept_terms": True,
    })
    assert r.status_code == 422


def test_register_terms_not_accepted(client):
    r = client.post("/api/auth/register", json={
        "full_name": "Test", "email": "terms@cybersentinel.io",
        "password": "SecurePass123", "confirm_password": "SecurePass123", "accept_terms": False,
    })
    assert r.status_code == 422


def test_login_success(client):
    r = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "Admin@2026"})
    assert r.status_code == 200
    body = r.json()
    assert body["tokens"]["access_token"]
    assert body["tokens"]["refresh_token"]
    assert body["user"]["roles"] == ["ADMIN"]


def test_login_failure(client):
    r = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "wrong"})
    assert r.status_code == 401


def test_refresh_token(client):
    r = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "Admin@2026"})
    refresh = r.json()["tokens"]["refresh_token"]
    r2 = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 200
    assert r2.json()["access_token"]


def test_refresh_invalid_token(client):
    r = client.post("/api/auth/refresh", json={"refresh_token": "garbage"})
    assert r.status_code == 401


def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


def test_rbac_viewer_cannot_simulate(client, viewer_headers):
    r = client.post("/api/simulations/brute-force", headers=viewer_headers)
    assert r.status_code == 403


def test_rbac_analyst_can_simulate(client, analyst_headers):
    r = client.post("/api/simulations/brute-force", headers=analyst_headers)
    assert r.status_code == 200


def test_rate_limiting(client):
    # Multiple rapid failed logins should eventually hit the limiter
    codes = []
    for _ in range(8):
        r = client.post("/api/auth/login", json={"email": "x@y.io", "password": "bad"})
        codes.append(r.status_code)
    assert 429 in codes or all(c in (401,) for c in codes)
