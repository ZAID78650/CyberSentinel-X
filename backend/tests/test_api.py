"""API endpoint tests using the TestClient."""


def test_dashboard_summary(client, admin_headers):
    r = client.get("/api/dashboard/summary", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body["kpis"]) == 6
    assert isinstance(body["recent_events"], list)
    assert len(body["recent_events"]) >= 1
    assert isinstance(body["agent_statuses"], list)


def test_events_pagination(client, admin_headers):
    r = client.get("/api/events", headers=admin_headers, params={"page": 1, "page_size": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 1
    assert len(body["items"]) <= 10
    assert body["pages"] >= 1


def test_events_filtering(client, admin_headers):
    r = client.get("/api/events", headers=admin_headers, params={"event_type": "LOGIN_FAILURE", "page_size": 5})
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["event_type"] == "LOGIN_FAILURE"


def test_alerts_and_incidents_list(client, admin_headers):
    r = client.get("/api/alerts", headers=admin_headers)
    assert r.status_code == 200
    assert isinstance(r.json()["items"], list)
    r = client.get("/api/incidents", headers=admin_headers)
    assert r.status_code == 200
    assert isinstance(r.json()["items"], list)


def test_threat_intel_mitre(client, admin_headers):
    r = client.get("/api/threat-intelligence/mitre", headers=admin_headers)
    assert r.status_code == 200
    assert len(r.json()) >= 40


def test_analytics(client, admin_headers):
    r = client.get("/api/analytics", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["events_total"] >= 1
    assert isinstance(body["events_by_type"], dict)


def test_actions_log(client, admin_headers):
    r = client.get("/api/actions-log", headers=admin_headers, params={"page_size": 5})
    assert r.status_code == 200
    assert isinstance(r.json()["items"], list)


def test_security_headers(client):
    r = client.get("/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_unknown_route_404(client, admin_headers):
    assert client.get("/api/does-not-exist", headers=admin_headers).status_code == 404
