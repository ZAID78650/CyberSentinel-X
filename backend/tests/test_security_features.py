"""Tests for detection accuracy, firewall layers, and OAuth endpoints."""


def test_detection_accuracy_is_measured_and_high():
    from app.ml.evaluate import run_evaluation
    res = run_evaluation()
    assert res["total_events"] > 100
    assert res["recall"] >= 95.0, f"recall too low: {res}"
    assert res["accuracy"] >= 90.0, f"accuracy too low: {res}"
    assert res["true_positives"] >= 50
    assert res["true_negatives"] > res["false_positives"]


def test_firewall_stats_endpoint(client, admin_headers):
    r = client.get("/api/security/firewall", headers=admin_headers)
    assert r.status_code == 200, r.text
    data = r.json()
    layers = {lyr["layer"]: lyr for lyr in data["layers"]}
    for key in ("REQUEST_ID", "BODY_LIMIT", "WAF_PAYLOAD", "SECURITY_HDR", "RATE_LIMIT", "IP_WATCH", "BRUTE_GUARD"):
        assert key in layers, f"missing layer {key}"
    assert all(lyr["status"] == "ACTIVE" for lyr in data["layers"])


def test_oauth_providers_unconfigured(client):
    r = client.get("/api/auth/oauth/providers")
    assert r.status_code == 200, r.text
    names = {p["provider"] for p in r.json()["providers"]}
    assert {"google", "github"} <= names


def test_oauth_authorize_graceful(client):
    r = client.get("/api/auth/oauth/google/authorize")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is False  # no credentials in test env
    assert "not configured" in body["message"].lower()


def test_oauth_unknown_provider(client):
    r = client.get("/api/auth/oauth/unknown/authorize")
    assert r.status_code == 404


def test_waf_blocks_sqli(client, admin_headers):
    # The WAF middleware rejects SQLi payloads before they reach the handler
    r = client.post(
        "/api/events",
        json={"event_type": "LOGIN_SUCCESS", "severity": "LOW", "user_id": "' OR 1=1 --"},
        headers=admin_headers,
    )
    assert r.status_code == 400
    assert "WAF" in r.json()["detail"]


def test_assets_and_playbooks(client, admin_headers):
    r = client.get("/api/security/assets", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["total"] >= 1

    r = client.get("/api/security/playbooks", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["total"] >= 1
