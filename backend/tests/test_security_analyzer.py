"""Tests for the MALWARE_GUARD firewall layer and the one-click threat analyzer."""
from app.core.firewall import _load_malware_set


def test_malware_guard_blocks_control_plane_reference(client, admin_headers):
    # A control-plane POST referencing a known malware hash (EICAR) is blocked
    # by the middleware before any route runs.
    r = client.post(
        "/api/security/firewall/test-malware",
        json={"note": "firewall test", "hash": "44d88612fea8a8f36de82e1278abb02f"},
        headers=admin_headers,
    )
    assert r.status_code == 403
    body = r.json()
    assert body.get("layer") == "MALWARE_GUARD"
    assert "44d88612fea8a8f36de82e1278abb02f" in body.get("detail", "")
    assert str("44d88612fea8a8f36de82e1278abb02f") in _load_malware_set()


def test_malware_guard_allows_data_plane(client, admin_headers):
    # The threat-intel search is data plane: referencing the same hash there
    # must not trigger the malware layer's 403.
    r = client.post(
        "/api/threat-intelligence/search",
        json={"query": "44d88612fea8a8f36de82e1278abb02f"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    assert "hits" in r.json()


def test_malware_guard_present_in_firewall_summary(client, admin_headers):
    r = client.get("/api/security/firewall", headers=admin_headers)
    assert r.status_code == 200
    layers = {item["layer"] for item in r.json()["layers"]}
    assert "MALWARE_GUARD" in layers


def test_analyze_known_indicator(client, admin_headers):
    r = client.post("/api/security/analyze", json={"query": "45.155.205.233"}, headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["intel"], "feed IP should produce an intel match"
    assert body["history"]["seen"] is True
    assert body["history"]["count"] >= 0
    assert {"score", "band", "components"} <= set(body["risk"])
    assert body["provenance"]["mode"] == "DATASET"
    assert "firewall" in body


def test_analyze_unknown_indicator_is_honest(client, admin_headers):
    r = client.post("/api/security/analyze", json={"query": "198.51.100.99"}, headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["intel"] == []
    assert "seen" in body["history"]
    assert body["provenance"]["mode"] == "DATASET"
