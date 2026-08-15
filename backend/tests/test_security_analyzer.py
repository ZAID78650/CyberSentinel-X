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
    # The block must be recorded in the firewall block log.
    log = client.get("/api/security/firewall/blocks", headers=admin_headers).json()["blocks"]
    assert any(
        b["layer"] == "MALWARE_GUARD" and b["indicator"] == "44d88612fea8a8f36de82e1278abb02f"
        for b in log
    )


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


def test_firewall_block_log_endpoint_shape(client, admin_headers):
    r = client.get("/api/security/firewall/blocks", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "blocks" in body
    for b in body["blocks"]:
        assert {"ts", "layer", "method", "path", "source_ip", "detail"} <= set(b)
        assert b["layer"] in {"IP_WATCH", "BODY_LIMIT", "WAF_PAYLOAD", "RATE_LIMIT",
                               "MALWARE_GUARD", "BRUTE_GUARD"}


def test_playbook_what_if_simulation(client, admin_headers):
    docs = client.get("/api/security/playbooks", params={"page_size": 20}, headers=admin_headers).json()
    assert docs["items"], "seeded knowledge base should contain playbook documents"
    doc = docs["items"][0]
    r = client.post(f"/api/security/playbooks/{doc['id']}/simulate", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["simulation"] is True
    assert body["playbook"]["id"] == doc["id"]
    assert body["provenance"]["mode"] == "SIMULATED"
    assert body["asset_count"] == len(body["affected_assets"])
    for a in body["affected_assets"]:
        assert a["exposure_after"] <= a["exposure"]
        assert "exposure" in a and "reduction_pct" in a
    assert body["exposure_after"] <= body["exposure_before"]
    assert "SIMULATION" in body["note"].upper()


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
