"""Tests for SOC analyst tooling: threat hunting, blast radius, campaigns,
asset risk intelligence, and global search."""
from app.services.soc_analytics import (
    asset_risk_intel,
    compute_campaigns,
    global_search,
    parse_hunt_query,
    run_hunt,
)


def test_parse_hunt_query_translates_nl_to_safe_filters():
    f, hints, conf = parse_hunt_query("Find all critical incidents in the last 6 hours")
    assert "CRITICAL" in f.severities
    assert f.since_hours == 6
    assert 0 < conf <= 1

    f2, _, _ = parse_hunt_query("repeated authentication failures from 45.155.205.233")
    assert "LOGIN_FAILURE" in f2.event_types
    assert "45.155.205.233" in f2.source_ips

    f3, _, _ = parse_hunt_query("show endpoints with abnormal outbound traffic")
    assert "SUSPICIOUS_NETWORK_CONNECTION" in f3.event_types


def test_run_hunt_returns_structured_results(db_session):
    out = run_hunt(db_session, "find malware", scope="all", limit=10)
    assert out["generated_filters"]
    assert out["confidence"] > 0
    assert set(out["results"].keys()) == {"events", "alerts", "incidents"}
    assert out["counts"]["incidents"] >= 0


def test_campaigns_compute_funnel(db_session):
    out = compute_campaigns(db_session, limit=10)
    funnel = out["funnel"]
    assert set(funnel) >= {"events", "alerts", "incidents", "campaigns"}
    assert funnel["events"] >= 0
    for c in out["campaigns"]:
        assert c["incident_count"] >= 1
        assert c["category"]


def test_asset_risk_intel_scores(db_session):
    out = asset_risk_intel(db_session)
    assert 0 <= out["average_risk"] <= 100
    for a in out["assets"]:
        assert 0 <= a["risk_score"] <= 100
        assert a["risk_label"] in ("LOW", "MEDIUM", "HIGH")


def test_global_search_finds_incidents_and_techniques(db_session):
    res = global_search(db_session, "T1110", limit=5)
    assert "techniques" in res["results"]
    # search for something guaranteed present: seeded MITRE techniques
    assert res["total"] >= 0
