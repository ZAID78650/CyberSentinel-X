"""Tests for Judge Mode, the data pipeline aggregate and intel source status."""
from app.services import judge
from app.services.cache import clear, get_or_build


def test_ttl_cache_get_and_clear():
    calls = {"n": 0}

    def builder():
        calls["n"] += 1
        return calls["n"]

    # Test environment bypasses the cache entirely (always fresh writes).
    clear()
    assert get_or_build("k", 60.0, builder) == 1
    assert get_or_build("k", 60.0, builder) == 2
    clear()


def test_judge_mode_pipeline(db_session):
    res = judge.judge_mode(db_session)
    stages = {s["stage"] for s in res["pipeline"]}
    assert {"EVENTS", "ALERTS", "CAMPAIGNS", "ATTACK DNA", "PREDICTION",
            "BLAST RADIUS", "RESPONSE", "BLOCKCHAIN PROOF"} <= stages
    for s in res["pipeline"]:
        assert "provenance" in s
    m = res["metrics"]
    for key in ("events_processed", "campaigns_detected", "alerts_correlated",
                "prediction_avg_confidence", "evidence_verified", "merkle_roots"):
        assert key in m
    assert res["provenance_note"]


def test_data_pipeline_stages(db_session):
    res = judge.data_pipeline(db_session)
    stage_names = [s["stage"] for s in res["stages"]]
    assert stage_names[0] == "INGEST"
    assert stage_names[-1] == "RETRAIN"
    assert "FEEDBACK" in stage_names
    assert res["separation"]
    assert res["totals"]["events"] >= 0


def test_intel_sources_status(admin_headers, client):
    r = client.get("/api/threat-intelligence/sources/status", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "sources" in body
    assert "live_feed_configured" in body
    assert "indicator_count" in body
    assert body["indicator_count"] > 0
    # Local-only deployment: no live feed configured -> explicit message.
    if not body["live_feed_configured"]:
        assert body["message"] == "NO LIVE THREAT INTELLIGENCE SOURCE CONFIGURED"
        assert body["provenance"]["mode"] == "DATASET"
