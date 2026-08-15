"""Tests for resilience services: what-if simulator, live scenario replay,
cyber resilience score, and compliance center."""
from app.services.resilience import (
    compliance_posture,
    cyber_resilience,
    run_live_scenario,
    simulate_attack,
)
from app.models.security import SecurityEvent
from sqlalchemy import select



def test_simulate_attack_labels_simulation(db_session):
    out = simulate_attack(db_session, "ast-app-server", starting_stage="Initial Access")
    assert out["simulation"] is True
    assert out["risk_before"] > out["risk_after"]
    assert out["affected_assets_before"] >= out["affected_assets_after"]
    assert len(out["kill_chain"]) >= 1
    assert all(p["state"] == "SIMULATED" for p in out["kill_chain"])


def test_simulate_attack_unknown_asset_raises(db_session):
    import pytest
    with pytest.raises(ValueError):
        simulate_attack(db_session, "no-such-asset-xyz")


def test_live_scenario_replay_marks_simulated_and_detects(db_session):
    """Replaying the kill chain creates SIMULATED events that the real
    detection engine flags, producing an alert + incident."""
    out = run_live_scenario(db_session, "ast-app-server", "Initial Access", actor="test")
    assert out["simulation"] is True
    assert out["events_ingested"] >= 10
    assert out["anomalous_count"] >= 3
    assert out["incident_id"]
    assert out["pipeline"] == "started"
    assert out["chain"][0] == "Initial Access"

    # Every replayed event must carry the SIMULATED source label
    simulated = list(db_session.scalars(select(SecurityEvent).where(
        SecurityEvent.source == "SIMULATED"
    )).all())
    replay_events = [e for e in simulated if e.asset_id == "ast-app-server"]
    assert len(replay_events) == out["events_ingested"]
    assert all(e.user_id and e.user_id.startswith("sim-") for e in replay_events)
    assert any(e.is_anomalous for e in replay_events)


def test_cyber_resilience_is_explainable(db_session):
    out = cyber_resilience(db_session)
    assert 0 <= out["resilience_score"] <= 100
    assert out["label"] in ("STRONG", "MODERATE", "WEAK")
    assert len(out["factors"]) == 6
    assert abs(sum(f["weight"] for f in out["factors"]) - 1.0) < 0.01
    assert out["explanation"]


def test_compliance_posture_structure(db_session):
    out = compliance_posture(db_session)
    assert 0 <= out["overall_posture"] <= 100
    names = [f["framework"] for f in out["frameworks"]]
    assert "NIST CSF" in names and "CIS Controls" in names and "ISO 27001" in names
    for f in out["frameworks"]:
        assert 0 <= f["posture"] <= 100
        assert f["controls_covered"] <= f["controls_total"]
