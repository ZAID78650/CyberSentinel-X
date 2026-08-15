"""Tests for the campaign intelligence engines: velocity, momentum,
similarity, MITRE coverage, mutation detection and business impact."""
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models.intel import IncidentMitreMapping, MitreTechnique
from app.models.security import Asset, Incident, IncidentEvent, SecurityEvent
from app.services import campaign_intel as ci


def _incident(db, category="Credential Attack", severity="HIGH", src="45.155.205.233"):
    incident = Incident(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title=f"Campaign test {category}",
        severity=severity,
        status="OPEN",
        confidence=0.9,
        risk_score=60.0,
        risk_label="MEDIUM",
        category=category,
        created_by="test",
    )
    db.add(incident)
    db.commit()
    return incident


def _event(db, incident, event_type, minutes=0, anomaly=True, src="45.155.205.233",
           dst="10.0.0.5", asset="SERVER-07", severity="HIGH", user="u-1",
           proto="tcp", extra_meta=None):
    base = datetime.now(timezone.utc) - timedelta(minutes=30)
    meta = {"proto": proto, "sbytes": 1000, "dbytes": 500, **(extra_meta or {})}
    event = SecurityEvent(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        timestamp=base + timedelta(minutes=minutes),
        event_type=event_type,
        severity=severity,
        source_ip=src,
        destination_ip=dst,
        user_id=user,
        device_id="dev-1",
        asset_id=asset,
        source="test",
        metadata_=meta,
        anomaly_score=0.9 if anomaly else 0.1,
        is_anomalous=anomaly,
    )
    db.add(event)
    db.commit()
    db.add(IncidentEvent(incident_id=incident.id, event_id=event.event_id))
    db.commit()
    return event


def _map_techniques(db, incident, tactics):
    """Map one real seeded technique per tactic onto the incident."""
    for tactic in tactics:
        tech = db.scalar(select(MitreTechnique).where(MitreTechnique.tactic == tactic).limit(1))
        if tech is not None:
            db.add(IncidentMitreMapping(incident_id=incident.id, technique_id=tech.technique_id, confidence=0.8))
    db.commit()


def test_attack_velocity_computes_stages_and_band(db_session):
    inc = _incident(db_session, severity="CRITICAL")
    _event(db_session, inc, "PORT_SCAN", minutes=0, severity="LOW")           # Reconnaissance
    _event(db_session, inc, "LOGIN_FAILURE", minutes=3, severity="HIGH")      # Initial Access
    _event(db_session, inc, "SUSPICIOUS_PROCESS", minutes=5, severity="HIGH") # Execution
    _event(db_session, inc, "DATA_EXFILTRATION", minutes=7, severity="CRITICAL")  # Exfiltration
    camp = ci.campaign_from_id(db_session, inc.incident_id)
    assert camp is not None

    v = ci.attack_velocity(db_session, camp)
    assert v["band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert v["attack_velocity"] > 0
    assert v["campaign_escalation_detected"] in (True, False)
    assert "Reconnaissance" in v["stages_observed"]
    assert "Exfiltration" in v["stages_observed"]
    assert all("from" in t and "to" in t and "minutes" in t for t in v["stage_transitions"])
    assert v["evidence"]


def test_attack_velocity_empty_campaign_is_safe(db_session):
    inc = _incident(db_session)
    camp = ci.campaign_from_id(db_session, inc.incident_id)
    v = ci.attack_velocity(db_session, camp)
    assert v["band"] == "LOW"
    assert v["attack_velocity"] == 0.0
    assert v["stages_observed"] == []


def test_campaign_momentum_uses_signal_components(db_session):
    inc = _incident(db_session)
    # slow early phase, bursty late phase with new assets + exfiltration
    for i in range(4):
        _event(db_session, inc, "LOGIN_SUCCESS", minutes=i * 4, anomaly=False, severity="LOW")
    for i in range(8):
        _event(db_session, inc, "DATA_EXFILTRATION", minutes=20 + i, severity="CRITICAL",
               asset=f"SERVER-{10 + i}")
    camp = ci.campaign_from_id(db_session, inc.incident_id)
    m = ci.campaign_momentum(db_session, camp)
    assert 0.0 <= m["momentum"] <= 100.0
    assert m["status"] in {"ESCALATING", "STABLE", "CONTAINED", "INSUFFICIENT_DATA"}
    assert m["new_assets"] >= 0
    assert "components" in m
    assert set(m["components"]) == {"event_rate_change", "new_assets", "anomaly_ratio",
                                    "severity_change", "exfiltration"}


def test_campaign_similarity_is_explainable(db_session):
    a = _incident(db_session, category="Credential Attack")
    b = _incident(db_session, category="Credential Attack")
    for inc in (a, b):
        _event(db_session, inc, "LOGIN_FAILURE", minutes=1, severity="HIGH")
        _event(db_session, inc, "PORT_SCAN", minutes=2, severity="LOW")
    ca = ci.campaign_from_id(db_session, a.incident_id)
    cb = ci.campaign_from_id(db_session, b.incident_id)
    sim = ci.similarity_between(db_session, ca, cb)
    assert 0.0 <= sim["similarity"] <= 100.0
    assert len(sim["components"]) == 5
    assert sim["top_reasons"]

    ranked = ci.similar_campaigns(db_session, a.incident_id, limit=5)
    assert ranked["campaign_id"] == a.incident_id
    assert all(0.0 <= r["similarity"] <= 100.0 for r in ranked["similar"])


def test_mitre_coverage_reports_gaps(db_session):
    inc = _incident(db_session)
    _event(db_session, inc, "LOGIN_FAILURE", minutes=1, severity="HIGH")
    _map_techniques(db_session, inc, ["initial-access", "credential-access"])
    camp = ci.campaign_from_id(db_session, inc.incident_id)
    cov = ci.mitre_coverage(db_session, camp)
    assert 0.0 <= cov["overall_coverage"] <= 100.0
    assert cov["stages"]
    assert isinstance(cov["detection_gaps"], list)
    assert cov["observed_techniques"]


def test_campaign_mutation_flags_behavioral_twins(db_session):
    a = _incident(db_session, category="Brute Force")
    b = _incident(db_session, category="Brute Force")
    _event(db_session, a, "LOGIN_FAILURE", minutes=1, severity="HIGH", src="45.155.205.233")
    _event(db_session, a, "PORT_SCAN", minutes=2, severity="LOW", src="45.155.205.233")
    _event(db_session, b, "LOGIN_FAILURE", minutes=1, severity="HIGH", src="203.0.113.9")
    _event(db_session, b, "PORT_SCAN", minutes=2, severity="LOW", src="203.0.113.9")
    res = ci.campaign_mutation(db_session, a.incident_id)
    assert res["campaign_id"] == a.incident_id
    assert isinstance(res["mutations"], list)
    assert res["note"]


def test_business_impact_qualitative(db_session):
    db_session.add(Asset(name="FIN-DB", asset_type="database", criticality=10))
    db_session.add(Asset(name="SERVER-07", asset_type="server", criticality=5))
    db_session.commit()
    inc = _incident(db_session)
    _event(db_session, inc, "DATA_DOWNLOAD", minutes=1, severity="CRITICAL", asset="FIN-DB", dst="FIN-DB")
    camp = ci.campaign_from_id(db_session, inc.incident_id)
    bi = ci.business_impact(db_session, camp)
    assert bi["impact"] == "HIGH"
    assert "FIN-DB" in bi["critical_assets"]
    assert "FIN-DB" in bi["sensitive_data_stores"]
    assert bi["evidence"]
