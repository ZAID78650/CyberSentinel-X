"""Detection engine, ML anomaly detection, event ingestion, threat intel tests."""
from datetime import datetime, timedelta, timezone

from app.core.database import SessionLocal
from app.ml.anomaly import AnomalyDetector
from app.services.event_service import ingest_batch, ingest_event
from app.schemas.event import EventIngest
from app.threat_intel.adapter import ThreatIntelAdapter


def _ev(event_type, severity="LOW", user="u1", ip="10.1.1.1", minutes=5, **meta):
    return EventIngest(
        event_type=event_type, severity=severity, source_ip=ip, user_id=user,
        device_id="dev-1", source="test",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes),
        metadata=meta,
    )


def test_event_ingestion_normalizes():
    db = SessionLocal()
    try:
        ev = ingest_event(db, _ev("LOGIN_SUCCESS"), source="test")
        assert ev.event_type == "LOGIN_SUCCESS"
        assert ev.severity == "LOW"
        assert ev.event_id.startswith("evt-")
    finally:
        db.close()


def test_invalid_event_type_rejected():
    db = SessionLocal()
    try:
        try:
            ingest_event(db, _ev("NOT_A_REAL_TYPE"))
            assert False, "should have raised"
        except ValueError:
            pass
    finally:
        db.close()


def test_brute_force_rule_fires():
    db = SessionLocal()
    try:
        payloads = [_ev("LOGIN_FAILURE", user="bruteforce.test", ip="103.75.190.12", minutes=20 - i) for i in range(6)]
        events = ingest_batch(db, payloads, source="test")
        flagged = [e for e in events if e.detection_reason and "failed logins" in e.detection_reason]
        assert len(flagged) >= 1
    finally:
        db.close()


def test_malware_rule_fires_and_intel_matches():
    db = SessionLocal()
    try:
        ev = ingest_event(db, _ev("MALWARE_DETECTED", severity="LOW", user="malware.test",
                                  ip="192.168.1.50", malware="RedLine Stealer",
                                  file_hash="b1946ac92492d2347c6235b4d2611184"), source="test")
        assert ev.detection_reason
        assert "Threat intel match" in ev.detection_reason
        assert "Malware detection" in ev.detection_reason
        assert ev.severity == "CRITICAL"
    finally:
        db.close()


def test_anomaly_detector_scores():
    detector = AnomalyDetector()
    events = [
        {"event_type": "LOGIN_SUCCESS", "severity": "LOW", "source_ip": "10.0.0.1", "user_id": "u1",
         "timestamp": datetime.now(timezone.utc)},
        {"event_type": "LOGIN_SUCCESS", "severity": "LOW", "source_ip": "10.0.0.2", "user_id": "u2",
         "timestamp": datetime.now(timezone.utc)},
        {"event_type": "FILE_ACCESS", "severity": "LOW", "source_ip": "10.0.0.3", "user_id": "u3",
         "timestamp": datetime.now(timezone.utc)},
    ] * 6
    detector.fit(events)
    assert detector.is_fitted
    normal = detector.score({"event_type": "LOGIN_SUCCESS", "severity": "LOW",
                             "source_ip": "10.0.0.1", "user_id": "u1",
                             "timestamp": datetime.now(timezone.utc)})
    anomalous = detector.score({"event_type": "DATA_EXFILTRATION", "severity": "CRITICAL",
                                "source_ip": "45.155.205.233", "user_id": "u-x",
                                "timestamp": datetime.now(timezone.utc)})
    assert 0 <= normal <= 1 and 0 <= anomalous <= 1
    assert anomalous > normal


def test_threat_intel_search():
    db = SessionLocal()
    try:
        adapter = ThreatIntelAdapter(db)
        hits = adapter.search("45.155.205.233")
        assert len(hits) >= 1
        assert hits[0]["indicator_type"] == "IP"
        hits2 = adapter.search("Log4Shell")
        assert any(h["value"] == "CVE-2021-44228" for h in hits2)
    finally:
        db.close()


def test_mitre_dataset_present():
    from app.threat_intel.mitre_data import MITRE_TECHNIQUES
    ids = {t["technique_id"] for t in MITRE_TECHNIQUES}
    assert "T1110" in ids and "T1078" in ids and "T1041" in ids
    assert len(MITRE_TECHNIQUES) >= 40


def test_rag_index_and_retrieve():
    from app.rag.rag_service import index_documents, retrieve_context
    db = SessionLocal()
    try:
        count = index_documents(db)
        assert count >= 5
        results = retrieve_context(db, "how to respond to a data exfiltration")
        assert len(results) >= 1
    finally:
        db.close()
