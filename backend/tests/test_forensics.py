"""Tests for the forensic layer: evidence ledger integrity, attack DNA, predictions."""
import uuid

from sqlalchemy import delete, func, select

from app.models.forensics import AttackDna, AttackPrediction, EvidenceRecord, LedgerBlock
from app.models.security import Incident, IncidentEvent, SecurityEvent
from app.services.attack_dna import AttackDnaService, cosine_similarity
from app.services.evidence import EvidenceService, compute_record_hash
from app.services.prediction import PredictionService


def _make_incident(db, severity="HIGH", category="Credential Attack"):
    incident = Incident(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title=f"Test incident {category}",
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


def _make_event(db, incident, event_type="LOGIN_FAILURE", anomaly_score=0.9):
    event = SecurityEvent(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        event_type=event_type,
        severity="HIGH",
        source_ip="45.155.205.233",
        destination_ip="10.0.0.5",
        user_id="u-test-1",
        asset_id="a-test-1",
        source="test",
        anomaly_score=anomaly_score,
        is_anomalous=True,
    )
    db.add(event)
    db.add(IncidentEvent(incident_id=incident.id, event_id=event.event_id))
    db.commit()
    return event


def test_evidence_chain_roundtrip_valid(db_session):
    ev = EvidenceService(db_session)
    before = db_session.scalar(select(func.count()).select_from(EvidenceRecord)) or 0
    a = ev.create_evidence(None, "MANUAL", "record a", "desc a", {"k": "v"},
                           data_source="LOCAL", created_by="test")
    b = ev.create_evidence(None, "MANUAL", "record b", "desc b", {"k2": "v2"},
                           data_source="LOCAL", created_by="test")
    db_session.commit()

    assert b.chain_index == a.chain_index + 1  # sequentially hash-linked
    assert b.prev_hash == a.record_hash  # chain of custody link
    assert ev.verify_evidence(a.evidence_id)["valid"]
    assert ev.verify_evidence(b.evidence_id)["valid"]

    report = ev.verify_chain()
    assert report["integrity"] == "VALID"
    assert report["evidence_records"] == before + 2


def test_evidence_tamper_detected_and_restored(db_session):
    ev = EvidenceService(db_session)
    rec = ev.create_evidence(None, "MANUAL", "original title", "original body", {"a": 1},
                             data_source="LOCAL", created_by="test")
    db_session.commit()

    # recomputed hash of stored fields must match stored hash
    stored = db_session.get(EvidenceRecord, rec.id)
    assert compute_record_hash(stored.chain_index, stored.prev_hash,
                               stored.content_hash, stored.created_at) == stored.record_hash

    # mutate the description without updating hashes -> integrity alert
    tamper = ev.tamper_test(rec.evidence_id)
    assert tamper["tamper_detected"]
    assert tamper["status"] == "TAMPERED"

    # chain must now flag the record
    report = ev.verify_chain()
    assert report["integrity"] == "TAMPERED"
    assert rec.evidence_id in report["evidence_tampered"]

    # restoring the original payload brings it back to VALID
    restored = ev.restore(rec.evidence_id)
    assert restored["valid"]
    assert restored["status"] == "VALID"


def test_ledger_mining_and_proof_of_work(db_session):
    # self-contained: start from an empty ledger so block counts are exact
    db_session.execute(delete(LedgerBlock))
    db_session.execute(delete(EvidenceRecord))
    db_session.commit()

    ev = EvidenceService(db_session)
    for i in range(3):
        ev.create_evidence(None, "MANUAL", f"rec {i}", None, {"i": i},
                           data_source="LOCAL", created_by="test")
    block = ev.mine_block(created_by="test")
    db_session.commit()

    assert block.record_count == 3
    assert block.block_hash.startswith("0" * 4)  # proof-of-work difficulty satisfied
    assert block.block_index == 0
    assert block.prev_block_hash == "0" * 64  # genesis anchor

    report = ev.verify_chain()
    assert report["integrity"] == "VALID"
    assert report["ledger_blocks"] == 1
    assert report["evidence_records"] == 3
    assert report["ledger_blocks_valid"] == 1


def test_attack_dna_generation_and_similarity(db_session):
    inc = _make_incident(db_session, severity="HIGH", category="Credential Attack")
    for _ in range(5):
        _make_event(db_session, incident=inc, event_type="LOGIN_FAILURE", anomaly_score=0.9)
    dna = AttackDnaService(db_session).generate(inc)
    db_session.commit()

    assert dna.dna_id.startswith("AD-")
    assert dna.family == "Credential Attack"
    assert "Abnormal authentication" in dna.behaviors
    assert len(dna.fingerprint) == 64
    assert db_session.get(AttackDna, dna.id) is not None

    # idempotent
    dna2 = AttackDnaService(db_session).generate(inc)
    assert dna2.id == dna.id

    # identical fingerprint vectors are ~similar
    v1 = dna.features["vector"]
    assert cosine_similarity(v1, v1) > 0.99
    assert cosine_similarity([], []) == 0.0


def test_prediction_is_labeled_and_has_control(db_session):
    inc = _make_incident(db_session, severity="CRITICAL", category="Exfiltration")
    for _ in range(3):
        _make_event(db_session, incident=inc, event_type="DATA_EXFILTRATION")
    pred = PredictionService(db_session).predict(inc)
    db_session.commit()

    assert pred.is_prediction is True
    assert pred.current_stage == "Exfiltration"
    assert pred.predicted_stage == "Exfiltration"  # terminal stage
    assert pred.probability == 1.0
    assert pred.recommended_control  # prevention guidance present
    assert db_session.get(AttackPrediction, pred.id) is not None
