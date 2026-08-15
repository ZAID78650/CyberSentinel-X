"""Tests for the UNSW-NB15 dataset ingestion pipeline (mapping + detection)."""
from app.services.unsw import map_row, score_and_annotate


def _row(attack_cat: str = "Normal", label: int = 0) -> dict:
    return {
        "attack_cat": attack_cat,
        "label": label,
        "proto": "tcp",
        "service": "-",
        "state": "FIN",
        "sbytes": 258,
        "dbytes": 172,
        "spkts": 6,
        "dpkts": 4,
        "rate": 74.08,
        "sttl": 252,
        "dttl": 254,
        "sload": 14158.9,
        "dload": 8495.3,
    }


def test_normal_row_maps_to_benign_event():
    ev = map_row("test", 1, 1, 100, _row())
    assert ev["event_id"] == "unsw-test-1"
    assert ev["source"] == "unsw-bulk"
    assert ev["severity"] == "LOW"
    assert ev["metadata"]["attack_cat"] == "Normal"
    assert ev["metadata"]["label"] == 0
    assert ev["metadata"]["sbytes"] == 258.0
    assert ev["metadata"]["proto"] == "tcp"


def test_attack_row_maps_to_high_severity_event():
    ev = map_row("train", 7, 7, 100, _row(attack_cat="Exploits", label=1))
    assert ev["event_id"] == "unsw-train-7"
    assert ev["event_type"] == "PRIVILEGE_ESCALATION"
    assert ev["severity"] == "CRITICAL"
    assert ev["metadata"]["attack_cat"] == "Exploits"
    assert ev["source_ip"].startswith("45.")  # hostile external source


def test_unknown_attack_family_degrades_safely():
    ev = map_row("test", 3, 3, 100, _row(attack_cat="NovelThreat", label=1))
    assert ev["event_type"] == "SUSPICIOUS_NETWORK_CONNECTION"
    assert ev["severity"] == "MEDIUM"


def test_scoring_flags_attacks_anomalous():
    events = [
        map_row("test", i, i, 40, _row(attack_cat="Backdoor", label=1)) for i in range(1, 21)
    ] + [
        map_row("test", i, i, 40, _row()) for i in range(21, 41)
    ]
    scored = score_and_annotate(events, fit_sample=40)
    attacks = [e for e in scored if e["is_anomalous"]]
    assert len(attacks) >= 20  # all labeled attacks flagged
    for e in scored:
        assert 0.0 <= e["anomaly_score"] <= 1.0
    # labeled attacks carry a detection reason
    backdoor = [e for e in scored if e["metadata"]["attack_cat"] == "Backdoor"][0]
    assert backdoor["detection_reason"] and "Backdoor" in backdoor["detection_reason"]


def test_timestamps_span_to_now():
    ev_first = map_row("test", 1, 1, 1000, _row())
    ev_last = map_row("train", 900, 1000, 1000, _row())
    assert ev_first["timestamp"] < ev_last["timestamp"]


def test_reingest_is_idempotent(db_session, tmp_path):
    """Re-ingesting the same dataset must skip existing rows instead of
    aborting on the unique event_id constraint (regression: re-runs of the
    upload->ingest flow crashed with a UniqueViolation)."""
    import csv

    from app.models.security import SecurityEvent
    from app.services.unsw import ingest_unsw_files

    header = [
        "id", "attack_cat", "label", "proto", "service", "state",
        "sbytes", "dbytes", "rate", "spkts", "dpkts", "sttl", "dttl",
        "sload", "dload",
    ]
    rows = [
        ["1", "Backdoor", "1", "tcp", "-", "FIN", "258", "172", "74.08", "6", "4", "252", "254", "14158.9", "8495.3"],
        ["2", "Normal", "0", "udp", "-", "INT", "100", "80", "12.5", "2", "2", "250", "250", "10", "10"],
    ]
    path = tmp_path / "reingest.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

    first = ingest_unsw_files([str(path)], limit=0, clear_existing=False)
    assert first.get("inserted") == 2, first
    before = db_session.query(SecurityEvent).count()

    second = ingest_unsw_files([str(path)], limit=0, clear_existing=False)
    assert "error" not in second, second
    assert second.get("inserted") == 0, second
    # No duplicate events, and no duplicate auto-detected alerts/incidents.
    assert db_session.query(SecurityEvent).count() == before
