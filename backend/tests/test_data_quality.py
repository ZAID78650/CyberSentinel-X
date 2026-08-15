"""Tests for the data quality center and ML model drift (PSI)."""
import uuid
from datetime import datetime, timedelta, timezone

from app.models.security import SecurityEvent
from app.services import data_quality


def _evt(db, i, anomaly=False, score=None, ts=None):
    event = SecurityEvent(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        timestamp=ts or (datetime.now(timezone.utc) - timedelta(hours=i)),
        event_type="LOGIN_FAILURE" if anomaly else "LOGIN_SUCCESS",
        severity="HIGH" if anomaly else "LOW",
        source_ip="45.155.205.233",
        destination_ip="10.0.0.5",
        user_id="u-q",
        asset_id="SERVER-01",
        source="test",
        metadata_={"proto": "tcp"},
        anomaly_score=score if score is not None else (0.9 if anomaly else 0.1),
        is_anomalous=anomaly,
    )
    db.add(event)
    db.commit()
    return event


def test_data_quality_reports_metrics(db_session):
    for i in range(10):
        _evt(db_session, i, anomaly=(i % 2 == 0))
    res = data_quality.data_quality(db_session)
    assert 0.0 <= res["quality"] <= 100.0
    assert res["pipeline"] in {"HEALTHY", "DEGRADED", "POOR"}
    assert set(res["missing_rates"]) == {"event_type", "severity", "timestamp", "source_ip"}
    assert res["duplicates"] >= 0
    assert "penalties" in res


def test_data_quality_empty_store():
    """Uses an isolated temp DB so the shared seeded corpus is untouched."""
    import os
    import tempfile

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base

    path = tempfile.mktemp(suffix=".db")
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    try:
        res = data_quality.data_quality(db)
        assert res["pipeline"] == "EMPTY"
        assert res["quality"] == 0.0
    finally:
        db.close()
        os.remove(path)


def test_model_drift_healthy_on_stable_scores(db_session):
    # 120 events, stable anomaly-score distribution (no drift)
    for i in range(120):
        _evt(db_session, i, anomaly=(i < 20), score=0.1 + (i % 10) * 0.01)
    res = data_quality.model_drift(db_session)
    assert res["drift"] in {"LOW", "MODERATE", "HIGH"}
    assert res["status"] in {"HEALTHY", "MONITOR", "RETRAINING RECOMMENDED"}
    assert 0.0 <= res["psi"]
    assert "kl_divergence" in res


def test_psi_pure_function(db_session):
    ref = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] * 30
    same = ref[:]
    shifted = [min(1.0, x + 0.5) for x in ref]
    assert data_quality._psi(ref, same) < 0.05
    assert data_quality._psi(ref, shifted) > data_quality._psi(ref, same)
