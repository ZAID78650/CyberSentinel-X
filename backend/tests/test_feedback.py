"""Tests for the analyst feedback loop (Feature 16)."""
import uuid

from sqlalchemy import func, select

from app.models.feedback import AnalystFeedback, CorrelationSetting
from app.models.security import Alert
from app.services import feedback
from app.services.feedback import BASE_DETECTION_FLOOR


def _any_alert(db):
    return db.scalar(select(Alert).limit(1))


def test_submit_feedback_creates_label(db_session, admin_headers, client):
    alert = _any_alert(db_session)
    assert alert is not None

    r = client.post(
        f"/api/alerts/{alert.id}/feedback",
        json={"label": "TRUE_POSITIVE", "note": "matches known brute-force pattern"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["label"] == "TRUE_POSITIVE"
    assert body["analyst"]

    count = db_session.scalar(
        select(func.count()).select_from(AnalystFeedback).where(AnalystFeedback.alert_id == alert.id)
    )
    assert count == 1


def test_relabel_replaces_previous(db_session, admin_headers, client):
    alert = _any_alert(db_session)
    client.post(f"/api/alerts/{alert.id}/feedback", json={"label": "TRUE_POSITIVE"}, headers=admin_headers)
    r = client.post(f"/api/alerts/{alert.id}/feedback", json={"label": "FALSE_POSITIVE"}, headers=admin_headers)
    assert r.status_code == 200
    count = db_session.scalar(
        select(func.count()).select_from(AnalystFeedback).where(AnalystFeedback.alert_id == alert.id)
    )
    assert count == 1
    row = db_session.scalar(
        select(AnalystFeedback).where(AnalystFeedback.alert_id == alert.id, AnalystFeedback.label == "FALSE_POSITIVE")
    )
    assert row is not None


def test_invalid_label_rejected(db_session, admin_headers, client):
    alert = _any_alert(db_session)
    r = client.post(f"/api/alerts/{alert.id}/feedback", json={"label": "MAYBE"}, headers=admin_headers)
    assert r.status_code == 400


def test_feedback_stats_shape(db_session, admin_headers, client):
    r = client.get("/api/analytics/feedback-stats", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    for key in ("signals_before_correlation", "alerts_after_correlation", "label_counts",
                "false_positive_rate", "precision", "provenance"):
        assert key in body
    assert body["provenance"]["mode"] == "ANALYST FEEDBACK"
    assert sum(body["label_counts"].values()) >= 1  # labels set by the tests above


def _new_alert(db, category="PORT_SCAN"):
    alert = Alert(
        alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
        title=f"{category} test", severity="MEDIUM", status="OPEN",
        category=category, confidence=0.7, source_event_ids=[],
    )
    db.add(alert)
    db.commit()
    return alert


def test_retrain_applies_adjustment_with_consent(db_session, admin_headers, client):
    """FP-heavy category raises the detection floor; change is audited and
    exposed, and the Detection Agent's floor loader reflects it."""
    for _ in range(2):
        alert = _new_alert(db_session)
        r = client.post(f"/api/alerts/{alert.id}/feedback", json={"label": "FALSE_POSITIVE"}, headers=admin_headers)
        assert r.status_code == 200

    res = feedback.apply_suggestions(db_session, analyst="admin@cybersentinel.io")
    port_scan = [c for c in res["applied"] if c["category"] == "PORT_SCAN"]
    assert len(port_scan) == 1
    assert port_scan[0]["action"] == "raise"
    assert port_scan[0]["new_floor"] == round(BASE_DETECTION_FLOOR + 0.15, 3)

    setting = db_session.get(CorrelationSetting, "PORT_SCAN")
    assert setting is not None
    assert setting.floor_adjustment == 0.15
    floors = feedback.load_correlation_floors(db_session)
    assert floors.get("PORT_SCAN") == 0.15

    # The settings surface through the stats endpoint too.
    r = client.get("/api/analytics/feedback-stats", headers=admin_headers)
    assert r.status_code == 200
    applied = [a for a in r.json()["applied_settings"] if a["category"] == "PORT_SCAN"]
    assert applied and applied[0]["effective_floor"] == round(BASE_DETECTION_FLOOR + 0.15, 3)


def test_feedback_stats_include_category_suggestions(db_session, admin_headers, client):
    r = client.get("/api/analytics/feedback-stats", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "category_stats" in body
    assert isinstance(body["category_stats"], list)
    for row in body["category_stats"]:
        assert {"category", "total", "true_positive", "false_positive",
                "precision", "false_positive_rate", "suggestion"} <= set(row)
