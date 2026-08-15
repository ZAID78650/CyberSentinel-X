"""Tests for the analyst feedback loop (Feature 16)."""
from sqlalchemy import func, select

from app.models.feedback import AnalystFeedback
from app.models.security import Alert


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


def test_feedback_stats_include_category_suggestions(db_session, admin_headers, client):
    r = client.get("/api/analytics/feedback-stats", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "category_stats" in body
    assert isinstance(body["category_stats"], list)
    for row in body["category_stats"]:
        assert {"category", "total", "true_positive", "false_positive",
                "precision", "false_positive_rate", "suggestion"} <= set(row)
