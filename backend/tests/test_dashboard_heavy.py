"""Dashboard heavy-endpoint tests.

Regression guard for the SQL-side aggregation rewrite: these endpoints must
never load the full event corpus into Python (that OOM'd the Render free
tier). The assertions verify the SQL path works on SQLite (portability) and
that responses are aggregate-shaped, not one-row-per-event.
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.models.security import SecurityEvent


def _make_event(hour: int, category: str, anomalous: bool, ts: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"dash-{uuid.uuid4().hex[:12]}",
        timestamp=ts,
        event_type="FLOW",
        severity="HIGH" if anomalous else "LOW",
        source_ip=f"203.0.113.{hour % 250 + 1}",
        destination_ip="10.0.0.1",
        source="test-dash",
        is_anomalous=anomalous,
        anomaly_score=0.9 if anomalous else 0.1,
        metadata_={
            "dataset": "unsw-nb15",
            "attack_cat": category,
            "sbytes": 1000,
            "dbytes": 500,
            "rate": 10.5,
            "spkts": 4,
            "dpkts": 3,
        },
    )


def test_attack_distribution_aggregates_in_sql(db_session, client, admin_headers):
    """Anomalous events collapse to (category, hour) rows — never 1:1 with events."""
    base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    events = []
    # 5 anomalous events in one unique category+hour, plus 2 in another hour,
    # plus a NON-anomalous one that must NOT appear (is_anomalous filter).
    hour_a = base.hour
    hour_b = (base + timedelta(hours=4)).hour
    hour_na = (base + timedelta(hours=2)).hour
    for i in range(5):
        events.append(_make_event(hour_a, "test-dos-a", True, base + timedelta(minutes=i)))
    events.extend([
        _make_event(hour_b, "test-dos-b", True, base + timedelta(hours=4)),
        _make_event(hour_b, "test-dos-b", True, base + timedelta(hours=4, minutes=1)),
        _make_event(hour_na, "test-dos-a", False, base + timedelta(hours=2)),
    ])
    db_session.add_all(events)
    db_session.commit()

    r = client.get("/api/dashboard/attack-distribution", headers=admin_headers)
    assert r.status_code == 200, r.text
    rows = r.json()
    assert isinstance(rows, list) and rows

    by_key = {(d["category"], d["hour"]): d["count"] for d in rows}
    # 5x (test-dos-a, that hour) collapsed to a single aggregate row.
    assert by_key.get(("test-dos-a", hour_a)) == 5
    # The 2x (test-dos-b, other hour) collapsed too.
    assert by_key.get(("test-dos-b", hour_b)) == 2
    # The non-anomalous event is excluded entirely.
    assert ("test-dos-a", hour_na) not in by_key
    # Aggregate-shaped: never more rows than categories x 24 hours.
    assert len(rows) <= 24 * 40
    for d in rows:
        assert d["category"]
        assert 0 <= d["hour"] <= 23
        assert d["count"] >= 1


def test_events_timeseries_buckets_in_sql(db_session, client, admin_headers):
    """Hourly buckets come back in the frontend's `.000Z` key format."""
    base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    hour = base.hour
    events = [
        _make_event(hour, "test-dos-c", True, base),
        _make_event(hour, "test-dos-c", False, base + timedelta(minutes=10)),
        _make_event(hour, "test-dos-c", True, base + timedelta(minutes=20)),
    ]
    db_session.add_all(events)
    db_session.commit()

    r = client.get("/api/dashboard/events-timeseries", headers=admin_headers)
    assert r.status_code == 200, r.text
    buckets = r.json()
    assert isinstance(buckets, list) and buckets

    key = base.strftime("%Y-%m-%dT%H:00:00.000Z")
    match = next((b for b in buckets if b["time"] == key), None)
    assert match is not None, f"expected bucket {key} in {buckets}"
    # 3 inserted + whatever the seed corpus contributed to this hour.
    assert match["total"] >= 3
    assert match["anomalous"] >= 2
    assert match["anomalous"] <= match["total"]
    # Every bucket key is a UTC ISO hour in the exact format the frontend's
    # hourKey() equality check expects (this is what makes WS live bumps work).
    import re
    assert all(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$", b["time"]) for b in buckets)


def test_threat_space_column_projection(db_session, client, admin_headers):
    """UNSW points are returned with the full 3D payload, bounded by limit."""
    base = datetime.now(timezone.utc) - timedelta(hours=3)
    db_session.add(_make_event(base.hour, "test-dos-d", True, base))
    db_session.commit()

    r = client.get("/api/dashboard/threat-space?limit=100", headers=admin_headers)
    assert r.status_code == 200, r.text
    points = r.json()
    assert isinstance(points, list)
    assert len(points) <= 100
    point = next((p for p in points if p["source_ip"] == f"203.0.113.{base.hour % 250 + 1}"), None)
    assert point is not None, "inserted UNSW point missing from threat-space"
    for field in ("x", "y", "z", "category", "severity", "is_anomalous", "event_type", "timestamp"):
        assert field in point
    assert isinstance(point["x"], (int, float))
