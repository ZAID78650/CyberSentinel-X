"""Tests for UEBA profiles, entity risk and attack-surface analysis."""
import uuid
from datetime import datetime, timedelta, timezone

from app.models.security import SecurityEvent
from app.services import ueba


def _evt(db, user, minute, event_type="LOGIN_SUCCESS", hour=10, anomaly=False, device="mac-1", day=-1, **kw):
    base = datetime.now(timezone.utc).replace(hour=hour, minute=0, second=0, microsecond=0) \
        + timedelta(days=day) + timedelta(minutes=minute)
    event = SecurityEvent(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        timestamp=base,
        event_type=event_type,
        severity=kw.get("severity", "MEDIUM"),
        source_ip=kw.get("src", "10.1.1.5"),
        destination_ip="10.0.0.1",
        user_id=user,
        device_id=device,
        asset_id=kw.get("asset", "SERVER-01"),
        source="test",
        metadata_={"proto": "tcp", "sbytes": 1000, "dbytes": 200},
        anomaly_score=0.9 if anomaly else 0.1,
        is_anomalous=anomaly,
    )
    db.add(event)
    db.commit()
    return event


def test_ueba_profile_flags_off_hours_and_failures(db_session):
    user = f"u-{uuid.uuid4().hex[:8]}"
    # baseline: 10 daytime successful logins (yesterday, 10:00-14:30)
    for i in range(10):
        _evt(db_session, user, i * 30, hour=10, day=-1)
    # current: off-hours + failed logins + new device (today, 03:00)
    for i in range(5):
        _evt(db_session, user, i, event_type="LOGIN_FAILURE", hour=3, day=0, anomaly=True,
             device=f"unknown-{i}")
    profiles = ueba.ueba_profiles(db_session, entity_type="user", limit=10)
    row = next((p for p in profiles["profiles"] if p["entity"] == user), None)
    assert row is not None
    assert row["risk"] > 0
    assert row["status"] in {"LOW", "MEDIUM", "HIGH"}
    names = {f["name"] for f in row["factors"]}
    assert "Off-hours activity" in names
    assert "Failed authentication spike" in names


def test_entity_risk_and_enterprise_aggregate(db_session):
    user = f"u-{uuid.uuid4().hex[:8]}"
    for i in range(6):
        _evt(db_session, user, i * 40, hour=10)
    res = ueba.entity_risk(db_session, entity_type="user", limit=50)
    assert res["entity_type"] == "user"
    assert 0.0 <= res["enterprise_risk"] <= 100.0
    assert res["entities"]
    row = next((e for e in res["entities"] if e["entity"] == user), None)
    assert row is not None
    assert row["band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(row["components"]) == {"UEBA", "Threat Intelligence", "Anomaly Ratio", "Asset Criticality"}


def test_attack_surface_computed_from_telemetry(db_session):
    user = f"u-{uuid.uuid4().hex[:8]}"
    for i in range(20):
        _evt(db_session, user, i * 5, hour=12, event_type="BRUTE_FORCE", anomaly=True)
    res = ueba.attack_surface(db_session)
    assert "score" in res and "band" in res
    assert 0.0 <= res["score"] <= 100.0
    assert res["auth_failures"] >= 20
    assert res["note"]


def test_unknown_entity_type_rejected(db_session):
    try:
        ueba.ueba_profiles(db_session, entity_type="nope")
        assert False, "should have raised"
    except ValueError:
        pass


def test_entity_detail_drilldown(db_session):
    user = f"u-{uuid.uuid4().hex[:8]}"
    for i in range(6):
        _evt(db_session, user, i * 40, hour=10)
    for i in range(4):
        _evt(db_session, user, i, hour=3, day=0, event_type="LOGIN_FAILURE", anomaly=True, device=f"unk-{i}")
    detail = ueba.entity_detail(db_session, "user", user)
    assert detail["entity"] == user
    assert detail["entity_type"] == "user"
    assert detail["events"] == 10
    assert 0.0 <= detail["risk"] <= 100.0
    assert detail["band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(detail["components"]) == {"UEBA", "Threat Intelligence", "Anomaly Ratio", "Asset Criticality"}
    assert detail["ueba"]["factors"], "off-hours + failure spike should surface factors"
    assert detail["features"]["off_hours_ratio"] > 0
    assert len(detail["recent_events"]) == 10
    assert "note" in detail
    # Unknown entity type must raise.
    try:
        ueba.entity_detail(db_session, "nope", "x")
        assert False, "should have raised"
    except ValueError:
        pass


def test_entity_detail_api(client, admin_headers, db_session):
    # Entity with seeded events (from the corpus seed) must resolve via the API.
    user = "u-entity-api"
    for i in range(5):
        _evt(db_session, user, i * 20, hour=11)
    r = client.get(f"/api/ueba/entity/user/{user}", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["entity"] == user
    assert body["events"] >= 5
    assert "risk" in body and "recent_events" in body
    # Invalid entity type -> 400.
    r2 = client.get("/api/ueba/entity/nope/x", headers=admin_headers)
    assert r2.status_code == 400
