"""User & Entity Behavior Analytics, entity risk, attack surface.

All values are computed from the stored event corpus:

* :func:`ueba_profiles` — per-entity behavioral baselines (first 60% of the
  entity's events) vs current behavior (last 40%), with explainable factors.
* :func:`entity_risk` — independent explainable risk per entity type plus an
  enterprise aggregate.
* :func:`attack_surface` — exposure signals observed in telemetry.
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.security import Asset, Incident, SecurityEvent
from app.risk.engine import band

logger = logging.getLogger(__name__)

ENTITY_COLUMNS = {
    "user": SecurityEvent.user_id,
    "ip": SecurityEvent.source_ip,
    "device": SecurityEvent.device_id,
}

OFF_HOURS = {h for h in range(24) if h < 8 or h > 18}
AUTH_TYPES = {"LOGIN_SUCCESS", "LOGIN_FAILURE", "BRUTE_FORCE"}
FAIL_TYPES = {"LOGIN_FAILURE", "BRUTE_FORCE"}


def _entity_rows(db: Session, entity_type: str, limit_entities: int = 15) -> List[Tuple[str, List[SecurityEvent]]]:
    col = ENTITY_COLUMNS.get(entity_type)
    if col is None:
        raise ValueError(f"Unknown entity type: {entity_type} (use user|ip|device)")
    counts = db.execute(
        select(col, func.count())
        .where(col.isnot(None))
        .group_by(col)
        .order_by(func.count().desc())
        .limit(limit_entities)
    ).all()
    out: List[Tuple[str, List[SecurityEvent]]] = []
    for value, _count in counts:
        events = list(db.scalars(
            select(SecurityEvent).where(col == value).order_by(SecurityEvent.timestamp)
        ).all())
        out.append((str(value), events))
    return out


def _features(events: List[SecurityEvent]) -> Dict[str, float]:
    hours = [e.timestamp.hour for e in events]
    logins = [e for e in events if e.event_type in AUTH_TYPES]
    failed = sum(1 for e in logins if e.event_type in FAIL_TYPES)
    span_h = max((events[-1].timestamp - events[0].timestamp).total_seconds() / 3600.0, 1e-9)
    return {
        "n": len(events),
        "off_hours_ratio": sum(1 for h in hours if h in OFF_HOURS) / max(len(hours), 1),
        "failed_ratio": failed / max(len(logins), 1),
        "distinct_devices": float(len({e.device_id for e in events if e.device_id})),
        "distinct_ips": float(len({e.source_ip for e in events if e.source_ip})),
        "data_volume": sum(
            float((e.metadata_ or {}).get("sbytes", 0) or 0)
            + float((e.metadata_ or {}).get("dbytes", 0) or 0)
            for e in events
        ),
        "anomaly_ratio": sum(1 for e in events if e.is_anomalous) / max(len(events), 1),
        "rate_per_hour": len(events) / span_h,
    }


# ---------------------------------------------------------------------------
# Feature 7 — UEBA
# ---------------------------------------------------------------------------

def _ueba_risk(events: List[SecurityEvent]) -> Dict[str, Any]:
    if len(events) < 4:
        return {
            "risk": 0.0, "status": "INSUFFICIENT_DATA", "factors": [],
            "note": "Fewer than 4 events — insufficient baseline.",
        }
    split = max(int(len(events) * 0.6), 1)
    base, curr = events[:split], events[split:]
    fb, fc = _features(base), _features(curr)

    factors: List[Dict[str, Any]] = []
    total = 0.0

    if fc["off_hours_ratio"] > max(fb["off_hours_ratio"], 0.2) + 0.25:
        total += 25
        factors.append({
            "name": "Off-hours activity", "score": 25,
            "evidence": f"current off-hours ratio {fc['off_hours_ratio']:.0%} vs baseline {fb['off_hours_ratio']:.0%}",
        })
    if fc["failed_ratio"] > max(fb["failed_ratio"], 0.1) + 0.3:
        total += 25
        factors.append({
            "name": "Failed authentication spike", "score": 25,
            "evidence": f"current failed-login ratio {fc['failed_ratio']:.0%} vs baseline {fb['failed_ratio']:.0%}",
        })
    dev_base = {e.device_id for e in base if e.device_id}
    dev_curr = {e.device_id for e in curr if e.device_id}
    new_devices = dev_curr - dev_base
    if new_devices:
        total += 15
        factors.append({
            "name": "New device", "score": 15,
            "evidence": f"devices not seen in baseline: {', '.join(sorted(new_devices)[:3])}",
        })
    if fc["data_volume"] > 3 * max(fb["data_volume"], 1.0):
        total += 15
        factors.append({
            "name": "Large data access", "score": 15,
            "evidence": f"current data volume {fc['data_volume']:.0f}B vs baseline {fb['data_volume']:.0f}B",
        })
    if fc["anomaly_ratio"] > 0.5:
        total += 20
        factors.append({
            "name": "Anomalous activity ratio", "score": 20,
            "evidence": f"{fc['anomaly_ratio']:.0%} of current events flagged anomalous",
        })

    risk = round(min(total, 100.0), 1)
    status = "HIGH" if risk >= 70 else ("MEDIUM" if risk >= 40 else "LOW")
    return {
        "risk": risk, "status": status, "factors": factors,
        "baseline_events": len(base), "current_events": len(curr),
        "note": "Baseline = first 60% of the entity's events; current = last 40%.",
    }


def entity_detail(db: Session, entity_type: str, value: str, sample_events: int = 25) -> Dict[str, Any]:
    """Drill-down for one entity: UEBA baseline deviation, risk components,
    intel matches, related incidents, asset record and a recent-event sample.
    All numbers are computed from stored data — no fabricated analysis."""
    col = ENTITY_COLUMNS.get(entity_type)
    if col is None:
        raise ValueError(f"Unknown entity type: {entity_type} (use user|ip|device)")
    value = str(value).strip()
    if not value:
        raise ValueError("Entity value required")

    all_events = list(db.scalars(
        select(SecurityEvent).where(col == value).order_by(SecurityEvent.timestamp)
    ).all())
    ueba = _ueba_risk(all_events)
    feats = _features(all_events) if all_events else {}
    intel_hits = sum(1 for e in all_events if e.detection_reason and "Threat intel match" in (e.detection_reason or ""))
    anomaly_ratio = sum(1 for e in all_events if e.is_anomalous) / max(len(all_events), 1)

    # Related incidents through the incident-event join.
    related: List[Dict[str, Any]] = []
    eids = [e.event_id for e in all_events[:1000]]
    if eids:
        from app.models.security import IncidentEvent
        seen_ids: set = set()
        for ie in db.scalars(select(IncidentEvent).where(IncidentEvent.event_id.in_(eids))):
            seen_ids.add(ie.incident_id)
        if seen_ids:
            incs = list(db.scalars(select(Incident).where(Incident.id.in_(list(seen_ids)[:10]))).all())
            for inc in sorted(incs, key=lambda i: i.created_at, reverse=True)[:6]:
                related.append({
                    "id": str(inc.id),
                    "incident_id": inc.incident_id, "title": inc.title,
                    "severity": inc.severity, "status": inc.status,
                    "risk_score": inc.risk_score,
                })

    # Asset record (best-effort match per entity type).
    asset = None
    if entity_type == "ip":
        asset = db.scalar(select(Asset).where(Asset.ip_address == value))
    elif entity_type == "device":
        asset = db.scalar(select(Asset).where(Asset.hostname == value))
    elif entity_type == "user":
        asset = db.scalar(select(Asset).where(Asset.owner == value))
    asset_row = None
    if asset is not None:
        asset_row = {
            "name": asset.name, "asset_type": asset.asset_type,
            "ip_address": asset.ip_address, "hostname": asset.hostname,
            "criticality": asset.criticality, "owner": asset.owner,
        }

    criticality = (asset.criticality if asset else 5) or 5
    components = {
        "UEBA": round(ueba["risk"], 1),
        "Threat Intelligence": round(min(100.0, intel_hits * 20), 1),
        "Anomaly Ratio": round(anomaly_ratio * 100, 1),
        "Asset Criticality": round(criticality * 10, 1),
    }
    risk = round(0.45 * ueba["risk"] + 0.25 * min(100.0, intel_hits * 20)
                 + 0.20 * anomaly_ratio * 100 + 0.10 * criticality * 10, 1)

    # Threat-intel feed match for the entity itself.
    intel = []
    try:
        from app.threat_intel.adapter import ThreatIntelAdapter
        intel = ThreatIntelAdapter(db).search(value)
    except Exception:  # pragma: no cover
        pass

    recent = [{
        "event_id": e.event_id, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "event_type": e.event_type, "severity": e.severity,
        "is_anomalous": e.is_anomalous, "detection_reason": e.detection_reason,
    } for e in all_events[-sample_events:]]

    return {
        "entity": value,
        "entity_type": entity_type,
        "events": len(all_events),
        "risk": risk,
        "band": band(risk),
        "components": components,
        "ueba": ueba,
        "features": {
            "off_hours_ratio": round(feats.get("off_hours_ratio", 0.0), 3),
            "failed_ratio": round(feats.get("failed_ratio", 0.0), 3),
            "distinct_devices": int(feats.get("distinct_devices", 0)),
            "distinct_ips": int(feats.get("distinct_ips", 0)),
            "anomaly_ratio": round(feats.get("anomaly_ratio", 0.0), 3),
            "rate_per_hour": round(feats.get("rate_per_hour", 0.0), 2),
        },
        "intel_hits": intel_hits,
        "intel": [{"value": i["value"], "indicator_type": i["indicator_type"],
                    "severity": i["severity"], "confidence": i["confidence"],
                    "source": i["source"], "match_reason": i.get("match_reason", "")} for i in intel],
        "related_incidents": related,
        "asset": asset_row,
        "recent_events": recent,
        "note": "Risk = 0.45·UEBA + 0.25·intel + 0.20·anomaly ratio + 0.10·asset criticality; UEBA compares last 40% of events to the first 60% baseline.",
    }


def ueba_profiles(db: Session, entity_type: str = "user", limit: int = 15) -> Dict[str, Any]:
    rows = _entity_rows(db, entity_type, limit)
    profiles = []
    for value, events in rows:
        ueba = _ueba_risk(events)
        feats = _features(events)
        profiles.append({
            "entity": value,
            "events": len(events),
            "risk": ueba["risk"],
            "status": ueba["status"],
            "factors": ueba["factors"],
            "baseline_events": ueba["baseline_events"],
            "current_events": ueba["current_events"],
            "features": {
                "off_hours_ratio": round(feats["off_hours_ratio"], 3),
                "failed_ratio": round(feats["failed_ratio"], 3),
                "distinct_devices": int(feats["distinct_devices"]),
                "distinct_ips": int(feats["distinct_ips"]),
                "anomaly_ratio": round(feats["anomaly_ratio"], 3),
                "rate_per_hour": round(feats["rate_per_hour"], 2),
            },
        })
    profiles.sort(key=lambda p: -p["risk"])
    return {
        "entity_type": entity_type,
        "profiles": profiles,
        "note": "Statistical baselines (z-score style deviation) over real event history.",
    }


# ---------------------------------------------------------------------------
# Feature 8 — Entity risk + enterprise risk
# ---------------------------------------------------------------------------

def entity_risk(db: Session, entity_type: str = "user", limit: int = 15) -> Dict[str, Any]:
    rows = _entity_rows(db, entity_type, limit)
    entities = []
    for value, events in rows:
        ueba = _ueba_risk(events)
        intel_hits = sum(1 for e in events if e.detection_reason and "Threat intel match" in (e.detection_reason or ""))
        anom_ratio = sum(1 for e in events if e.is_anomalous) / max(len(events), 1)
        criticality = 5
        if entity_type == "ip":
            asset = db.scalar(select(Asset).where(Asset.ip_address == value))
            criticality = (asset.criticality if asset else 5) or 5
        components = {
            "UEBA": round(ueba["risk"], 1),
            "Threat Intelligence": round(min(100.0, intel_hits * 20), 1),
            "Anomaly Ratio": round(anom_ratio * 100, 1),
            "Asset Criticality": round(criticality * 10, 1),
        }
        risk = round(0.45 * ueba["risk"] + 0.25 * min(100.0, intel_hits * 20)
                     + 0.20 * anom_ratio * 100 + 0.10 * criticality * 10, 1)
        entities.append({
            "entity": value,
            "type": entity_type,
            "risk": risk,
            "band": band(risk),
            "intel_hits": intel_hits,
            "anomaly_ratio": round(anom_ratio, 3),
            "components": components,
            "ueba_status": ueba["status"],
        })
    entities.sort(key=lambda e: -e["risk"])
    enterprise = round(sum(e["risk"] for e in entities) / max(len(entities), 1), 1) if entities else 0.0
    return {
        "entity_type": entity_type,
        "entities": entities,
        "enterprise_risk": enterprise,
        "enterprise_band": band(enterprise),
        "count": len(entities),
        "note": "Risk = 0.45·UEBA + 0.25·intel + 0.20·anomaly ratio + 0.10·asset criticality (weighted, explainable).",
    }


# ---------------------------------------------------------------------------
# Feature 12 — Attack surface analysis
# ---------------------------------------------------------------------------

def attack_surface(db: Session, sample: int = 20000) -> Dict[str, Any]:
    """Attack-surface score from observed exposure signals (no random values)."""
    events = list(db.scalars(
        select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(sample)
    ).all())
    if not events:
        return {"score": 0.0, "band": "LOW", "note": "No telemetry — attack surface not computable.",
                "exposed_endpoints": 0, "intel_matches": 0, "auth_failures": 0, "open_ports": 0}

    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.2", "172.30.", "172.31.", "127.", "0.")
    external = {e.destination_ip for e in events if e.destination_ip and not e.destination_ip.startswith(private_prefixes)}
    protocols = Counter((e.metadata_ or {}).get("proto", "-") for e in events)
    intel_matches = sum(1 for e in events if e.detection_reason and "Threat intel match" in (e.detection_reason or ""))
    auth_failures = sum(1 for e in events if e.event_type in FAIL_TYPES)
    ports = set()
    for e in events:
        meta = e.metadata_ or {}
        if meta.get("sport"):
            ports.add(str(meta["sport"]))
        if meta.get("dport"):
            ports.add(str(meta["dport"]))

    score = round(min(100.0, 20.0 * len(protocols) / 3.0 + min(25.0, intel_matches * 5.0)
                      + min(20.0, auth_failures / 10.0) + min(20.0, len(external) / 10.0)
                      + min(15.0, len(ports) / 10.0)), 1)

    # Highest-criticality asset involved in anomalous traffic.
    top_asset = None
    top_crit = -1
    anomalous_assets = {e.asset_id for e in events if e.is_anomalous and e.asset_id}
    if anomalous_assets:
        for a in db.scalars(select(Asset).where(Asset.name.in_(list(anomalous_assets)))).all():
            if (a.criticality or 0) > top_crit:
                top_crit, top_asset = a.criticality or 0, a.name

    return {
        "score": score,
        "band": band(score),
        "exposed_endpoints": len(external),
        "protocols_seen": len(protocols),
        "intel_matches": intel_matches,
        "auth_failures": auth_failures,
        "open_ports": len(ports),
        "highest_risk_asset": top_asset,
        "note": "Computed from observed telemetry: protocols, external endpoints, intel matches, auth failures, ports.",
    }
