"""Explainable dynamic risk scoring.

Weights (initial model):
- 30% Behavioral anomaly
- 20% Threat intelligence
- 20% Asset criticality
- 15% Attack progression (MITRE chain depth)
- 15% Historical evidence (volume + confidence)

Score bands: 0-30 LOW, 31-60 MEDIUM, 61-80 HIGH, 81-100 CRITICAL.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.utils import to_uuid

from app.models.intel import IncidentMitreMapping
from app.models.security import Incident, IncidentEvent, SecurityEvent

logger = logging.getLogger(__name__)

WEIGHTS = {
    "behavioral_anomaly": 0.30,
    "threat_intelligence": 0.20,
    "asset_criticality": 0.20,
    "attack_progression": 0.15,
    "historical_evidence": 0.15,
}

SEVERITY_BANDS = [(30, "LOW"), (60, "MEDIUM"), (80, "HIGH"), (100, "CRITICAL")]


def band(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score <= threshold:
            return label
    return "CRITICAL"


def compute_risk(db: Session, incident_id: str) -> Dict[str, Any]:
    """Compute (and persist) an explainable risk score for an incident."""
    uid = to_uuid(incident_id)
    incident = db.scalar(select(Incident).where(Incident.id == uid))
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    incident_events = list(db.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == uid)
    ).all())
    event_ids = [ie.event_id for ie in incident_events]
    events: List[SecurityEvent] = []
    if event_ids:
        events = list(db.scalars(
            select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))
        ).all())

    factors: List[Dict[str, Any]] = []

    # 1. Behavioral anomaly (30%)
    if events:
        avg_anomaly = sum(e.anomaly_score or 0.5 for e in events) / len(events)
        anomalous = sum(1 for e in events if e.is_anomalous)
        anomaly_component = min(1.0, avg_anomaly * 0.7 + (anomalous / max(len(events), 1)) * 0.3)
    else:
        anomaly_component = 0.1
    factors.append({
        "name": "Behavioral Anomaly",
        "weight": WEIGHTS["behavioral_anomaly"],
        "score": round(anomaly_component, 3),
        "contribution": round(anomaly_component * WEIGHTS["behavioral_anomaly"], 3),
        "evidence": f"Average anomaly score {avg_anomaly:.2f} across {len(events)} events" if events else "No correlated events",
    })

    # 2. Threat intelligence (20%)
    intel_hits = sum(1 for e in events if e.detection_reason and "Threat intel match" in (e.detection_reason or ""))
    intel_component = min(1.0, 0.3 + 0.35 * intel_hits) if intel_hits else 0.1
    factors.append({
        "name": "Threat Intelligence",
        "weight": WEIGHTS["threat_intelligence"],
        "score": round(intel_component, 3),
        "contribution": round(intel_component * WEIGHTS["threat_intelligence"], 3),
        "evidence": f"{intel_hits} events matched known threat indicators",
    })

    # 3. Asset criticality (20%)
    from app.models.security import Asset
    criticalities = []
    for e in events:
        if e.asset_id:
            asset = db.scalar(select(Asset).where(Asset.name == e.asset_id))
            if asset:
                criticalities.append(asset.criticality)
    if criticalities:
        avg_crit = sum(criticalities) / len(criticalities)
        asset_component = avg_crit / 10.0
    else:
        asset_component = 0.4
    factors.append({
        "name": "Asset Criticality",
        "weight": WEIGHTS["asset_criticality"],
        "score": round(asset_component, 3),
        "contribution": round(asset_component * WEIGHTS["asset_criticality"], 3),
        "evidence": f"Criticality {avg_crit:.0f}/10 across {len(criticalities)} assets" if criticalities else "No assets identified",
    })

    # 4. Attack progression (15%)
    mappings = list(db.scalars(
        select(IncidentMitreMapping).where(IncidentMitreMapping.incident_id == uid)
    ).all())
    distinct_tactics = set()
    from app.models.intel import MitreTechnique
    for m in mappings:
        tech = db.scalar(select(MitreTechnique).where(MitreTechnique.technique_id == m.technique_id))
        if tech:
            distinct_tactics.add(tech.tactic)
    progression = min(1.0, len(distinct_tactics) / 6.0 + 0.15 * len(mappings))
    factors.append({
        "name": "Attack Progression",
        "weight": WEIGHTS["attack_progression"],
        "score": round(progression, 3),
        "contribution": round(progression * WEIGHTS["attack_progression"], 3),
        "evidence": f"{len(distinct_tactics)} tactics / {len(mappings)} techniques mapped",
    })

    # 5. Historical evidence (15%)
    evidence_count = len(events)
    severity_boost = sum({"LOW": 0, "MEDIUM": 0.2, "HIGH": 0.4, "CRITICAL": 0.7}.get(e.severity, 0) for e in events)
    evidence_component = min(1.0, evidence_count / 40.0 * 0.5 + severity_boost / max(len(events), 1) * 0.5)
    factors.append({
        "name": "Historical Evidence",
        "weight": WEIGHTS["historical_evidence"],
        "score": round(evidence_component, 3),
        "contribution": round(evidence_component * WEIGHTS["historical_evidence"], 3),
        "evidence": f"{evidence_count} correlated events with severity-weighted confidence",
    })

    score = round(sum(f["contribution"] for f in factors) * 100, 1)
    score = max(0.0, min(100.0, score))

    from app.models.investigation import RiskScore
    existing = db.scalar(select(RiskScore).where(RiskScore.incident_id == uid).order_by(RiskScore.created_at.desc()))
    if existing:
        existing.score = score
        existing.severity_label = band(score)
        existing.factors = {"factors": factors, "weights": WEIGHTS}
        db.commit()
    else:
        db.add(RiskScore(
            incident_id=uid, score=score, severity_label=band(score),
            factors={"factors": factors, "weights": WEIGHTS}, model_version="v1",
        ))
        db.commit()

    incident.risk_score = score
    incident.risk_label = band(score)
    db.commit()

    reason = f"Risk computed from {len(events)} correlated events with {len(distinct_tactics)} ATT&CK tactics reached."
    return {
        "incident_id": str(incident_id),
        "score": score,
        "severity_label": band(score),
        "confidence": round(min(0.99, 0.5 + 0.05 * len(events)), 2),
        "factors": factors,
        "reason": reason,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


def get_latest_risk(db: Session, incident_id: str) -> Dict[str, Any]:
    from app.models.investigation import RiskScore
    uid = to_uuid(incident_id)
    row = db.scalar(select(RiskScore).where(RiskScore.incident_id == uid).order_by(RiskScore.created_at.desc()))
    if row is None:
        return compute_risk(db, incident_id)
    return {
        "incident_id": str(incident_id),
        "score": row.score,
        "severity_label": row.severity_label,
        "confidence": round(min(0.99, 0.5 + 0.05 * row.score / 20), 2),
        "factors": row.factors.get("factors", []),
        "reason": "Risk score from latest computation",
        "computed_at": row.created_at.isoformat(),
    }
