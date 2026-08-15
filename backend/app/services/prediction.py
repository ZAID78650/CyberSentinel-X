"""Predictive attack path engine.

Maps observed events to MITRE-style attack stages and predicts the most
likely next stage using a transparent transition model (domain priors).
Predictions are always labeled as predictions — never as confirmed events.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.forensics import AttackPrediction
from app.models.security import Incident, IncidentEvent, SecurityEvent

logger = logging.getLogger(__name__)

# Attack-stage order (Lockheed/Cyber Kill-Chain flavored, MITRE-aligned).
STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
]

# Event types / attack families that place an incident at a given stage.
STAGE_EVENT_MAP: List[tuple[str, set[str]]] = [
    ("Reconnaissance", {"PORT_SCAN", "SUSPICIOUS_NETWORK_CONNECTION"}),
    ("Initial Access", {"LOGIN_FAILURE", "LOGIN_SUCCESS", "NEW_DEVICE", "UNUSUAL_LOCATION", "BRUTE_FORCE"}),
    ("Execution", {"SUSPICIOUS_PROCESS", "MALWARE_DETECTED"}),
    ("Privilege Escalation", {"PRIVILEGE_ESCALATION"}),
    ("Credential Access", {"LOGIN_FAILURE", "BRUTE_FORCE"}),
    ("Collection", {"DATABASE_ACCESS", "FILE_ACCESS", "DATA_DOWNLOAD"}),
    ("Exfiltration", {"DATA_EXFILTRATION"}),
]

# Domain-prior transition probabilities: stage -> {next stage: probability}.
TRANSITIONS: Dict[str, Dict[str, float]] = {
    "Reconnaissance": {"Initial Access": 0.62, "Execution": 0.21, "Privilege Escalation": 0.17},
    "Initial Access": {"Privilege Escalation": 0.34, "Execution": 0.31, "Credential Access": 0.23, "Lateral Movement": 0.12},
    "Execution": {"Persistence": 0.32, "Privilege Escalation": 0.30, "Defense Evasion": 0.22, "Collection": 0.16},
    "Persistence": {"Lateral Movement": 0.45, "Privilege Escalation": 0.30, "Collection": 0.25},
    "Privilege Escalation": {"Lateral Movement": 0.42, "Collection": 0.30, "Credential Access": 0.28},
    "Defense Evasion": {"Lateral Movement": 0.40, "Collection": 0.35, "Exfiltration": 0.25},
    "Credential Access": {"Lateral Movement": 0.51, "Collection": 0.31, "Exfiltration": 0.18},
    "Lateral Movement": {"Collection": 0.42, "Exfiltration": 0.38, "Persistence": 0.20},
    "Collection": {"Exfiltration": 0.78, "Lateral Movement": 0.22},
    "Exfiltration": {"Exfiltration": 1.0},  # terminal
}

# Recommended controls per predicted stage.
STAGE_CONTROL: Dict[str, str] = {
    "Reconnaissance": "Rate-limit + monitor inbound scanning; enable port-scan detection rules",
    "Initial Access": "Enforce MFA + conditional access on all remote authentication",
    "Execution": "Application allow-listing and EDR behavioral blocking",
    "Persistence": "Audit scheduled tasks, services and startup persistence locations",
    "Privilege Escalation": "Harden privileged accounts; monitor UAC/sudo elevation",
    "Defense Evasion": "Watch for AV/EDR exclusions and process hollowing",
    "Credential Access": "Rotate credentials; enable honeytoken accounts",
    "Lateral Movement": "Restrict remote authentication; segment the network",
    "Collection": "Monitor sensitive-database/file access; data-loss-prevention rules",
    "Exfiltration": "Block large outbound transfers; enforce egress allow-lists",
}

PROTECTION_MITRE: Dict[str, str] = {
    "Reconnaissance": "T1595", "Initial Access": "T1078", "Execution": "T1059",
    "Persistence": "T1547", "Privilege Escalation": "T1078", "Defense Evasion": "T1562",
    "Credential Access": "T1110", "Lateral Movement": "T1021", "Collection": "T1005",
    "Exfiltration": "T1041",
}


def next_prediction_id(db: Session) -> str:
    count = db.scalar(select(func.count()).select_from(AttackPrediction)) or 0
    return f"PRED-{count + 1:04d}"


def _stage_for_events(events: List[SecurityEvent]) -> str:
    """Determine the furthest stage reached based on observed event types."""
    etypes = {e.event_type for e in events}
    stage_index = -1
    for stage, kinds in STAGE_EVENT_MAP:
        if etypes & kinds:
            # rank by position in STAGE_ORDER, not map order (map omits stages)
            stage_index = max(stage_index, STAGE_ORDER.index(stage))
    return STAGE_ORDER[stage_index] if stage_index >= 0 else "Reconnaissance"


class PredictionService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    def predict(self, incident: Incident) -> AttackPrediction:
        """Generate (or return existing) next-stage prediction for an incident."""
        existing = self.db.scalar(
            select(AttackPrediction).where(AttackPrediction.incident_id == incident.id)
            .order_by(AttackPrediction.created_at.desc()).limit(1)
        )
        if existing:
            return existing

        event_ids = list(self.db.scalars(
            select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
        ).all())
        events: List[SecurityEvent] = []
        if event_ids:
            events = list(self.db.scalars(
                select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids[:400]))
            ).all())

        current = _stage_for_events(events)
        transitions = TRANSITIONS.get(current, TRANSITIONS["Reconnaissance"])
        predicted = max(transitions, key=transitions.get)
        probability = transitions[predicted]

        # Confidence blends data volume, severity and anomaly signal.
        sev_weight = {"LOW": 0.15, "MEDIUM": 0.3, "HIGH": 0.45, "CRITICAL": 0.5}.get(incident.severity, 0.3)
        volume = min(1.0, len(events) / 100)
        anomaly = 0.0
        scores = [e.anomaly_score for e in events if e.anomaly_score is not None]
        if scores:
            anomaly = sum(scores) / len(scores)
        confidence = round(min(0.97, 0.35 + sev_weight + 0.3 * volume + 0.2 * anomaly), 3)

        pred = AttackPrediction(
            incident_id=incident.id,
            current_stage=current,
            predicted_stage=predicted,
            probability=round(probability, 4),
            confidence=confidence,
            recommended_control=STAGE_CONTROL.get(predicted, ""),
            rationale=(
                f"Observed activity is consistent with the '{current}' stage "
                f"({len(events)} correlated events). Based on the attack-path model, "
                f"the next most likely stage is '{predicted}' (probability "
                f"{probability:.0%}, confidence {confidence:.0%}). This is a "
                f"prediction, not a confirmed event."
            ),
            model_version="attack-path-v1",
            is_prediction=True,
            meta={"stages_observed": _observed_stages(events),
                  "event_count": len(events), "mitre_next": PROTECTION_MITRE.get(predicted)},
        )
        self.db.add(pred)
        self.db.commit()
        self.db.refresh(pred)
        logger.info("prediction %s for %s: %s -> %s (%.0f%%)",
                    pred.id, incident.incident_id, current, predicted, probability * 100)
        return pred

    # ------------------------------------------------------------------
    def full_path(self, incident: Incident) -> Dict[str, Any]:
        """Build the predicted kill-chain path from observed stages onward."""
        event_ids = list(self.db.scalars(
            select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
        ).all())
        events: List[SecurityEvent] = []
        if event_ids:
            events = list(self.db.scalars(
                select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids[:400]))
            ).all())
        observed = _observed_stages(events)
        pred = self.predict(incident)
        idx = STAGE_ORDER.index(pred.predicted_stage)
        remaining = STAGE_ORDER[idx:]
        path = [{"stage": s, "state": "observed" if s in observed else "predicted",
                 "probability": None if s in observed else round(
                     max(TRANSITIONS.get(prev, {}).get(s, 0.0) for prev in STAGE_ORDER[:idx] or [s]), 2)
                 } for i, s in enumerate(remaining[:5])]
        return {"current_stage": pred.current_stage, "predicted_stage": pred.predicted_stage,
                "probability": pred.probability, "confidence": pred.confidence,
                "recommended_control": pred.recommended_control, "rationale": pred.rationale,
                "path": path, "observed_stages": observed}


def _observed_stages(events: List[SecurityEvent]) -> List[str]:
    etypes = {e.event_type for e in events}
    seen = [s for s, kinds in STAGE_EVENT_MAP if etypes & kinds]
    return seen
