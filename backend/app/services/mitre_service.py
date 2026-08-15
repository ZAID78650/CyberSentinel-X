"""Map incident activity to MITRE ATT&CK techniques with confidence."""
import logging
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.utils import to_uuid

from app.models.intel import IncidentMitreMapping, MitreTechnique
from app.models.security import Incident, IncidentEvent, SecurityEvent

logger = logging.getLogger(__name__)

# event_type -> (technique_id, base confidence, rationale)
_EVENT_TO_TECHNIQUE: Dict[str, tuple] = {
    "LOGIN_FAILURE": ("T1110", 0.75, "Repeated authentication failures indicate credential brute forcing"),
    "BRUTE_FORCE": ("T1110", 0.9, "Brute-force pattern over a short window"),
    "LOGIN_SUCCESS": ("T1078", 0.7, "Successful authentication, possibly with compromised credentials"),
    "NEW_DEVICE": ("T1078", 0.6, "Authentication from a device with no prior history"),
    "UNUSUAL_LOCATION": ("T1078", 0.7, "Authentication from an atypical geographic location"),
    "PRIVILEGE_ESCALATION": ("T1548", 0.85, "Elevation of privileges beyond the account baseline"),
    "MALWARE_DETECTED": ("T1204", 0.7, "Malware execution detected on an endpoint"),
    "SUSPICIOUS_PROCESS": ("T1059", 0.65, "Suspicious process execution / scripting activity"),
    "DATA_EXFILTRATION": ("T1041", 0.8, "Suspected data transfer to an external destination"),
    "DATABASE_ACCESS": ("T1005", 0.6, "Access to sensitive data store"),
    "DATA_DOWNLOAD": ("T1005", 0.65, "Download of sensitive data"),
    "FILE_ACCESS": ("T1083", 0.5, "File and directory enumeration"),
    "PORT_SCAN": ("T1046", 0.8, "Network service discovery / port scanning"),
    "SUSPICIOUS_NETWORK_CONNECTION": ("T1071", 0.6, "Suspicious outbound network connection"),
}


def infer_techniques_from_events(events: List[SecurityEvent]) -> Dict[str, Dict[str, Any]]:
    """Map a set of events to techniques. Returns {technique_id: {confidence, evidence}}."""
    mapping: Dict[str, Dict[str, Any]] = {}
    for e in events:
        rule = _EVENT_TO_TECHNIQUE.get(e.event_type)
        if rule is None:
            continue
        tid, conf, rationale = rule
        entry = mapping.setdefault(tid, {"confidence": 0.0, "evidence": []})
        entry["confidence"] = max(entry["confidence"], conf)
        entry["evidence"].append(f"{e.event_type} at {e.timestamp.isoformat()} — {rationale}")
    # Malware with C2 domain also maps to T1071
    for e in events:
        if e.event_type == "MALWARE_DETECTED" and e.metadata_ and e.metadata_.get("c2_domain"):
            entry = mapping.setdefault("T1071", {"confidence": 0.0, "evidence": []})
            entry["confidence"] = max(entry["confidence"], 0.6)
            entry["evidence"].append(f"Malware C2 callback to {e.metadata_['c2_domain']}")
    return mapping


def map_incident_to_mitre(db: Session, incident_id: str) -> List[IncidentMitreMapping]:
    """Persist and return MITRE mappings for an incident (idempotent-ish)."""
    uid = to_uuid(incident_id)
    incident = db.scalar(select(Incident).where(Incident.id == uid))
    if incident is None:
        return []

    incident_events = list(db.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == uid)
    ).all())
    event_ids = [ie.event_id for ie in incident_events]
    events: List[SecurityEvent] = []
    if event_ids:
        events = list(db.scalars(
            select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))
        ).all())

    inferred = infer_techniques_from_events(events)

    # Remove stale mappings and re-create
    existing = list(db.scalars(
        select(IncidentMitreMapping).where(IncidentMitreMapping.incident_id == uid)
    ).all())
    for m in existing:
        db.delete(m)
    db.flush()

    created: List[IncidentMitreMapping] = []
    for tid, info in inferred.items():
        technique = db.scalar(select(MitreTechnique).where(MitreTechnique.technique_id == tid))
        if technique is None:
            continue
        rec = IncidentMitreMapping(
            incident_id=uid,
            technique_id=tid,
            confidence=round(info["confidence"], 2),
            evidence="; ".join(info["evidence"][:3]),
        )
        db.add(rec)
        created.append(rec)
    db.commit()
    return created


def list_incident_mappings(db: Session, incident_id: str) -> List[Dict[str, Any]]:
    uid = to_uuid(incident_id)
    rows = list(db.scalars(
        select(IncidentMitreMapping).where(IncidentMitreMapping.incident_id == uid)
    ).all())
    result = []
    for m in rows:
        technique = db.scalar(select(MitreTechnique).where(MitreTechnique.technique_id == m.technique_id))
        result.append({
            "technique_id": m.technique_id,
            "name": technique.name if technique else m.technique_id,
            "tactic": technique.tactic if technique else "",
            "confidence": m.confidence,
            "evidence": m.evidence,
            "severity_hint": technique.severity_hint if technique else "MEDIUM",
        })
    return result
