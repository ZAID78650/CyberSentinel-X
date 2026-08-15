"""Alert creation, correlation, and incident creation."""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security import Alert, Incident, IncidentEvent, SecurityEvent
from app.services.audit import log_action

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

CATEGORY_BY_EVENT = {
    "LOGIN_FAILURE": "CREDENTIAL_ATTACK",
    "BRUTE_FORCE": "CREDENTIAL_ATTACK",
    "LOGIN_SUCCESS": "ACCOUNT_TAKEOVER",
    "NEW_DEVICE": "ACCOUNT_TAKEOVER",
    "UNUSUAL_LOCATION": "ACCOUNT_TAKEOVER",
    "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION",
    "MALWARE_DETECTED": "MALWARE",
    "SUSPICIOUS_PROCESS": "MALWARE",
    "DATA_EXFILTRATION": "EXFILTRATION",
    "DATABASE_ACCESS": "DATA_BREACH",
    "DATA_DOWNLOAD": "DATA_BREACH",
    "FILE_ACCESS": "DATA_BREACH",
    "PORT_SCAN": "RECONNAISSANCE",
    "SUSPICIOUS_NETWORK_CONNECTION": "C2",
}


def _category_for(events: List[SecurityEvent]) -> str:
    for e in events:
        cat = CATEGORY_BY_EVENT.get(e.event_type)
        if cat:
            return cat
    return "GENERIC"


def create_alert_from_events(db: Session, events: List[SecurityEvent], title: str,
                             actor: str = "detection-agent") -> Alert:
    """Create an alert summarizing a cluster of suspicious events."""
    severities = [e.severity for e in events]
    severity = max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))
    confidence = round(min(0.98, 0.4 + 0.06 * len(events)), 2)
    anomaly_scores = [e.anomaly_score for e in events if e.anomaly_score is not None]
    avg_anomaly = round(sum(anomaly_scores) / len(anomaly_scores), 3) if anomaly_scores else None
    reasons = [r for e in events if e.detection_reason for r in e.detection_reason.split("; ") if r]

    alert = Alert(
        alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
        title=title,
        description=f"Detection Agent correlated {len(events)} events into a single alert.",
        severity=severity,
        status="OPEN",
        category=_category_for(events),
        confidence=confidence,
        anomaly_score=avg_anomaly,
        detection_reason="; ".join(dict.fromkeys(reasons))[:2000],
        source_event_ids=[e.event_id for e in events],
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    log_action(db, actor=actor, action="ALERT.CREATED", target_type="alert",
               target_id=str(alert.id), detail={"severity": severity, "events": len(events)})
    return alert


def create_incident_from_alert(db: Session, alert: Alert, actor: str = "detection-agent") -> Incident:
    """Create an incident from an alert and link its events."""
    incident = db.scalar(select(Incident).where(Incident.alert_id == alert.id))
    if incident:
        return incident

    events = list(db.scalars(
        select(SecurityEvent).where(SecurityEvent.event_id.in_(alert.source_event_ids))
    ).all())

    users = sorted({e.user_id for e in events if e.user_id})
    ips = sorted({e.source_ip for e in events if e.source_ip})
    who = users[0] if users else (ips[0] if ips else "unknown entity")
    incident = Incident(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title=alert.title,
        description=f"Correlated from alert {alert.alert_id} involving {who}. {alert.detection_reason or ''}"[:2000],
        severity=alert.severity,
        status="OPEN",
        confidence=alert.confidence,
        category=alert.category,
        alert_id=alert.id,
        created_by=actor,
    )
    db.add(incident)
    db.flush()
    for e in events:
        db.add(IncidentEvent(incident_id=incident.id, event_id=e.event_id))
    db.commit()
    db.refresh(incident)
    log_action(db, actor=actor, action="INCIDENT.CREATED", target_type="incident",
               target_id=str(incident.id), detail={"severity": incident.severity, "events": len(events)})

    # Email the ops address when a high-severity incident is opened
    if incident.severity in ("HIGH", "CRITICAL"):
        try:
            from app.core.email import send_incident_alert
            from app.core.config import get_settings
            url = f"{get_settings().frontend_url.rstrip('/')}/incidents?open={incident.id}"
            details = incident.description or incident.title
            send_incident_alert(incident.title, incident.severity, url, details)
        except Exception as exc:  # pragma: no cover — email is best-effort
            logger.warning("incident email failed: %s", exc)
    return incident


def find_recent_incident_for_user(db: Session, user_id: str, hours: int = 6) -> Optional[Incident]:
    """Correlation helper: find an open incident touching the same user recently."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    incidents = list(db.scalars(
        select(Incident).where(Incident.created_at >= cutoff).order_by(Incident.created_at.desc()).limit(20)
    ))
    for inc in incidents:
        links = list(db.scalars(
            select(IncidentEvent).where(IncidentEvent.incident_id == inc.id).limit(100)
        ).all())
        ev_ids = [lnk.event_id for lnk in links]
        if not ev_ids:
            continue
        evs = list(db.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(ev_ids))).all())
        if any(e.user_id == user_id for e in evs):
            return inc
    return None
