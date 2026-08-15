"""Response recommendation engine.

Generates controlled, allowlisted response actions for an incident.
High-impact actions require human approval. Execution is SIMULATED —
no real-world destructive action is ever performed.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.utils import to_uuid

from app.models.investigation import ApprovalRequest, ResponseRecommendation
from app.models.security import Incident, IncidentEvent, SecurityEvent
from app.services.audit import log_action

logger = logging.getLogger(__name__)

ACTION_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "Revoke active user sessions": {
        "impact": "HIGH",
        "evidence": "Active sessions observed from atypical source during the incident window",
        "requires_approval": True,
    },
    "Force password reset and MFA re-enrollment": {
        "impact": "MEDIUM",
        "evidence": "Credentials may be compromised; account accessed from an unfamiliar device",
        "requires_approval": True,
    },
    "Isolate affected endpoint": {
        "impact": "HIGH",
        "evidence": "Malware/behavioral detections on the endpoint",
        "requires_approval": True,
    },
    "Block suspicious IP": {
        "impact": "MEDIUM",
        "evidence": "IP matched known threat indicators or drove the attack pattern",
        "requires_approval": True,
    },
    "Review privileged activity": {
        "impact": "LOW",
        "evidence": "Privilege escalation observed; review admin actions for the account",
        "requires_approval": False,
    },
    "Escalate incident": {
        "impact": "LOW",
        "evidence": "Incident severity/risk warrants escalation to senior analysts",
        "requires_approval": False,
    },
}


def generate_recommendations(db: Session, incident_id: str, actor: str = "response-agent") -> List[ResponseRecommendation]:
    """Create response recommendations for an incident (idempotent)."""
    uid = to_uuid(incident_id)
    incident = db.scalar(select(Incident).where(Incident.id == uid))
    if incident is None:
        return []

    existing = list(db.scalars(
        select(ResponseRecommendation).where(ResponseRecommendation.incident_id == uid)
    ).all())
    if existing:
        return existing

    incident_events = list(db.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == uid)
    ).all())
    event_ids = [ie.event_id for ie in incident_events]
    events: List[SecurityEvent] = []
    if event_ids:
        events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))).all())

    etypes = {e.event_type for e in events}
    src_ips = sorted({e.source_ip for e in events if e.source_ip})
    users = sorted({e.user_id for e in events if e.user_id})
    has_malware = "MALWARE_DETECTED" in etypes
    has_exfil = "DATA_EXFILTRATION" in etypes
    has_escalation = "PRIVILEGE_ESCALATION" in etypes
    has_bruteforce = "BRUTE_FORCE" in etypes or any(
        e.event_type == "LOGIN_FAILURE" for e in events)

    actions: List[str] = []
    if has_bruteforce or users:
        actions.append("Revoke active user sessions")
    if users or has_bruteforce:
        actions.append("Force password reset and MFA re-enrollment")
    if has_malware or has_escalation or has_exfil:
        actions.append("Isolate affected endpoint")
    if src_ips:
        actions.append("Block suspicious IP")
    if has_escalation:
        actions.append("Review privileged activity")
    actions.append("Escalate incident")

    recs: List[ResponseRecommendation] = []
    for action in actions:
        tpl = ACTION_TEMPLATES[action]
        evidence = tpl["evidence"]
        if action == "Block suspicious IP":
            evidence = f"Block source IP(s): {', '.join(src_ips[:3])} — " + evidence
        rec = ResponseRecommendation(
            incident_id=uid,
            action=action,
            impact=tpl["impact"],
            reason=None,
            evidence=evidence,
            requires_approval=tpl["requires_approval"],
            status="PENDING",
        )
        db.add(rec)
        db.flush()  # assign rec.id before creating the approval request
        recs.append(rec)
        if tpl["requires_approval"]:
            db.add(ApprovalRequest(
                incident_id=uid,
                recommendation_id=rec.id,
                requested_by=actor,
                status="PENDING",
            ))
    db.commit()
    for r in recs:
        db.refresh(r)
    log_action(db, actor=actor, action="RESPONSE.RECOMMENDATIONS_GENERATED",
               target_type="incident", target_id=str(incident_id),
               detail={"count": len(recs)})
    return recs


def simulate_execution(db: Session, recommendation_id: str, actor: str) -> Dict[str, Any]:
    """Simulate execution of an approved response action.

    Only approved recommendations may be executed. The execution is a
    simulated containment action in the demo environment.
    """
    rec = db.get(ResponseRecommendation, to_uuid(recommendation_id))
    if rec is None:
        raise ValueError("Recommendation not found")
    if rec.status != "APPROVED":
        raise ValueError("Recommendation must be approved before execution")

    summaries = {
        "Revoke active user sessions": "Simulated: all active sessions for the affected account were revoked.",
        "Force password reset and MFA re-enrollment": "Simulated: password reset enforced and MFA re-enrollment triggered for affected users.",
        "Isolate affected endpoint": "Simulated: endpoint was isolated from the network via EDR policy.",
        "Block suspicious IP": "Simulated: source IP added to perimeter blocklist.",
        "Review privileged activity": "Simulated: privileged activity report generated for analyst review.",
        "Escalate incident": "Simulated: incident escalated to senior analyst queue.",
    }
    rec.status = "EXECUTED"
    rec.executed_at = datetime.now(timezone.utc)
    rec.execution_summary = summaries.get(rec.action, f"Simulated: {rec.action} executed.")
    db.commit()

    log_action(db, actor=actor, action="RESPONSE.EXECUTED", target_type="recommendation",
               target_id=str(recommendation_id), detail={"action": rec.action, "simulated": True})

    incident = db.get(Incident, rec.incident_id)
    if incident and incident.status in ("OPEN", "INVESTIGATING"):
        incident.status = "CONTAINED"
        db.commit()

    return {
        "status": "EXECUTED",
        "action": rec.action,
        "summary": rec.execution_summary,
        "simulated": True,
    }


def decide_approval(db: Session, approval_id: str, decision: str, actor: str, reason: Optional[str] = None) -> Dict[str, Any]:
    """Approve or reject an approval request. Returns execution result on approve."""
    approval = db.get(ApprovalRequest, to_uuid(approval_id))
    if approval is None:
        raise ValueError("Approval request not found")
    if approval.status != "PENDING":
        raise ValueError("Approval request already decided")

    approval.status = decision.upper()
    approval.decision_by = actor
    approval.decision_at = datetime.now(timezone.utc)
    approval.reason = reason
    db.commit()

    rec = db.get(ResponseRecommendation, approval.recommendation_id)
    if rec:
        rec.status = "APPROVED" if decision.upper() == "APPROVED" else "REJECTED"
        db.commit()

    log_action(db, actor=actor, action=f"APPROVAL.{decision.upper()}",
               target_type="approval", target_id=str(approval_id),
               detail={"recommendation": rec.action if rec else None, "reason": reason})

    execution_summary = None
    if decision.upper() == "APPROVED" and rec:
        result = simulate_execution(db, rec.id, actor)
        execution_summary = result["summary"]

    return {"status": decision.upper(), "execution_summary": execution_summary}


def list_pending_approvals(db: Session) -> List[Dict[str, Any]]:
    rows = list(db.scalars(
        select(ApprovalRequest).where(ApprovalRequest.status == "PENDING").order_by(ApprovalRequest.created_at.desc())
    ).all())
    out = []
    for a in rows:
        rec = db.get(ResponseRecommendation, a.recommendation_id)
        incident = db.get(Incident, a.incident_id)
        out.append({
            "id": str(a.id),
            "incident_id": str(a.incident_id),
            "recommendation_id": str(a.recommendation_id),
            "requested_by": a.requested_by,
            "status": a.status,
            "decision_by": a.decision_by,
            "decision_at": a.decision_at,
            "reason": a.reason,
            "created_at": a.created_at,
            "recommendation_action": rec.action if rec else None,
            "incident_title": incident.title if incident else None,
            "incident_severity": incident.severity if incident else None,
        })
    return out
