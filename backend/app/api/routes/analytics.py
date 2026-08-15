"""Analytics route."""
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.ml.evaluate import run_evaluation
from app.models.investigation import ActionLog, ApprovalRequest, RiskScore
from app.models.intel import IncidentMitreMapping, MitreTechnique
from app.models.security import Alert, Incident, SecurityEvent
from app.models.user import User
from app.schemas.report import AnalyticsOut

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("", response_model=AnalyticsOut)
def analytics(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    events_total = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    events_by_type = {r[0]: r[1] for r in db.execute(
        select(SecurityEvent.event_type, func.count()).group_by(SecurityEvent.event_type)).all()}
    alerts_total = db.scalar(select(func.count()).select_from(Alert)) or 0
    alerts_by_severity = {r[0]: r[1] for r in db.execute(
        select(Alert.severity, func.count()).group_by(Alert.severity)).all()}
    alerts_by_category = {r[0]: r[1] for r in db.execute(
        select(Alert.category, func.count()).group_by(Alert.category)).all()}
    incidents_total = db.scalar(select(func.count()).select_from(Incident)) or 0
    incidents_by_status = {r[0]: r[1] for r in db.execute(
        select(Incident.status, func.count()).group_by(Incident.status)).all()}
    risk_over_time = [{"date": str(r[0]), "avg_risk": round(float(r[1]), 1)} for r in db.execute(
        select(func.date(RiskScore.created_at), func.avg(RiskScore.score))
        .group_by(func.date(RiskScore.created_at)).order_by(func.date(RiskScore.created_at))).all()]
    top_threat_sources = [{"source": r[0], "count": r[1]} for r in db.execute(
        select(SecurityEvent.source_ip, func.count()).where(SecurityEvent.source_ip.isnot(None))
        .group_by(SecurityEvent.source_ip).order_by(func.count().desc()).limit(8)).all()]

    # Top techniques across incidents
    tech_counts = db.execute(
        select(IncidentMitreMapping.technique_id, func.count()).group_by(IncidentMitreMapping.technique_id)
        .order_by(func.count().desc()).limit(8)
    ).all()
    top_attack_techniques = []
    for tid, count in tech_counts:
        tech = db.scalar(select(MitreTechnique).where(MitreTechnique.technique_id == tid))
        top_attack_techniques.append({
            "technique_id": tid,
            "name": tech.name if tech else tid,
            "tactic": tech.tactic if tech else "",
            "count": count,
        })

    actions_executed = db.scalar(select(func.count()).select_from(ActionLog)) or 0
    approvals_pending = db.scalar(select(func.count()).select_from(ApprovalRequest)
                                  .where(ApprovalRequest.status == "PENDING")) or 0

    detection_accuracy = run_evaluation()

    return AnalyticsOut(
        events_total=events_total,
        events_by_type=events_by_type,
        alerts_total=alerts_total,
        alerts_by_severity=alerts_by_severity,
        alerts_by_category=alerts_by_category,
        incidents_total=incidents_total,
        incidents_by_status=incidents_by_status,
        risk_over_time=risk_over_time,
        top_threat_sources=top_threat_sources,
        top_attack_techniques=top_attack_techniques,
        actions_executed=actions_executed,
        approvals_pending=approvals_pending,
        detection_accuracy=detection_accuracy,
    )
