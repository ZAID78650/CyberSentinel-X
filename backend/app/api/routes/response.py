"""Response center, approvals and actions log routes."""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.orchestrator import Orchestrator
from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.models.investigation import ActionLog, ApprovalRequest, ResponseRecommendation
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.response import (
    ApprovalDecision,
    ApprovalDecisionOut,
    ApprovalOut,
    RecommendationOut,
)
from app.response.engine import decide_approval, generate_recommendations, simulate_execution

router = APIRouter(tags=["response"])


@router.get("/api/response-recommendations/{incident_id}", response_model=List[RecommendationOut])
def get_recommendations(incident_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    recs = generate_recommendations(db, str(incident_id))
    return [RecommendationOut.model_validate(r) for r in recs]


@router.get("/api/approvals", response_model=List[ApprovalOut])
def list_approvals(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    if status:
        stmt = stmt.where(ApprovalRequest.status == status.upper())
    rows = list(db.scalars(stmt).all())
    out = []
    for a in rows:
        rec = db.get(ResponseRecommendation, a.recommendation_id)
        from app.models.security import Incident
        incident = db.get(Incident, a.incident_id)
        out.append(ApprovalOut(
            id=a.id, incident_id=a.incident_id, recommendation_id=a.recommendation_id,
            requested_by=a.requested_by, status=a.status, decision_by=a.decision_by,
            decision_at=a.decision_at, reason=a.reason, created_at=a.created_at,
            recommendation_action=rec.action if rec else None,
            incident_title=incident.title if incident else None,
            incident_severity=incident.severity if incident else None,
        ))
    return out


@router.post("/api/approvals/{approval_id}/approve", response_model=ApprovalDecisionOut)
async def approve(approval_id: UUID, decision: ApprovalDecision, db: Session = Depends(get_db),
                  user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST"))):
    try:
        result = decide_approval(db, str(approval_id), "APPROVED", user.email, decision.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    approval = db.get(ApprovalRequest, approval_id)
    await Orchestrator().on_approval_decided(str(approval.incident_id))
    return ApprovalDecisionOut(
        approval=ApprovalOut(
            id=approval.id, incident_id=approval.incident_id, recommendation_id=approval.recommendation_id,
            requested_by=approval.requested_by, status=approval.status, decision_by=approval.decision_by,
            decision_at=approval.decision_at, reason=approval.reason, created_at=approval.created_at,
        ),
        status=result["status"], message="Action approved and simulated execution started.",
        execution_summary=result.get("execution_summary"),
    )


@router.post("/api/approvals/{approval_id}/reject", response_model=ApprovalDecisionOut)
async def reject(approval_id: UUID, decision: ApprovalDecision, db: Session = Depends(get_db),
                 user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST"))):
    try:
        result = decide_approval(db, str(approval_id), "REJECTED", user.email, decision.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    approval = db.get(ApprovalRequest, approval_id)
    await Orchestrator().on_approval_decided(str(approval.incident_id))
    return ApprovalDecisionOut(
        approval=ApprovalOut(
            id=approval.id, incident_id=approval.incident_id, recommendation_id=approval.recommendation_id,
            requested_by=approval.requested_by, status=approval.status, decision_by=approval.decision_by,
            decision_at=approval.decision_at, reason=approval.reason, created_at=approval.created_at,
        ),
        status=result["status"], message="Action rejected.",
    )


@router.post("/api/response-recommendations/{recommendation_id}/execute", response_model=dict)
def execute_recommendation(recommendation_id: UUID, db: Session = Depends(get_db),
                           user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST"))):
    try:
        result = simulate_execution(db, str(recommendation_id), user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.get("/api/actions-log", response_model=Paginated[dict])
def actions_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    actor: Optional[str] = None,
    action: Optional[str] = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(ActionLog).order_by(ActionLog.created_at.desc())
    if actor:
        stmt = stmt.where(ActionLog.actor == actor)
    if action:
        stmt = stmt.where(ActionLog.action.contains(action))
    total = len(list(db.scalars(stmt).all()))
    rows = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    items = [
        {
            "id": str(r.id), "actor": r.actor, "action": r.action, "target_type": r.target_type,
            "target_id": r.target_id, "detail": r.detail, "ip_address": r.ip_address,
            "created_at": r.created_at,
        }
        for r in rows
    ]
    return Paginated[dict](items=items, total=total, page=page, page_size=page_size, pages=pages)
