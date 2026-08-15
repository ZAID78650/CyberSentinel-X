"""Incidents routes."""
import asyncio
import uuid
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.agents.orchestrator import Orchestrator
from app.core.database import get_db
from app.models.security import Incident
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.event import IncidentCreate, IncidentOut
from app.services.audit import log_action

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=Paginated[IncidentOut])
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(Incident).order_by(Incident.created_at.desc())
    if severity:
        stmt = stmt.where(Incident.severity == severity.upper())
    if status:
        stmt = stmt.where(Incident.status == status.upper())
    if category:
        stmt = stmt.where(Incident.category == category.upper())
    total = len(list(db.scalars(stmt).all()))
    items = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[IncidentOut](
        items=[IncidentOut.model_validate(i) for i in items], total=total, page=page, page_size=page_size, pages=pages
    )


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentOut.model_validate(incident)


@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    incident = Incident(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title=payload.title,
        description=payload.description,
        severity=payload.severity.upper(),
        category=payload.category.upper(),
        status="OPEN",
        created_by=user.email,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    log_action(db, actor=user.email, action="INCIDENT.MANUALLY_CREATED",
               target_type="incident", target_id=str(incident.id))
    return IncidentOut.model_validate(incident)


@router.post("/{incident_id}/investigate", response_model=dict)
async def investigate_incident(
    incident_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = "INVESTIGATING"
    db.commit()
    log_action(db, actor=user.email, action="INCIDENT.INVESTIGATION_STARTED",
               target_type="incident", target_id=str(incident_id))
    orchestrator = Orchestrator()
    asyncio.create_task(orchestrator.run_pipeline(str(incident_id)))
    return {"status": "started", "incident_id": str(incident_id), "message": "Investigation pipeline launched"}


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(
    incident_id: UUID,
    status: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    from app.models.security import INCIDENT_STATUSES
    if status.upper() not in INCIDENT_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {INCIDENT_STATUSES}")
    incident.status = status.upper()
    db.commit()
    log_action(db, actor=user.email, action="INCIDENT.STATUS_CHANGED",
               target_type="incident", target_id=str(incident_id), detail={"status": status.upper()})
    return IncidentOut.model_validate(incident)
