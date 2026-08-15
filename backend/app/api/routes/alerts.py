"""Alerts routes."""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.security import Alert
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.event import AlertOut
from app.services import feedback as feedback_service

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=Paginated[AlertOut])
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(Alert).order_by(Alert.created_at.desc())
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())
    if status:
        stmt = stmt.where(Alert.status == status.upper())
    if category:
        stmt = stmt.where(Alert.category == category.upper())
    total = len(list(db.scalars(stmt).all()))
    items = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[AlertOut](
        items=[AlertOut.model_validate(a) for a in items], total=total, page=page, page_size=page_size, pages=pages
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertOut.model_validate(alert)


class FeedbackIn(BaseModel):
    label: str = Field(description="TRUE_POSITIVE | FALSE_POSITIVE | BENIGN | UNKNOWN")
    note: Optional[str] = None


@router.post("/{alert_id}/feedback")
async def submit_feedback(
    alert_id: UUID,
    body: FeedbackIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Record an analyst label for an alert (adaptive false-positive loop)."""
    try:
        fb = feedback_service.submit_feedback(
            db, alert_id, body.label, analyst=user.email or user.full_name, note=body.note
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    from app.core.websocket_manager import ws_manager
    await ws_manager.broadcast("analyst_feedback", {
        "alert_id": str(alert_id), "label": fb.label, "analyst": fb.analyst,
    })
    return {"alert_id": str(alert_id), "label": fb.label, "analyst": fb.analyst, "created_at": fb.created_at.isoformat()}
