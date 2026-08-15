"""Security events routes."""
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.websocket_manager import ws_manager
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.event import EventIngest, EventOut
from app.services.audit import log_action
from app.services.event_service import ingest_batch, ingest_event, query_events

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=Paginated[EventOut])
def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_id: Optional[str] = None,
    anomalous_only: bool = False,
    sort: str = "desc",
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    items, total, pages = query_events(
        db, page=page, page_size=page_size, event_type=event_type, severity=severity,
        source_ip=source_ip, user_id=user_id, anomalous_only=anomalous_only, sort=sort,
    )
    return Paginated[EventOut](
        items=[EventOut.model_validate(i) for i in items], total=total, page=page, page_size=page_size, pages=pages
    )


@router.post("", response_model=EventOut, status_code=201)
async def create_event(
    payload: EventIngest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    event = ingest_event(db, payload, source="api")
    log_action(db, actor=user.email, action="EVENT.INGESTED", target_type="event",
               target_id=event.event_id, detail={"event_type": event.event_type})
    await ws_manager.broadcast("new_event", {
        "event_id": event.event_id, "event_type": event.event_type,
        "severity": event.severity, "is_anomalous": event.is_anomalous,
    })
    return EventOut.model_validate(event)


@router.post("/batch", response_model=List[EventOut])
def create_events_batch(
    payloads: List[EventIngest],
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    events = ingest_batch(db, payloads, source="api-batch")
    return [EventOut.model_validate(e) for e in events]


@router.get("/live")
async def live_events(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Most recent events for the live feed."""
    items, _total, _pages = query_events(db, page=1, page_size=limit)
    return [EventOut.model_validate(i) for i in items]
