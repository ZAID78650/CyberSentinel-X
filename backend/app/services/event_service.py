"""Security event normalization and ingestion."""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security import SecurityEvent
from app.schemas.event import EventIngest
from app.services.detection import DetectionService

logger = logging.getLogger(__name__)


def normalize_event(payload: EventIngest, source: str = "api") -> Dict[str, Any]:
    """Normalize an event into the canonical CyberSentinel X model."""
    return {
        "event_id": payload.event_id if getattr(payload, "event_id", None) else f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": payload.timestamp or datetime.now(timezone.utc),
        "event_type": payload.event_type.upper(),
        "severity": (payload.severity or "LOW").upper(),
        "source_ip": payload.source_ip,
        "destination_ip": payload.destination_ip,
        "user_id": payload.user_id,
        "device_id": payload.device_id,
        "asset_id": payload.asset_id,
        "source": payload.source or source,
        "metadata": payload.metadata or {},
    }


def ingest_event(db: Session, payload: EventIngest, source: str = "api") -> SecurityEvent:
    """Normalize, detect anomalies and persist a single event."""
    data = normalize_event(payload, source)
    detection = DetectionService(db)
    event = detection.process_event(data)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def ingest_batch(db: Session, payloads: List[EventIngest], source: str = "batch") -> List[SecurityEvent]:
    """Ingest a batch of events (used by the simulator)."""
    events: List[SecurityEvent] = []
    detection = DetectionService(db)
    for p in payloads:
        data = normalize_event(p, source)
        event = detection.process_event(data)
        db.add(event)
        events.append(event)
    db.commit()
    for e in events:
        db.refresh(e)
    return events


def query_events(
    db: Session,
    page: int = 1,
    page_size: int = 50,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_id: Optional[str] = None,
    anomalous_only: bool = False,
    sort: str = "desc",
) -> tuple:
    stmt = select(SecurityEvent)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type.upper())
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity.upper())
    if source_ip:
        stmt = stmt.where(SecurityEvent.source_ip == source_ip)
    if user_id:
        stmt = stmt.where(SecurityEvent.user_id == user_id)
    if anomalous_only:
        stmt = stmt.where(SecurityEvent.is_anomalous.is_(True))

    # Count via a subquery instead of materializing every row (cheap on
    # large corpora like UNSW-NB15).
    from sqlalchemy import func as sa_func, select as sa_select

    total = db.scalar(sa_select(sa_func.count()).select_from(stmt.subquery())) or 0
    col = SecurityEvent.timestamp
    stmt = stmt.order_by(col.desc() if sort == "desc" else col.asc())
    items = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    pages = max((total + page_size - 1) // page_size, 1)
    return items, total, pages
