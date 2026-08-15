"""Threat intelligence routes."""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.intel import (
    MitreTechniqueOut,
    ThreatIndicatorOut,
    ThreatIntelSearchRequest,
    ThreatIntelSearchResponse,
)
from app.services.mitre_service import list_incident_mappings  # noqa: F401
from app.threat_intel.adapter import ThreatIntelAdapter
from app.threat_intel.mitre_data import MITRE_TECHNIQUES

router = APIRouter(prefix="/api/threat-intelligence", tags=["threat-intel"])


@router.get("", response_model=Paginated[ThreatIndicatorOut])
def list_indicators(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    indicator_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    adapter = ThreatIntelAdapter(db)
    items, total = adapter.list_indicators(page, page_size, indicator_type)
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[ThreatIndicatorOut](
        items=[ThreatIndicatorOut.model_validate(i) for i in items], total=total,
        page=page, page_size=page_size, pages=pages,
    )


@router.post("/search", response_model=ThreatIntelSearchResponse)
def search_intel(
    req: ThreatIntelSearchRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    adapter = ThreatIntelAdapter(db)
    hits = adapter.search(req.query, req.indicator_type)
    return ThreatIntelSearchResponse(query=req.query, hits=hits, source_count=len(adapter.list_sources()))


@router.get("/mitre", response_model=list[MitreTechniqueOut])
def list_mitre(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    from app.models.intel import MitreTechnique
    from sqlalchemy import select
    rows = list(db.scalars(select(MitreTechnique).order_by(MitreTechnique.technique_id)).all())
    if not rows:
        return [MitreTechniqueOut(**t) for t in MITRE_TECHNIQUES]
    return [MitreTechniqueOut.model_validate(r) for r in rows]
