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


@router.get("/sources/status")
def sources_status(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Threat-intel fusion status: which feeds are configured and their provenance.

    Only real sources are reported. If no external STIX/TAXII/API feed is
    configured, `live_feed_configured` is false and the UI shows
    NO LIVE THREAT INTELLIGENCE SOURCE CONFIGURED.
    """
    from app.models.intel import ThreatIndicator
    from sqlalchemy import func, select

    adapter = ThreatIntelAdapter(db)
    sources = adapter.list_sources()
    indicator_count = db.scalar(select(func.count()).select_from(ThreatIndicator)) or 0
    live = [
        {
            "name": s.name,
            "source_type": s.source_type,
            "status": s.status,
            "base_url": s.base_url,
            "description": s.description,
        }
        for s in sources
        if s.source_type != "local"
    ]
    return {
        "sources": [
            {
                "name": s.name,
                "source_type": s.source_type,
                "status": s.status,
                "base_url": s.base_url,
                "description": s.description,
            }
            for s in sources
        ],
        "live_feed_configured": bool(live),
        "live_sources": live,
        "indicator_count": indicator_count,
        "message": None if live else "NO LIVE THREAT INTELLIGENCE SOURCE CONFIGURED",
        "provenance": {
            "mode": "LIVE" if live else "DATASET",
            "feed": ", ".join(s["name"] for s in live) or "local synthetic feed only",
        },
    }


@router.get("/mitre", response_model=list[MitreTechniqueOut])
def list_mitre(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    from app.models.intel import MitreTechnique
    from sqlalchemy import select
    rows = list(db.scalars(select(MitreTechnique).order_by(MitreTechnique.technique_id)).all())
    if not rows:
        return [MitreTechniqueOut(**t) for t in MITRE_TECHNIQUES]
    return [MitreTechniqueOut.model_validate(r) for r in rows]
