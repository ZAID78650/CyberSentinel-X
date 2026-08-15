"""Attack DNA API routes."""
import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.forensics import AttackDna
from app.models.security import Incident
from app.models.user import User
from app.services.attack_dna import AttackDnaService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/attack-dna", tags=["attack-dna"])


def _dna_out(d: AttackDna) -> dict:
    return {
        "id": str(d.id),
        "dna_id": d.dna_id,
        "incident_id": str(d.incident_id),
        "fingerprint": d.fingerprint,
        "family": d.family,
        "confidence": d.confidence,
        "severity": d.severity,
        "risk_score": d.risk_score,
        "techniques": d.techniques or [],
        "behaviors": d.behaviors or [],
        "features": d.features or {},
        "historical_similarity": d.historical_similarity,
        "similar_to": d.similar_to,
        "created_at": d.created_at.isoformat(),
    }


@router.get("")
def list_dna(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    items = list(db.scalars(select(AttackDna).order_by(AttackDna.created_at.desc()).limit(limit)).all())
    return {"items": [_dna_out(d) for d in items], "total": len(items)}


@router.get("/similar")
def similar(
    incident_id: Optional[UUID] = None,
    top_k: int = Query(5, ge=1, le=20),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return {"items": AttackDnaService(db).search_similar(incident_id=incident_id, top_k=top_k)}


@router.get("/{incident_id}")
def get_or_generate(
    incident_id: UUID,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    dna = AttackDnaService(db).generate(incident)
    similar_items = AttackDnaService(db).search_similar(incident_id=incident_id, top_k=5)
    return {**_dna_out(dna), "similar_attacks": similar_items}
