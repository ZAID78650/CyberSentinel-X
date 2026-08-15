"""Campaign intelligence endpoints (velocity, momentum, similarity, coverage,
mutation, business impact). All values are computed from real correlated data.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services import campaign_intel as ci

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])


def _resolve(db: Session, campaign_id: str):
    campaign = ci.campaign_from_id(db, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    return campaign


@router.get("/{campaign_id}/velocity")
def velocity(campaign_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return ci.attack_velocity(db, _resolve(db, campaign_id))


@router.get("/{campaign_id}/momentum")
def momentum(campaign_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return ci.campaign_momentum(db, _resolve(db, campaign_id))


@router.get("/{campaign_id}/similar")
def similar(campaign_id: str, limit: int = 10, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return ci.similar_campaigns(db, campaign_id, limit=limit)


@router.get("/{campaign_id}/mitre-coverage")
def mitre_coverage(campaign_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return ci.mitre_coverage(db, _resolve(db, campaign_id))


@router.get("/{campaign_id}/mutation")
def mutation(campaign_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return ci.campaign_mutation(db, campaign_id)


@router.get("/{campaign_id}/business-impact")
def business_impact(campaign_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return ci.business_impact(db, _resolve(db, campaign_id))


@router.get("/{campaign_id}/intel")
def campaign_intel_summary(campaign_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Combined velocity + momentum + MITRE coverage + status/prediction extras."""
    campaign = _resolve(db, campaign_id)
    return {
        "campaign_id": campaign_id,
        "velocity": ci.attack_velocity(db, campaign),
        "momentum": ci.campaign_momentum(db, campaign),
        "mitre_coverage": ci.mitre_coverage(db, campaign),
        **ci.campaign_extras(db, campaign),
    }


@router.get("/command-center")
def command_center(
    limit: int = 50,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Command-center payload: summary cards + full table rows with intel."""
    from app.services.cache import get_or_build
    return get_or_build(f"command-center:{limit}", 20.0, lambda: ci.command_center(db, limit=limit))
