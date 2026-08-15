"""Attack prediction API routes."""
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.forensics import AttackPrediction
from app.models.security import Incident
from app.models.user import User
from app.services.prediction import PredictionService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/predictions", tags=["predictions"])


@router.get("")
def list_predictions(
    limit: int = 100,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    items = list(db.scalars(
        select(AttackPrediction).order_by(AttackPrediction.created_at.desc()).limit(limit)
    ).all())
    return {
        "items": [
            {
                "id": str(p.id),
                "incident_id": str(p.incident_id),
                "current_stage": p.current_stage,
                "predicted_stage": p.predicted_stage,
                "probability": p.probability,
                "confidence": p.confidence,
                "recommended_control": p.recommended_control,
                "rationale": p.rationale,
                "model_version": p.model_version,
                "is_prediction": p.is_prediction,
                "created_at": p.created_at.isoformat(),
            }
            for p in items
        ],
        "total": len(items),
    }


@router.get("/{incident_id}")
def get_prediction(
    incident_id: UUID,
    full: bool = False,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    service = PredictionService(db)
    if full:
        return service.full_path(incident)
    pred = service.predict(incident)
    return {
        "id": str(pred.id),
        "incident_id": str(pred.incident_id),
        "current_stage": pred.current_stage,
        "predicted_stage": pred.predicted_stage,
        "probability": pred.probability,
        "confidence": pred.confidence,
        "recommended_control": pred.recommended_control,
        "rationale": pred.rationale,
        "model_version": pred.model_version,
        "is_prediction": pred.is_prediction,
        "created_at": pred.created_at.isoformat(),
    }
