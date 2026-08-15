"""Data quality center + ML model drift + feedback stats + judge mode."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services import data_quality, feedback, judge

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/data-quality")
def quality(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return data_quality.data_quality(db)


@router.get("/model-drift")
def drift(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return data_quality.model_drift(db)


@router.get("/feedback-stats")
def feedback_stats(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return feedback.feedback_stats(db)


@router.get("/judge-mode")
def judge_mode(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    from app.services.cache import get_or_build
    # Heaviest aggregate (campaign scan + MTTD/MTTR per incident) — TTL cached.
    return get_or_build("judge-mode", 30.0, lambda: judge.judge_mode(db))
