"""Data pipeline aggregate (Feature 34)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services import judge

router = APIRouter(prefix="/api/data", tags=["data"])


@router.get("/pipeline")
def pipeline(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return judge.data_pipeline(db)
