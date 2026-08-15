"""UEBA, entity risk and attack-surface endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services import ueba

router = APIRouter(prefix="/api/ueba", tags=["ueba"])


@router.get("/profiles")
def profiles(entity_type: str = "user", limit: int = 15,
             db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    try:
        return ueba.ueba_profiles(db, entity_type=entity_type, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/entity-risk")
def entity_risk(entity_type: str = "user", limit: int = 15,
                db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    try:
        return ueba.entity_risk(db, entity_type=entity_type, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/attack-surface")
def attack_surface(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return ueba.attack_surface(db)
