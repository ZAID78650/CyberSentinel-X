"""Health and readiness endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    """Liveness probe."""
    return {"status": "ok", "service": "cybersentinel-backend"}


@router.get("/ready")
def ready(db: Session = Depends(get_db)):
    """Readiness probe: verifies database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        db.scalar(select(User).limit(1))
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ready" if db_ok else "not-ready", "database": "connected" if db_ok else "unavailable"}
