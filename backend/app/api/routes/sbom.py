"""Software Bill of Materials + supply-chain risk routes."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services import sbom as sbom_service

router = APIRouter(prefix="/api/sbom", tags=["sbom"])


@router.get("")
def get_sbom(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return sbom_service.scan_sbom(db)
