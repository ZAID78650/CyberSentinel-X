"""Security / firewall / assets / playbooks routes."""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.core.firewall import firewall_stats, firewall_summary
from app.ml.evaluate import run_evaluation
from app.models.intel import KnowledgeDocument
from app.models.security import Asset
from app.models.user import User
from app.schemas.common import Paginated

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/firewall")
def get_firewall(_user: User = Depends(get_current_user)):
    return firewall_summary()


@router.get("/firewall/layers")
def get_firewall_layers(_user: User = Depends(get_current_user)):
    return {"layers": firewall_stats()}


@router.get("/detection-accuracy")
def get_detection_accuracy(_user: User = Depends(get_current_user)):
    """Live-measured detection accuracy over the labeled evaluation corpus."""
    return run_evaluation()


@router.post("/test-email")
def test_email(user: User = Depends(require_roles("ADMIN"))):
    """Send a test email to the configured ops address (verifies SMTP)."""
    from app.core.email import email_enabled, send_ops_alert
    if not email_enabled():
        return {"sent": False, "configured": False,
                "message": "SMTP not configured. Set SMTP_USER and SMTP_PASSWORD in backend/.env."}
    ok = send_ops_alert(
        "CyberSentinel X — SMTP test",
        "This is a test email from CyberSentinel X. SMTP is configured and working.",
        "<p>This is a <b>test email</b> from CyberSentinel X.</p><p>SMTP is configured and working.</p>",
    )
    return {"sent": ok, "configured": True, "message": "Test email sent." if ok else "Sending failed — check SMTP credentials."}


@router.get("/assets", response_model=Paginated[dict])
def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    asset_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(Asset).order_by(Asset.criticality.desc(), Asset.name)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    total = len(list(db.scalars(stmt).all()))
    items = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[dict](
        items=[_asset_dict(a) for a in items], total=total, page=page, page_size=page_size, pages=pages
    )


@router.get("/playbooks", response_model=Paginated[dict])
def list_playbooks(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(KnowledgeDocument).where(KnowledgeDocument.doc_type.in_(["playbook", "policy", "cve", "mitre"]))
    total = len(list(db.scalars(stmt).all()))
    items = list(db.scalars(stmt.order_by(KnowledgeDocument.title).offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[dict](
        items=[_doc_dict(d) for d in items], total=total, page=page, page_size=page_size, pages=pages
    )


def _asset_dict(a: Asset) -> dict:
    return {
        "id": str(a.id),
        "name": a.name,
        "asset_type": a.asset_type,
        "ip_address": a.ip_address,
        "hostname": a.hostname,
        "criticality": a.criticality,
        "owner": a.owner,
        "description": a.description,
    }


def _doc_dict(d: KnowledgeDocument) -> dict:
    return {
        "id": str(d.id),
        "title": d.title,
        "source": d.source,
        "doc_type": d.doc_type,
        "chunk_count": d.chunk_count,
        "tags": d.tags,
        "content_preview": d.content[:400] + ("…" if len(d.content) > 400 else ""),
    }
