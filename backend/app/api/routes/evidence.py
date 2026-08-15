"""Evidence ledger + blockchain API routes."""
import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.models.forensics import EvidenceRecord, LedgerBlock
from app.models.user import User
from app.services.audit import log_action
from app.services.evidence import EvidenceService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


class EvidenceCreate(BaseModel):
    incident_id: Optional[UUID] = None
    evidence_type: str = "MANUAL"
    title: str
    description: Optional[str] = None
    payload: dict = {}
    data_source: str = "LOCAL"


def _record_out(r: EvidenceRecord) -> dict:
    return {
        "id": str(r.id),
        "evidence_id": r.evidence_id,
        "incident_id": str(r.incident_id) if r.incident_id else None,
        "evidence_type": r.evidence_type,
        "title": r.title,
        "description": r.description,
        "chain_index": r.chain_index,
        "prev_hash": r.prev_hash,
        "content_hash": r.content_hash,
        "record_hash": r.record_hash,
        "status": r.status,
        "data_source": r.data_source,
        "created_by": r.created_by,
        "verified_at": r.verified_at.isoformat() if r.verified_at else None,
        "created_at": r.created_at.isoformat(),
        "meta": r.meta or {},
    }


@router.get("")
def list_evidence(
    incident_id: Optional[UUID] = None,
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(EvidenceRecord).order_by(EvidenceRecord.chain_index.desc())
    if incident_id:
        stmt = stmt.where(EvidenceRecord.incident_id == incident_id)
    if status:
        stmt = stmt.where(EvidenceRecord.status == status.upper())
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    return {
        "items": [_record_out(i) for i in items], "total": total,
        "page": page, "page_size": page_size,
        "pages": max((total + page_size - 1) // page_size, 1),
    }


@router.get("/ledger")
def ledger(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    blocks = list(db.scalars(select(LedgerBlock).order_by(LedgerBlock.block_index)).all())
    return {
        "blocks": [
            {
                "block_index": b.block_index,
                "prev_block_hash": b.prev_block_hash,
                "records_digest": b.records_digest,
                "merkle_root": b.merkle_root,
                "nonce": b.nonce,
                "block_hash": b.block_hash,
                "record_count": b.record_count,
                "mined_at": b.mined_at.isoformat(),
                "evidence_ids": (b.meta or {}).get("evidence_ids", []),
                "difficulty": (b.meta or {}).get("difficulty"),
            }
            for b in blocks
        ],
        "total_blocks": len(blocks),
    }


@router.post("/ledger/mine")
async def mine(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    try:
        block = EvidenceService(db).mine_block(created_by=user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "mined": True,
        "block_index": block.block_index,
        "block_hash": block.block_hash,
        "merkle_root": block.merkle_root,
        "nonce": block.nonce,
        "record_count": block.record_count,
    }


@router.post("/campaign/{campaign_id}/commit")
def commit_campaign_evidence(
    campaign_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    """Anchor a campaign's evidence into its own Merkle-rooted block."""
    from app.services.campaign_intel import campaign_from_id

    campaign = campaign_from_id(db, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    try:
        result = EvidenceService(db).commit_campaign_evidence(campaign, created_by=user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/ledger/backfill-merkle")
def backfill_merkle(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    """Backfill Merkle roots for blocks mined before the tree was introduced."""
    result = EvidenceService(db).backfill_merkle_roots(created_by=user.email)
    return result


@router.post("/ledger/verify")
def verify_ledger(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    report = EvidenceService(db).verify_chain()
    log_action(db, actor=_user.email, action="EVIDENCE.LEDGER_VERIFIED",
               target_type="ledger", target_id="all",
               detail={"integrity": report["integrity"], "records": report["evidence_records"]})
    return report


@router.post("", status_code=201)
def create_evidence(
    payload: EvidenceCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    if payload.incident_id:
        from app.models.security import Incident
        if db.get(Incident, payload.incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")
    record = EvidenceService(db).create_evidence(
        incident_id=payload.incident_id,
        evidence_type=payload.evidence_type.upper(),
        title=payload.title,
        description=payload.description,
        payload=payload.payload,
        data_source=payload.data_source.upper(),
        created_by=user.email,
    )
    return _record_out(record)


@router.post("/{evidence_id}/verify")
def verify_one(evidence_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    try:
        return EvidenceService(db).verify_evidence(evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/{evidence_id}/tamper-test")
def tamper_test(
    evidence_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    """SIMULATION ONLY: mutate a record's payload without updating its hash to
    demonstrate integrity-alert detection. Restore with /restore."""
    try:
        result = EvidenceService(db).tamper_test(evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    log_action(db, actor=user.email, action="EVIDENCE.TAMPER_TEST", target_type="evidence",
               target_id=evidence_id, detail={"simulated": True, "tamper_detected": result["tamper_detected"]})
    return result


@router.post("/{evidence_id}/restore")
def restore_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    try:
        result = EvidenceService(db).restore(evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    log_action(db, actor=user.email, action="EVIDENCE.RESTORED", target_type="evidence",
               target_id=evidence_id)
    return result
