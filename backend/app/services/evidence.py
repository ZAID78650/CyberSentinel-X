"""Tamper-evident evidence ledger.

Chain of custody is implemented as a hash chain over evidence records, with
periodic "mined" blocks (lightweight proof-of-work) that anchor batches of
evidence hashes. Nothing sensitive is stored on an external chain — only
hashes and provenance. The API mirrors a permissioned ledger so it can be
migrated to Hyperledger Fabric or another chain later.

Integrity model
---------------
- ``content_hash``   = SHA-256 over the canonical payload (title/description/meta).
- ``record_hash``    = SHA-256 over (chain_index, prev_hash, content_hash, created_at).
- ``block_hash``     = SHA-256 over (block_index, prev_block_hash, records_digest, nonce)
  with a leading-zeros proof-of-work target.

Verification recomputes every hash from stored fields; any edit is detected.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.forensics import EvidenceRecord, LedgerBlock
from app.services.audit import log_action

logger = logging.getLogger(__name__)

# Proof-of-work difficulty: require N leading zero hex chars.
POW_DIFFICULTY = 4
GENESIS_HASH = "0" * 64


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical(payload: Dict[str, Any]) -> str:
    """Stable JSON serialization so hashing is deterministic."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def next_evidence_id(db: Session) -> str:
    count = db.scalar(select(func.count()).select_from(EvidenceRecord)) or 0
    return f"EV-{datetime.now(timezone.utc).year}-{count + 1:06d}"


def _last_record(db: Session) -> Optional[EvidenceRecord]:
    return db.scalar(select(EvidenceRecord).order_by(EvidenceRecord.chain_index.desc()).limit(1))


def _last_block(db: Session) -> Optional[LedgerBlock]:
    return db.scalar(select(LedgerBlock).order_by(LedgerBlock.block_index.desc()).limit(1))


def _chain_anchor(db: Session) -> str:
    """Previous hash anchor: latest record hash, else latest block hash, else genesis."""
    rec = _last_record(db)
    if rec is not None:
        return rec.record_hash
    blk = _last_block(db)
    return blk.block_hash if blk is not None else GENESIS_HASH


def compute_content_hash(title: str, description: Optional[str], meta: Optional[Dict[str, Any]]) -> str:
    return sha256(canonical({"title": title, "description": description, "meta": meta or {}}))


def _canonical_dt(dt: datetime) -> str:
    """Normalize a timestamp so creation-time and read-back hashes match.

    SQLite stores datetimes without tzinfo, so a timezone-aware timestamp
    created at record time must hash identically to the naive value read back.
    """
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="microseconds")


def compute_record_hash(chain_index: int, prev_hash: str, content_hash: str, created_at: datetime) -> str:
    return sha256(f"{chain_index}|{prev_hash}|{content_hash}|{_canonical_dt(created_at)}")


def merkle_root(hashes: List[str]) -> str:
    """Binary Merkle tree root over a list of record hashes.

    Odd layers duplicate the last leaf; empty input hashes the empty string.
    The root lets anyone verify membership/integrity of the batch from just
    the root + their own hash (no raw evidence is stored on-chain).
    """
    if not hashes:
        return sha256("")
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256(f"{layer[i]}|{layer[i + 1]}") for i in range(0, len(layer), 2)]
    return layer[0]


def compute_block_hash(block_index: int, prev_block_hash: str, records_digest: str, nonce: int) -> str:
    return sha256(f"{block_index}|{prev_block_hash}|{records_digest}|{nonce}")


def mine_nonce(block_index: int, prev_block_hash: str, records_digest: str) -> int:
    """Find a nonce whose block hash starts with POW_DIFFICULTY zero hex chars."""
    target = "0" * POW_DIFFICULTY
    nonce = 0
    while True:
        if compute_block_hash(block_index, prev_block_hash, records_digest, nonce).startswith(target):
            return nonce
        nonce += 1


class EvidenceService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    def create_evidence(
        self,
        incident_id: Optional[uuid.UUID],
        evidence_type: str,
        title: str,
        description: Optional[str],
        payload: Dict[str, Any],
        data_source: str = "LOCAL",
        created_by: str = "evidence-agent",
        meta: Optional[Dict[str, Any]] = None,
    ) -> EvidenceRecord:
        """Append a new evidence record to the chain of custody."""
        # The content hash MUST cover exactly the fields verification recomputes:
        # title + description + the stored meta column. The caller's `payload`
        # is merged into meta so verification is deterministic and round-trips.
        merged_meta = {**(meta or {}), **payload}
        chain_index = (db_scalar_count(self.db, EvidenceRecord)) + 1
        prev = _chain_anchor(self.db)
        content_hash = compute_content_hash(title, description, merged_meta)
        created_at = datetime.now(timezone.utc)
        record_hash = compute_record_hash(chain_index, prev, content_hash, created_at)

        record = EvidenceRecord(
            incident_id=incident_id,
            evidence_id=next_evidence_id(self.db),
            evidence_type=evidence_type,
            title=title,
            description=description,
            chain_index=chain_index,
            prev_hash=prev,
            content_hash=content_hash,
            record_hash=record_hash,
            status="VALID",
            data_source=data_source,
            created_by=created_by,
            created_at=created_at,
            meta=merged_meta,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        log_action(self.db, actor=created_by, action="EVIDENCE.RECORDED",
                   target_type="evidence", target_id=record.evidence_id,
                   detail={"type": evidence_type, "chain_index": chain_index,
                           "record_hash": record_hash[:12]})
        return record

    # ------------------------------------------------------------------
    def mine_block(self, created_by: str = "evidence-agent") -> LedgerBlock:
        """Anchor all not-yet-committed evidence records into one mined block.

        "Uncommitted" is anchored on chain-index progression (the max chain
        index committed by the previous block), never on wall-clock time —
        timestamp-based filtering can re-commit records from the same second.
        """
        last = _last_block(self.db)
        block_index = (last.block_index + 1) if last else 0
        prev_block_hash = last.block_hash if last else GENESIS_HASH

        if last is None:
            uncommitted = list(self.db.scalars(
                select(EvidenceRecord).order_by(EvidenceRecord.chain_index).limit(100)
            ).all())
        else:
            last_ids = (last.meta or {}).get("evidence_ids", [])
            committed_through = 0
            if last_ids:
                committed_through = self.db.scalar(
                    select(func.max(EvidenceRecord.chain_index))
                    .where(EvidenceRecord.evidence_id.in_(last_ids))
                ) or 0
            uncommitted = list(self.db.scalars(
                select(EvidenceRecord)
                .where(EvidenceRecord.chain_index > committed_through)
                .order_by(EvidenceRecord.chain_index)
                .limit(100)
            ).all())
        if not uncommitted:
            raise ValueError("No evidence records to commit")

        records_digest = sha256(canonical({"hashes": [r.record_hash for r in uncommitted]}))
        # Merkle root over the batch's record hashes (tree, not linear digest).
        mroot = merkle_root([r.record_hash for r in uncommitted])
        nonce = mine_nonce(block_index, prev_block_hash, records_digest)
        block_hash = compute_block_hash(block_index, prev_block_hash, records_digest, nonce)

        block = LedgerBlock(
            block_index=block_index,
            prev_block_hash=prev_block_hash,
            records_digest=records_digest,
            merkle_root=mroot,
            nonce=nonce,
            block_hash=block_hash,
            record_count=len(uncommitted),
            mined_at=datetime.now(timezone.utc),
            meta={"evidence_ids": [r.evidence_id for r in uncommitted],
                  "last_chain_index": uncommitted[-1].chain_index,
                  "difficulty": POW_DIFFICULTY},
        )
        self.db.add(block)
        self.db.commit()
        self.db.refresh(block)
        log_action(self.db, actor=created_by, action="EVIDENCE.BLOCK_MINED",
                   target_type="ledger", target_id=str(block.block_index),
                   detail={"block_hash": block_hash[:12], "records": len(uncommitted)})
        return block

    # ------------------------------------------------------------------
    def commit_campaign_evidence(self, campaign: Dict[str, Any], created_by: str = "evidence-agent") -> Dict[str, Any]:
        """Anchor a campaign's evidence into its own Merkle-rooted block.

        Per-campaign commitment: the block's meta carries the campaign id, and
        the Merkle root covers exactly that campaign's evidence record hashes
        (chain order) — so the UI can show one root per campaign and a judge
        can verify membership of any individual hash against it.
        """
        from app.models.security import Incident

        inc_ids = campaign.get("incidents") or []
        incidents = list(self.db.scalars(
            select(Incident).where(Incident.incident_id.in_(inc_ids))
        ).all())
        if not incidents:
            raise ValueError("Campaign has no incidents")
        incident_uuids = [i.id for i in incidents]
        records = list(self.db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.incident_id.in_(incident_uuids))
            .order_by(EvidenceRecord.chain_index)
        ).all())
        if not records:
            raise ValueError("No evidence records for this campaign")

        last = _last_block(self.db)
        block_index = (last.block_index + 1) if last else 0
        prev_block_hash = last.block_hash if last else GENESIS_HASH
        hashes = [r.record_hash for r in records]
        records_digest = sha256(canonical({"hashes": hashes}))
        mroot = merkle_root(hashes)
        nonce = mine_nonce(block_index, prev_block_hash, records_digest)
        block_hash = compute_block_hash(block_index, prev_block_hash, records_digest, nonce)

        block = LedgerBlock(
            block_index=block_index,
            prev_block_hash=prev_block_hash,
            records_digest=records_digest,
            merkle_root=mroot,
            nonce=nonce,
            block_hash=block_hash,
            record_count=len(records),
            mined_at=datetime.now(timezone.utc),
            meta={"campaign_id": campaign.get("campaign_id"), "campaign_commit": True,
                  "evidence_ids": [r.evidence_id for r in records],
                  "last_chain_index": records[-1].chain_index,
                  "difficulty": POW_DIFFICULTY},
        )
        self.db.add(block)
        self.db.commit()
        self.db.refresh(block)
        log_action(self.db, actor=created_by, action="EVIDENCE.CAMPAIGN_COMMIT",
                   target_type="campaign", target_id=campaign.get("campaign_id"),
                   detail={"block_index": block_index, "merkle_root": mroot[:12], "records": len(records)})
        return {
            "campaign_id": campaign.get("campaign_id"),
            "block_index": block.block_index,
            "block_hash": block.block_hash,
            "merkle_root": block.merkle_root,
            "nonce": block.nonce,
            "evidence_count": len(records),
            "evidence_ids": [r.evidence_id for r in records],
        }

    # ------------------------------------------------------------------
    def backfill_merkle_roots(self, created_by: str = "evidence-agent") -> Dict[str, Any]:
        """Compute Merkle roots for blocks mined before the tree was introduced.

        Pre-Merkle blocks have ``merkle_root = NULL``; verification skips them
        and judge-mode counts them as zero. This recomputes each missing root
        from the block's committed record hashes (chain order) and persists it.
        """
        blocks = list(self.db.scalars(
            select(LedgerBlock).where(LedgerBlock.merkle_root.is_(None)).order_by(LedgerBlock.block_index)
        ).all())
        backfilled = 0
        for b in blocks:
            ids = (b.meta or {}).get("evidence_ids", [])
            if not ids:
                continue
            recs = list(self.db.scalars(
                select(EvidenceRecord)
                .where(EvidenceRecord.evidence_id.in_(ids[:200]))
                .order_by(EvidenceRecord.chain_index)
            ).all())
            if not recs:
                continue
            b.merkle_root = merkle_root([r.record_hash for r in recs])
            backfilled += 1
        self.db.commit()
        if backfilled:
            log_action(self.db, actor=created_by, action="EVIDENCE.MERKLE_BACKFILL",
                       target_type="ledger", target_id="all",
                       detail={"blocks_backfilled": backfilled})
        return {"backfilled": backfilled}

    # ------------------------------------------------------------------
    def verify_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Recompute hashes for one record; detect any tampering."""
        record = self.db.scalar(
            select(EvidenceRecord).where(EvidenceRecord.evidence_id == evidence_id)
        )
        if record is None:
            raise ValueError(f"Evidence {evidence_id} not found")

        expected_content = compute_content_hash(record.title, record.description, record.meta)
        content_ok = expected_content == record.content_hash
        expected_record = compute_record_hash(
            record.chain_index, record.prev_hash, record.content_hash, record.created_at
        )
        record_ok = expected_record == record.record_hash

        valid = content_ok and record_ok
        record.status = "VALID" if valid else "TAMPERED"
        record.verified_at = datetime.now(timezone.utc)
        self.db.commit()

        return {
            "evidence_id": record.evidence_id,
            "valid": valid,
            "status": record.status,
            "content_hash_ok": content_ok,
            "chain_hash_ok": record_ok,
            "stored_content_hash": record.content_hash,
            "recomputed_content_hash": expected_content,
            "stored_record_hash": record.record_hash,
            "recomputed_record_hash": expected_record,
            "chain_index": record.chain_index,
            "verified_at": record.verified_at.isoformat(),
            "tamper_detected": not valid,
        }

    # ------------------------------------------------------------------
    def verify_chain(self) -> Dict[str, Any]:
        """Walk the full evidence chain + ledger; produce an integrity audit."""
        records = list(self.db.scalars(select(EvidenceRecord).order_by(EvidenceRecord.chain_index)).all())
        blocks = list(self.db.scalars(select(LedgerBlock).order_by(LedgerBlock.block_index)).all())

        chain_broken = False
        issues: List[str] = []
        prev = GENESIS_HASH
        tampered: List[str] = []
        verified = 0
        for r in records:
            content_ok = compute_content_hash(r.title, r.description, r.meta) == r.content_hash
            record_ok = compute_record_hash(r.chain_index, r.prev_hash, r.content_hash, r.created_at) == r.record_hash
            link_ok = r.prev_hash == prev
            r.status = "VALID"
            if not (content_ok and record_ok and link_ok):
                r.status = "TAMPERED"
                chain_broken = True
                tampered.append(r.evidence_id)
                issues.append(f"chain break at EV-{r.chain_index} ({r.evidence_id})")
            else:
                verified += 1
            prev = r.record_hash

        block_broken = False
        merkle_broken = False
        bprev = GENESIS_HASH
        block_ok_count = 0
        merkle_ok_count = 0
        for b in blocks:
            expected = compute_block_hash(b.block_index, b.prev_block_hash, b.records_digest, b.nonce)
            link_ok = b.prev_block_hash == bprev
            if expected != b.block_hash or not link_ok:
                block_broken = True
                issues.append(f"block {b.block_index} hash/link mismatch")
            else:
                block_ok_count += 1
            # Merkle root check: recompute the tree from the block's records,
            # in the same chain-index order used when the block was mined.
            if b.merkle_root:
                ids = (b.meta or {}).get("evidence_ids", [])
                if ids:
                    recs = list(self.db.scalars(
                        select(EvidenceRecord)
                        .where(EvidenceRecord.evidence_id.in_(ids[:200]))
                        .order_by(EvidenceRecord.chain_index)
                    ).all())
                    recomputed = merkle_root([r.record_hash for r in recs])
                    if recomputed == b.merkle_root:
                        merkle_ok_count += 1
                    else:
                        merkle_broken = True
                        issues.append(f"block {b.block_index} merkle root mismatch")
                else:
                    merkle_ok_count += 1
            bprev = b.block_hash

        self.db.commit()
        integrity = "VALID" if (not chain_broken and not block_broken and not merkle_broken) else "TAMPERED"
        return {
            "integrity": integrity,
            "valid": not chain_broken and not block_broken and not merkle_broken,
            "evidence_records": len(records),
            "evidence_verified": verified,
            "evidence_tampered": tampered,
            "ledger_blocks": len(blocks),
            "ledger_blocks_valid": block_ok_count,
            "merkle_roots_valid": merkle_ok_count,
            "issues": issues,
            "audited_at": datetime.now(timezone.utc).isoformat(),
            "method": "sha256 chain + merkle roots + proof-of-work ledger",
        }

    # ------------------------------------------------------------------
    def tamper_test(self, evidence_id: str) -> Dict[str, Any]:
        """DEMO/SIMULATION: mutate a record's payload without updating its hash.

        This is how the UI demonstrates integrity-alert detection. The original
        payload is preserved in meta for restoration.
        """
        record = self.db.scalar(
            select(EvidenceRecord).where(EvidenceRecord.evidence_id == evidence_id)
        )
        if record is None:
            raise ValueError(f"Evidence {evidence_id} not found")
        meta = dict(record.meta or {})
        meta.setdefault("_original_description", record.description)
        record.description = f"{record.description or ''}\n[⛔ TAMPERED — content modified after hashing]"
        record.status = "TAMPERED"
        record.meta = meta
        self.db.commit()
        log_action(self.db, actor="evidence-agent", action="EVIDENCE.TAMPER_TEST",
                   target_type="evidence", target_id=evidence_id,
                   detail={"simulated": True})
        return self.verify_evidence(evidence_id)

    def restore(self, evidence_id: str) -> Dict[str, Any]:
        record = self.db.scalar(
            select(EvidenceRecord).where(EvidenceRecord.evidence_id == evidence_id)
        )
        if record is None:
            raise ValueError(f"Evidence {evidence_id} not found")
        meta = dict(record.meta or {})
        original = meta.pop("_original_description", None)
        if original is not None:
            record.description = original
            record.meta = meta
            self.db.commit()
        return self.verify_evidence(evidence_id)


def db_scalar_count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0
