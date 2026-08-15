"""Tests for the Merkle tree root and its integration with ledger blocks."""
from sqlalchemy import select

from app.models.forensics import EvidenceRecord
from app.services.evidence import EvidenceService, merkle_root, sha256


def test_merkle_root_cases():
    assert merkle_root([]) == sha256("")
    h = sha256("a")
    assert merkle_root([h]) == h  # single leaf: root is the leaf
    a, b = sha256("a"), sha256("b")
    assert merkle_root([a, b]) == sha256(f"{a}|{b}")
    root3 = merkle_root([sha256("a"), sha256("b"), sha256("c")])
    assert len(root3) == 64
    # odd layer duplicates the last leaf -> deterministic
    assert merkle_root([sha256("a"), sha256("b"), sha256("c")]) == root3


def test_mined_block_carries_merkle_root(db_session):
    svc = EvidenceService(db_session)
    recs = []
    for i in range(3):
        recs.append(svc.create_evidence(
            incident_id=None, evidence_type="TEST",
            title=f"merkle test {i}", description="payload",
            payload={"i": i}, data_source="TEST",
        ))
    block = svc.mine_block(created_by="test")
    assert block.merkle_root is not None
    assert len(block.merkle_root) == 64
    # Recompute the root from the block's own records (chain order) — must match.
    ids = (block.meta or {}).get("evidence_ids", [])
    records = list(db_session.scalars(
        select(EvidenceRecord)
        .where(EvidenceRecord.evidence_id.in_(ids))
        .order_by(EvidenceRecord.chain_index)
    ).all())
    assert merkle_root([r.record_hash for r in records]) == block.merkle_root


def test_backfill_merkle_roots_for_pre_merkle_blocks(db_session):
    """Blocks mined before the Merkle upgrade (merkle_root=NULL) get a root
    backfilled from their committed record hashes and then verify clean."""
    svc = EvidenceService(db_session)
    for i in range(2):
        svc.create_evidence(
            incident_id=None, evidence_type="TEST",
            title=f"backfill {i}", description="payload",
            payload={"i": i}, data_source="TEST",
        )
    block = svc.mine_block(created_by="test")
    ids = (block.meta or {}).get("evidence_ids", [])
    records = list(db_session.scalars(
        select(EvidenceRecord)
        .where(EvidenceRecord.evidence_id.in_(ids))
        .order_by(EvidenceRecord.chain_index)
    ).all())
    expected = merkle_root([r.record_hash for r in records])

    # Simulate a pre-Merkle block: root never computed.
    block.merkle_root = None
    db_session.commit()

    result = svc.backfill_merkle_roots(created_by="test")
    assert result["backfilled"] >= 1

    db_session.refresh(block)
    assert block.merkle_root == expected
    assert block.merkle_root is not None

    report = svc.verify_chain()
    assert report["merkle_roots_valid"] >= 1
    assert report["integrity"] == "VALID"


def test_verify_chain_includes_merkle_check(db_session):
    svc = EvidenceService(db_session)
    svc.create_evidence(incident_id=None, evidence_type="TEST",
                        title="audit", description="x", payload={}, data_source="TEST")
    svc.mine_block(created_by="test")
    audit = svc.verify_chain()
    assert "merkle_roots_valid" in audit
    assert "ledger_blocks" in audit
    assert "method" in audit and "merkle" in audit["method"]
