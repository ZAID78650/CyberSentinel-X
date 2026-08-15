"""Forensic models: tamper-evident evidence ledger, attack DNA, predictions.

The evidence ledger is a hash-chained record store with periodic "mined"
blocks (a lightweight proof-of-work), giving audit-grade chain-of-custody
without putting raw logs on any external chain. The architecture is a
permissioned-ledger abstraction — it can be swapped for Hyperledger
Fabric / a real chain later without changing call sites.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

EVIDENCE_TYPES = [
    "INCIDENT_CREATED",
    "INVESTIGATION",
    "THREAT_INTEL",
    "RISK",
    "RESPONSE",
    "ATTACK_DNA",
    "PREDICTION",
    "MANUAL",
    "SYSTEM",
]

EVIDENCE_STATUSES = ["VALID", "TAMPERED", "PENDING"]


class EvidenceRecord(Base, UUIDMixin, TimestampMixin):
    """A single piece of evidence, hash-linked into the chain of custody."""

    __tablename__ = "evidence_records"
    __table_args__ = (
        Index("ix_evidence_incident", "incident_id"),
        Index("ix_evidence_chain_index", "chain_index"),
    )

    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=True
    )
    evidence_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # --- integrity fields ---------------------------------------------------
    chain_index: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="VALID", nullable=False)
    data_source: Mapped[str] = mapped_column(String(24), default="LOCAL", nullable=False)  # LIVE|DATASET|SIMULATED|LOCAL
    created_by: Mapped[str] = mapped_column(String(128), default="evidence-agent", nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)


class LedgerBlock(Base, UUIDMixin, TimestampMixin):
    """A mined block committing a batch of evidence hashes (local proof-of-work)."""

    __tablename__ = "ledger_blocks"
    __table_args__ = (UniqueConstraint("block_index"),)

    block_index: Mapped[int] = mapped_column(Integer, nullable=False)
    prev_block_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    records_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    block_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    mined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)


class AttackDna(Base, UUIDMixin, TimestampMixin):
    """Behavioral fingerprint of a significant incident."""

    __tablename__ = "attack_dna"
    __table_args__ = (Index("ix_attack_dna_incident", "incident_id"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    dna_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    family: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    techniques: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    behaviors: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    features: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    historical_similarity: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    similar_to: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    incident: Mapped[Optional["Incident"]] = relationship()  # noqa: F821


class AttackPrediction(Base, UUIDMixin, TimestampMixin):
    """Predicted next attack stage. Always labeled as a prediction."""

    __tablename__ = "attack_predictions"
    __table_args__ = (Index("ix_predictions_incident", "incident_id"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    current_stage: Mapped[str] = mapped_column(String(48), nullable=False)
    predicted_stage: Mapped[str] = mapped_column(String(48), nullable=False)
    probability: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    recommended_control: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model_version: Mapped[str] = mapped_column(String(32), default="attack-path-v1", nullable=False)
    is_prediction: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
