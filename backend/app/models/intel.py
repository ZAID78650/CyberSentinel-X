"""Threat intelligence, MITRE ATT&CK and knowledge base models."""
# ruff: noqa: F821 (string forward references for SQLAlchemy relationships)
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin, utcnow


class ThreatIndicator(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "threat_indicators"
    __table_args__ = (Index("ix_indicators_type_value", "indicator_type", "value"),)

    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)  # IP | DOMAIN | URL | HASH | CVE | MALWARE | TECHNIQUE
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    source: Mapped[str] = mapped_column(String(128), default="local", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ThreatIntelligenceSource(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "threat_intelligence_sources"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), default="local", nullable=False)  # local | stix | taxii | api
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    base_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class MitreTechnique(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)  # e.g. T1078
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(64), nullable=False)  # initial-access | credential-access | ...
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity_hint: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    platforms: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)


class IncidentMitreMapping(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incident_mitre_mapping"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    technique_id: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="mitre_mappings")


class KnowledgeDocument(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "knowledge_documents"

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(128), default="local", nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    doc_type: Mapped[str] = mapped_column(String(64), default="policy", nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
