"""Investigation, attack graph, risk, response, approvals, reports, agent runs, audit logs."""
# ruff: noqa: F821 (string forward references for SQLAlchemy relationships)
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin, utcnow


class Investigation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "investigations"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", nullable=False)  # RUNNING | COMPLETED | FAILED
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verdict: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    timeline: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    evidence_summary: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    agent_run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    evidence: Mapped[List["InvestigationEvidence"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )


class InvestigationEvidence(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "investigation_evidence"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(128), default="event-correlation", nullable=False)

    investigation: Mapped[Investigation] = relationship(back_populates="evidence")


class AttackNode(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "attack_nodes"
    __table_args__ = (Index("ix_attack_nodes_incident", "incident_id"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    node_key: Mapped[str] = mapped_column(String(128), nullable=False)  # stable key within the graph
    node_type: Mapped[str] = mapped_column(String(32), nullable=False)  # ATTACKER | IP | USER | DEVICE | PROCESS | SERVER | DATABASE | DOMAIN | MALWARE | TECHNIQUE | ASSET
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    properties: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="attack_nodes")


class AttackEdge(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "attack_edges"
    __table_args__ = (Index("ix_attack_edges_incident", "incident_id"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    source_key: Mapped[str] = mapped_column(String(128), nullable=False)
    target_key: Mapped[str] = mapped_column(String(128), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(32), nullable=False)  # CONNECTED_TO | ACCESSED | AUTHENTICATED | EXECUTED | ESCALATED | EXFILTRATED
    properties: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="attack_edges")


class RiskScore(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "risk_scores"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity_label: Mapped[str] = mapped_column(String(16), nullable=False)
    factors: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), default="v1", nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="risk_records")


class ResponseRecommendation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "response_recommendations"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    impact: Mapped[str] = mapped_column(String(16), nullable=False)  # LOW | MEDIUM | HIGH
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)  # PENDING | APPROVED | REJECTED | EXECUTED | FAILED
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="recommendations")
    approval: Mapped[Optional["ApprovalRequest"]] = relationship(back_populates="recommendation", uselist=False)


class ApprovalRequest(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "approval_requests"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    recommendation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("response_recommendations.id", ondelete="CASCADE"), nullable=False
    )
    requested_by: Mapped[str] = mapped_column(String(128), default="response-agent", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)  # PENDING | APPROVED | REJECTED
    decision_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    decision_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="approvals")
    recommendation: Mapped[ResponseRecommendation] = relationship(back_populates="approval")


class IncidentReport(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incident_reports"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    report_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    html_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pdf_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="reports")


class AIAgentRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ai_agent_runs"
    __table_args__ = (Index("ix_agent_runs_incident", "incident_id"), Index("ix_agent_runs_status", "status"))

    agent_name: Mapped[str] = mapped_column(String(64), nullable=False)
    run_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    incident_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", nullable=False)  # RUNNING | COMPLETED | FAILED
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    tools_used: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ActionLog(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "action_logs"
    __table_args__ = (Index("ix_action_logs_actor", "actor"), Index("ix_action_logs_created_at", "created_at"))

    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    detail: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
