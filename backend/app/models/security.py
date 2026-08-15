"""Security events, alerts, incidents, assets and notifications."""
# ruff: noqa: F821 (string forward references for SQLAlchemy relationships)
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin, utcnow

EVENT_TYPES = [
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "NEW_DEVICE",
    "UNUSUAL_LOCATION",
    "PRIVILEGE_ESCALATION",
    "SUSPICIOUS_PROCESS",
    "FILE_ACCESS",
    "DATABASE_ACCESS",
    "DATA_DOWNLOAD",
    "DATA_EXFILTRATION",
    "MALWARE_DETECTED",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "SUSPICIOUS_NETWORK_CONNECTION",
]

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

ALERT_STATUSES = ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"]
INCIDENT_STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]


class Asset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)  # server | workstation | database | domain ...
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    criticality: Mapped[int] = mapped_column(Integer, default=5, nullable=False)  # 0-10
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class SecurityEvent(Base, UUIDMixin):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_source_ip", "source_ip"),
        Index("ix_events_event_type", "event_type"),
    )

    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="LOW", nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(128), default="synthetic", nullable=False)
    metadata_: Mapped[Optional[Dict[str, Any]]] = mapped_column("metadata", JSON, nullable=True)

    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    detection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="GENERIC", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_event_ids: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    incident: Mapped[Optional["Incident"]] = relationship(back_populates="alert", uselist=False)


class Incident(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_label: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    category: Mapped[str] = mapped_column(String(64), default="GENERIC", nullable=False)
    alert_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    alert: Mapped[Optional[Alert]] = relationship(back_populates="incident")
    events: Mapped[List["IncidentEvent"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    mitre_mappings: Mapped[List["IncidentMitreMapping"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    attack_nodes: Mapped[List["AttackNode"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    attack_edges: Mapped[List["AttackEdge"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    risk_records: Mapped[List["RiskScore"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    recommendations: Mapped[List["ResponseRecommendation"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    approvals: Mapped[List["ApprovalRequest"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    reports: Mapped[List["IncidentReport"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base, UUIDMixin):
    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    event_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="events")


class Notification(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)  # alert | incident | approval | system
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
