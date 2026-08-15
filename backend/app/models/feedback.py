"""Analyst feedback loop: analyst labels on alerts drive FPR/TPR tracking.

Feedback is never applied to models silently — it is stored, surfaced in the
analytics, and used to tune correlation thresholds only through an explicit
retraining step. Each label records who made it and when (audit trail).
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

FEEDBACK_LABELS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "UNKNOWN"]


class AnalystFeedback(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "analyst_feedback"
    __table_args__ = (
        Index("ix_feedback_alert", "alert_id"),
        Index("ix_feedback_analyst", "analyst"),
        Index("ix_feedback_label", "label"),
    )

    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(32), nullable=False)  # TRUE_POSITIVE | FALSE_POSITIVE | BENIGN | UNKNOWN
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    analyst: Mapped[str] = mapped_column(String(128), nullable=False)  # user email / display name

    alert: Mapped[Optional["Alert"]] = relationship(back_populates="feedback")  # noqa: F821
