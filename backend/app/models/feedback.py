"""Analyst feedback loop: analyst labels on alerts drive FPR/TPR tracking.

Feedback is never applied to models silently — it is stored, surfaced in the
analytics, and used to tune correlation thresholds only through an explicit
retraining step. Each label records who made it and when (audit trail).
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

FEEDBACK_LABELS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "UNKNOWN"]


class CorrelationSetting(Base, TimestampMixin):
    """An explicit, audited correlation-threshold adjustment per alert category.

    Set only through the retrain-with-consent endpoint; never modified
    silently. The Detection Agent reads these when scoring new events.
    """

    __tablename__ = "correlation_settings"

    category: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    base_floor: Mapped[float] = mapped_column(Float, default=0.55, nullable=False)
    floor_adjustment: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    applied_by: Mapped[str] = mapped_column(String(128), nullable=False)


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
