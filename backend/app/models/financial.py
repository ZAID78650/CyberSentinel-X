"""Financial cybercrime intelligence models."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column as _Column, DateTime, Float, Integer, String, Text, Boolean, ForeignKey, Index, JSON,
)
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin, new_uuid, utcnow

# Use Column directly from sqlalchemy for backward-compatible style
Column = _Column


class FinancialComplaint(UUIDMixin, TimestampMixin, Base):
    """A cybercrime complaint filed with the National Cyber Crime Portal."""
    __tablename__ = "financial_complaints"

    complaint_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    district: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    city: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fraud_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    complaint_amount: Mapped[float] = mapped_column(Float, default=0.0)
    reported_amount: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="FILED")
    victim_account_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    suspect_account_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transaction_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    complaint_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    occurrence_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FinancialTransaction(UUIDMixin, TimestampMixin, Base):
    """A transaction linked to a cybercrime investigation."""
    __tablename__ = "financial_transactions"

    transaction_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    complaint_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    from_account: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    to_account: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    transaction_type: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(32), default="ONLINE")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    fraud_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    district: Mapped[str | None] = mapped_column(String(64), nullable=True)


class FinancialAccount(UUIDMixin, TimestampMixin, Base):
    """An account involved in cybercrime — victim, suspect, or mule."""
    __tablename__ = "financial_accounts"

    account_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False)
    bank_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ifsc: Mapped[str | None] = mapped_column(String(16), nullable=True)
    state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    district: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    linked_complaints: Mapped[int] = mapped_column(Integer, default=0)
    total_transaction_volume: Mapped[float] = mapped_column(Float, default=0.0)
    is_frozen: Mapped[bool] = mapped_column(Boolean, default=False)


class WithdrawalZone(UUIDMixin, TimestampMixin, Base):
    """A geographic zone with predicted withdrawal risk."""
    __tablename__ = "withdrawal_zones"

    zone_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    zone_name: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    district: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    latitude: Mapped[float] = mapped_column(Float, nullable=False)
    longitude: Mapped[float] = mapped_column(Float, nullable=False)
    risk_probability: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="LOW")
    complaint_count: Mapped[int] = mapped_column(Integer, default=0)
    transaction_count: Mapped[int] = mapped_column(Integer, default=0)
    historical_withdrawals: Mapped[int] = mapped_column(Integer, default=0)
    recent_activity_spike: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    model_version: Mapped[str] = mapped_column(String(32), default="XGBoost-v4")


class WithdrawalPrediction(UUIDMixin, TimestampMixin, Base):
    """A predictive alert for high-risk withdrawal activity."""
    __tablename__ = "withdrawal_predictions"

    prediction_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    alert_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    zone_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_probability: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    predicted_zone: Mapped[str] = mapped_column(String(128), nullable=False)
    time_window_start: Mapped[str | None] = mapped_column(String(8), nullable=True)
    time_window_end: Mapped[str | None] = mapped_column(String(8), nullable=True)
    crime_pattern: Mapped[str] = mapped_column(String(64), nullable=False)
    related_complaints: Mapped[int] = mapped_column(Integer, default=0)
    model_version: Mapped[str] = mapped_column(String(32), default="XGBoost-v4")
    is_actioned: Mapped[bool] = mapped_column(Boolean, default=False)
    actioned_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    district: Mapped[str | None] = mapped_column(String(64), nullable=True)
