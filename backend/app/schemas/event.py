"""Security event, alert and incident schemas."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from app.models.security import EVENT_TYPES, SEVERITIES


class EventIngest(BaseModel):
    event_type: str
    severity: Optional[str] = "LOW"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    asset_id: Optional[str] = None
    source: Optional[str] = "api"
    timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("event_type")
    @classmethod
    def valid_type(cls, v: str) -> str:
        if v.upper() not in EVENT_TYPES:
            raise ValueError(f"event_type must be one of {EVENT_TYPES}")
        return v.upper()

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.upper() not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        return v.upper() if v else v


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    user_id: Optional[str]
    device_id: Optional[str]
    asset_id: Optional[str]
    source: str
    metadata: Optional[Dict[str, Any]] = Field(default=None, validation_alias=AliasChoices("metadata_", "metadata"))
    anomaly_score: Optional[float]
    is_anomalous: bool
    detection_reason: Optional[str]


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    category: str
    confidence: float
    anomaly_score: Optional[float]
    detection_reason: Optional[str]
    source_event_ids: List[str]
    created_at: datetime


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    confidence: float
    risk_score: Optional[float]
    risk_label: Optional[str]
    category: str
    alert_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: Optional[str] = None
    severity: str = "MEDIUM"
    category: str = "GENERIC"
