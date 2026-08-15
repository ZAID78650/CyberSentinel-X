"""Report and analytics schemas."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    report_id: str
    title: str
    created_at: datetime
    created_by: Optional[str]


class ReportDetail(BaseModel):
    report: ReportOut
    content: Dict[str, Any]
    pdf_available: bool
    pdf_url: Optional[str] = None


class AnalyticsOut(BaseModel):
    events_total: int
    events_by_type: Dict[str, int]
    alerts_total: int
    alerts_by_severity: Dict[str, int]
    alerts_by_category: Dict[str, int]
    incidents_total: int
    incidents_by_status: Dict[str, int]
    risk_over_time: List[Dict[str, Any]]
    top_threat_sources: List[Dict[str, Any]]
    top_attack_techniques: List[Dict[str, Any]]
    actions_executed: int
    approvals_pending: int
    detection_accuracy: Optional[Dict[str, Any]] = None
