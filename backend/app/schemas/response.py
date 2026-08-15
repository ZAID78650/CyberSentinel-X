"""Response recommendations and approvals schemas."""
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class RecommendationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    action: str
    impact: str
    reason: Optional[str]
    evidence: Optional[str]
    requires_approval: bool
    status: str
    created_at: datetime
    executed_at: Optional[datetime]
    execution_summary: Optional[str]


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    recommendation_id: UUID
    requested_by: str
    status: str
    decision_by: Optional[str]
    decision_at: Optional[datetime]
    reason: Optional[str]
    created_at: datetime
    recommendation_action: Optional[str] = None
    incident_title: Optional[str] = None
    incident_severity: Optional[str] = None


class ApprovalDecision(BaseModel):
    reason: Optional[str] = None


class ApprovalDecisionOut(BaseModel):
    approval: ApprovalOut
    status: str
    message: str
    execution_summary: Optional[str] = None
