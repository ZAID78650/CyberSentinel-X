"""Threat intelligence, MITRE and knowledge base schemas."""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ThreatIndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    indicator_type: str
    value: str
    confidence: float
    severity: str
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    description: Optional[str]


class ThreatIntelSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=512)
    indicator_type: Optional[str] = None


class ThreatIntelHit(BaseModel):
    indicator_type: str
    value: str
    confidence: float
    severity: str
    source: str
    tags: List[str]
    description: Optional[str]
    match_reason: Optional[str] = None


class ThreatIntelSearchResponse(BaseModel):
    query: str
    hits: List[ThreatIntelHit]
    source_count: int


class MitreTechniqueOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    technique_id: str
    name: str
    tactic: str
    description: Optional[str]
    detection: Optional[str]
    severity_hint: str
    platforms: List[str]
    url: Optional[str]


class MitreMappingOut(BaseModel):
    technique_id: str
    name: str
    tactic: str
    confidence: float
    evidence: Optional[str]
