"""Investigation, attack graph and risk schemas."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class EvidenceItem(BaseModel):
    category: str
    description: str
    source: str
    detail: Optional[Dict[str, Any]] = None


class TimelineItem(BaseModel):
    timestamp: datetime
    event: str
    detail: Optional[Dict[str, Any]] = None


class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    summary: Optional[str]
    verdict: Optional[str]
    confidence: float
    timeline: List[Dict[str, Any]]
    evidence_summary: List[Dict[str, Any]]
    agent_run_id: Optional[str]


class InvestigationDetail(BaseModel):
    investigation: InvestigationOut
    evidence: List[EvidenceItem]
    mitre_mappings: List[Dict[str, Any]]


class AttackNodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str  # stable node key within the graph
    node_key: str
    node_type: str
    label: str
    properties: Dict[str, Any]


class AttackEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str  # source->target key
    source_key: str
    target_key: str
    edge_type: str
    properties: Dict[str, Any]


class GraphStats(BaseModel):
    total_nodes: int
    total_edges: int
    node_types: Dict[str, int]
    edge_types: Dict[str, int]
    density: float
    max_depth: int
    crown_jewel: Optional[str] = None
    crown_jewel_risk: Optional[float] = None
    events_analyzed: Optional[int] = 0
    attackers: Optional[int] = 0
    users: Optional[int] = 0
    techniques: Optional[int] = 0
    assets: Optional[int] = 0


class CriticalPath(BaseModel):
    nodes: List[str]
    node_labels: List[str]
    edge_types: List[str]
    total_risk: float


class AttackGraphOut(BaseModel):
    incident_id: UUID
    nodes: List[AttackNodeOut]
    edges: List[AttackEdgeOut]
    stats: Optional[GraphStats] = None
    critical_path: Optional[CriticalPath] = None


class RiskFactor(BaseModel):
    name: str
    weight: float
    score: float
    contribution: float
    evidence: str


class RiskOut(BaseModel):
    incident_id: UUID
    score: float
    severity_label: str
    confidence: float
    factors: List[RiskFactor]
    reason: str
    computed_at: datetime
