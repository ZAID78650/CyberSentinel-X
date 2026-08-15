"""Dashboard summary schema."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class KpiCard(BaseModel):
    label: str
    value: float
    change: Optional[float] = None
    trend: Optional[str] = None
    color: Optional[str] = None


class AgentStatus(BaseModel):
    name: str
    status: str  # ONLINE | RUNNING | WAITING | FAILED
    last_run: Optional[str] = None
    detail: Optional[str] = None


class DashboardSummary(BaseModel):
    kpis: List[KpiCard]
    alerts_by_severity: Dict[str, int]
    alerts_by_category: Dict[str, int]
    risk_over_time: List[Dict[str, Any]]
    top_threat_sources: List[Dict[str, Any]]
    recent_events: List[Dict[str, Any]]
    recent_incidents: List[Dict[str, Any]]
    agent_statuses: List[AgentStatus]
    ai_investigation_summary: Optional[Dict[str, Any]] = None
    response_recommendation: Optional[Dict[str, Any]] = None
