"""Allowlisted tools available to agents.

Every tool is a pure, read-mostly function over the database. No tool can
execute shell commands, run arbitrary Python, touch arbitrary files, or
reach external systems. Tool execution is logged via AIAgentRun.tools_used.
"""
import logging
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.attack_graph.builder import build_attack_graph
from app.models.intel import ThreatIndicator
from app.models.security import SecurityEvent
from app.rag.rag_service import retrieve_context
from app.risk.engine import compute_risk
from app.services.detection import event_to_dict
from app.threat_intel.adapter import ThreatIntelAdapter

logger = logging.getLogger(__name__)


def _ok(data: Any, summary: str) -> Dict[str, Any]:
    return {"data": data, "summary": summary}


# ----------------------------------------------------------------------
def search_security_events(db: Session, *, event_type: Optional[str] = None, user_id: Optional[str] = None,
                           source_ip: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type.upper())
    if user_id:
        stmt = stmt.where(SecurityEvent.user_id == user_id)
    if source_ip:
        stmt = stmt.where(SecurityEvent.source_ip == source_ip)
    events = list(db.scalars(stmt).all())
    return _ok([event_to_dict(e) for e in events],
               f"Found {len(events)} security events" + (f" for user {user_id}" if user_id else ""))


def get_user_history(db: Session, user_id: str, limit: int = 100) -> Dict[str, Any]:
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.user_id == user_id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
    )
    events = list(db.scalars(stmt).all())
    types = {}
    for e in events:
        types[e.event_type] = types.get(e.event_type, 0) + 1
    ips = sorted({e.source_ip for e in events if e.source_ip})
    return _ok({"user_id": user_id, "events": [event_to_dict(e) for e in events],
                "type_distribution": types, "known_ips": ips},
               f"User {user_id} has {len(events)} events, {len(ips)} distinct source IPs")


def get_device_history(db: Session, device_id: str, limit: int = 50) -> Dict[str, Any]:
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.device_id == device_id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
    )
    events = list(db.scalars(stmt).all())
    return _ok({"device_id": device_id, "events": [event_to_dict(e) for e in events]},
               f"Device {device_id} has {len(events)} events")


def get_asset_information(db: Session, asset_id: str) -> Dict[str, Any]:
    from app.models.security import Asset
    asset = db.scalar(select(Asset).where(Asset.name == asset_id))
    if asset is None:
        return _ok({"asset_id": asset_id, "found": False}, f"Asset {asset_id} not found in asset inventory")
    return _ok({"asset_id": str(asset.id), "name": asset.name, "asset_type": asset.asset_type,
                "ip_address": asset.ip_address, "hostname": asset.hostname,
                "criticality": asset.criticality, "owner": asset.owner, "found": True},
               f"Asset '{asset.name}' criticality {asset.criticality}/10")


def check_ip_reputation(db: Session, ip: str) -> Dict[str, Any]:
    ind = db.scalar(
        select(ThreatIndicator).where(ThreatIndicator.indicator_type == "IP", ThreatIndicator.value == ip)
    )
    if ind is None:
        return _ok({"ip": ip, "reputation": "UNKNOWN", "matched": False}, f"No intel for {ip}")
    return _ok({"ip": ip, "reputation": ind.severity, "matched": True, "confidence": ind.confidence,
                "tags": ind.tags, "description": ind.description},
               f"IP {ip} is a known {ind.severity} indicator (confidence {ind.confidence:.0%})")


def search_threat_intelligence(db: Session, query: str) -> Dict[str, Any]:
    adapter = ThreatIntelAdapter(db)
    hits = adapter.search(query)
    return _ok(hits, f"Threat intelligence returned {len(hits)} matches for '{query}'")


def search_knowledge_base(db: Session, query: str, k: int = 3) -> Dict[str, Any]:
    results = retrieve_context(db, query, k=k)
    return _ok(results, f"Knowledge base returned {len(results)} relevant documents for '{query}'")


def map_mitre_technique(db: Session, incident_id: str) -> Dict[str, Any]:
    from app.services.mitre_service import map_incident_to_mitre
    mappings = map_incident_to_mitre(db, incident_id)
    return _ok(mappings, f"Mapped incident to {len(mappings)} MITRE ATT&CK techniques")


def create_attack_graph(db: Session, incident_id: str) -> Dict[str, Any]:
    nodes, edges = build_attack_graph(db, incident_id)
    return _ok({"nodes": len(nodes), "edges": len(edges)},
               f"Attack graph reconstructed with {len(nodes)} nodes and {len(edges)} edges")


def calculate_risk(db: Session, incident_id: str) -> Dict[str, Any]:
    risk = compute_risk(db, incident_id)
    return _ok(risk, f"Risk score computed: {risk['score']}/100 ({risk['severity_label']})")


def generate_incident_report(db: Session, incident_id: str, actor: str = "report-agent") -> Dict[str, Any]:
    from app.reports.generator import generate_report
    report = generate_report(db, incident_id, actor=actor)
    return _ok({"report_id": report.report_id}, f"Incident report {report.report_id} generated")


TOOL_REGISTRY: Dict[str, Any] = {
    "search_security_events": search_security_events,
    "get_user_history": get_user_history,
    "get_device_history": get_device_history,
    "get_asset_information": get_asset_information,
    "check_ip_reputation": check_ip_reputation,
    "search_threat_intelligence": search_threat_intelligence,
    "search_knowledge_base": search_knowledge_base,
    "map_mitre_technique": map_mitre_technique,
    "create_attack_graph": create_attack_graph,
    "calculate_risk": calculate_risk,
    "generate_incident_report": generate_incident_report,
}
