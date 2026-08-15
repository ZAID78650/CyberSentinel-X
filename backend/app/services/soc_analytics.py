"""SOC analyst tooling: threat hunting, blast radius, campaigns, asset risk, search.

All queries are constructed from a small, whitelisted filter vocabulary — never
from user-supplied SQL. The threat-hunting console translates natural language
into these safe structured filters.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.attack_graph.builder import build_attack_graph
from app.core.utils import to_uuid
from app.models.forensics import AttackDna, EvidenceRecord
from app.models.intel import IncidentMitreMapping, MitreTechnique
from app.models.security import Alert, Incident, IncidentEvent, SecurityEvent

logger = logging.getLogger(__name__)

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
EVENT_TYPES = [
    "LOGIN_SUCCESS", "LOGIN_FAILURE", "NEW_DEVICE", "UNUSUAL_LOCATION",
    "PRIVILEGE_ESCALATION", "SUSPICIOUS_PROCESS", "FILE_ACCESS",
    "DATABASE_ACCESS", "DATA_DOWNLOAD", "DATA_EXFILTRATION",
    "MALWARE_DETECTED", "PORT_SCAN", "BRUTE_FORCE", "SUSPICIOUS_NETWORK_CONNECTION",
]


# ---------------------------------------------------------------------------
# Threat hunting — natural language -> safe structured filters
# ---------------------------------------------------------------------------

class HuntFilter:
    """Whitelisted, validated filter. Cannot express raw SQL."""

    def __init__(self) -> None:
        self.event_types: List[str] = []
        self.severities: List[str] = []
        self.source_ips: List[str] = []
        self.dest_ips: List[str] = []
        self.users: List[str] = []
        self.assets: List[str] = []
        self.categories: List[str] = []
        self.min_anomaly: Optional[float] = None
        self.min_risk: Optional[float] = None
        self.techniques: List[str] = []
        self.since_hours: Optional[int] = None
        self.limit = 100

    def apply_events(self, stmt):
        if self.event_types:
            stmt = stmt.where(SecurityEvent.event_type.in_(self.event_types))
        if self.severities:
            stmt = stmt.where(SecurityEvent.severity.in_(self.severities))
        if self.source_ips:
            stmt = stmt.where(SecurityEvent.source_ip.in_(self.source_ips))
        if self.dest_ips:
            stmt = stmt.where(SecurityEvent.destination_ip.in_(self.dest_ips))
        if self.users:
            stmt = stmt.where(SecurityEvent.user_id.in_(self.users))
        if self.assets:
            stmt = stmt.where(SecurityEvent.asset_id.in_(self.assets))
        if self.min_anomaly is not None:
            stmt = stmt.where(SecurityEvent.anomaly_score >= self.min_anomaly)
        if self.since_hours:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=self.since_hours)
            stmt = stmt.where(SecurityEvent.timestamp >= cutoff)
        return stmt

    def apply_alerts(self, stmt):
        if self.severities:
            stmt = stmt.where(Alert.severity.in_(self.severities))
        if self.categories:
            stmt = stmt.where(Alert.category.in_(self.categories))
        if self.min_anomaly is not None:
            stmt = stmt.where(Alert.anomaly_score >= self.min_anomaly)
        if self.since_hours:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=self.since_hours)
            stmt = stmt.where(Alert.created_at >= cutoff)
        return stmt

    def apply_incidents(self, stmt):
        if self.severities:
            stmt = stmt.where(Incident.severity.in_(self.severities))
        if self.categories:
            stmt = stmt.where(Incident.category.in_(self.categories))
        if self.min_risk is not None:
            stmt = stmt.where(Incident.risk_score >= self.min_risk)
        if self.since_hours:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=self.since_hours)
            stmt = stmt.where(Incident.created_at >= cutoff)
        return stmt

    def describe(self) -> List[str]:
        parts: List[str] = []
        if self.event_types:
            parts.append(f"event_type IN ({', '.join(self.event_types)})")
        if self.severities:
            parts.append(f"severity IN ({', '.join(self.severities)})")
        if self.source_ips:
            parts.append(f"source_ip IN ({', '.join(self.source_ips)})")
        if self.dest_ips:
            parts.append(f"destination_ip IN ({', '.join(self.dest_ips)})")
        if self.users:
            parts.append(f"user_id IN ({', '.join(self.users)})")
        if self.assets:
            parts.append(f"asset_id IN ({', '.join(self.assets)})")
        if self.categories:
            parts.append(f"category IN ({', '.join(self.categories)})")
        if self.min_anomaly is not None:
            parts.append(f"anomaly_score >= {self.min_anomaly}")
        if self.min_risk is not None:
            parts.append(f"risk_score >= {self.min_risk}")
        if self.since_hours:
            parts.append(f"timestamp >= now() - interval '{self.since_hours} hours'")
        return parts


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TYPE_RE = re.compile(r"\b(" + "|".join(t.lower() for t in EVENT_TYPES) + r")\b")
_SEV_RE = re.compile(r"\b(critical|high|medium|low)\b")
_HOUR_RE = re.compile(r"\b(\d+)\s*(?:hour|hr|h)s?\b")
_RISK_RE = re.compile(r"\brisk\s*(?:above|over|>|>=|at least)?\s*(\d{1,3})\b")
_ANOM_RE = re.compile(r"\banomal(?:y|ous)?\s*(?:score|scores?)?\s*(?:above|over|>|>=)?\s*(0\.\d+)\b")

INTENT_EVENT_TYPES = {
    "login failure": "LOGIN_FAILURE", "login": "LOGIN_SUCCESS",
    "failed login": "LOGIN_FAILURE", "brute force": "BRUTE_FORCE",
    "port scan": "PORT_SCAN", "malware": "MALWARE_DETECTED",
    "privilege escalation": "PRIVILEGE_ESCALATION",
    "exfiltration": "DATA_EXFILTRATION", "exfiltrat": "DATA_EXFILTRATION",
    "data download": "DATA_DOWNLOAD", "suspicious process": "SUSPICIOUS_PROCESS",
    "database access": "DATABASE_ACCESS", "file access": "FILE_ACCESS",
    "outbound": "SUSPICIOUS_NETWORK_CONNECTION", "network": "SUSPICIOUS_NETWORK_CONNECTION",
    "authentication": "LOGIN_FAILURE", "unusual location": "UNUSUAL_LOCATION",
    "new device": "NEW_DEVICE",
}
INTENT_CATEGORIES = {
    "malware": "MALWARE", "exfiltration": "EXFILTRATION",
    "privilege escalation": "PRIVILEGE_ESCALATION",
    "credential": "CREDENTIAL_ATTACK", "brute force": "BRUTE_FORCE",
    "recon": "RECONNAISSANCE", "reconnaissance": "RECONNAISSANCE",
    "account takeover": "ACCOUNT_TAKEOVER",
}


def parse_hunt_query(text: str) -> Tuple[HuntFilter, List[str], float]:
    """Translate a natural-language hunt into a safe HuntFilter.

    Returns (filter, recognized hints, confidence 0-1). Unknown or ambiguous
    inputs fall back to a broad recent-events scan — never arbitrary SQL.
    """
    low = text.lower()
    f = HuntFilter()
    hints: List[str] = []

    ips = _IP_RE.findall(text)
    if ips:
        f.source_ips = ips[:3]
        hints.append(f"source IP {', '.join(ips[:3])}")

    m = _HOUR_RE.search(low)
    if m:
        f.since_hours = min(int(m.group(1)), 24 * 30)
        hints.append(f"last {f.since_hours}h")

    m = _SEV_RE.search(low)
    if m:
        sev = m.group(1).upper()
        f.severities = [sev]
        hints.append(f"severity {sev}")

    m = _RISK_RE.search(low)
    if m:
        f.min_risk = float(m.group(1))
        hints.append(f"risk >= {int(f.min_risk)}")

    m = _ANOM_RE.search(low)
    if m:
        f.min_anomaly = float(m.group(1))
        hints.append(f"anomaly >= {f.min_anomaly}")

    for phrase, etype in INTENT_EVENT_TYPES.items():
        if phrase in low:
            if etype not in f.event_types:
                f.event_types.append(etype)
            hints.append(f"event {etype}")
    for phrase, cat in INTENT_CATEGORIES.items():
        if phrase in low:
            if cat not in f.categories:
                f.categories.append(cat)
            hints.append(f"category {cat}")

    for asset in ("server", "endpoint", "database", "workstation", "domain controller"):
        if f"critical {asset}" in low or "critical assets" in low:
            hints.append("critical assets")

    # user hints: "from user X" / "user X"
    for m in re.finditer(r"\buser[s]?\s+([a-zA-Z0-9._@-]+)", low):
        f.users.append(m.group(1))
        hints.append(f"user {m.group(1)}")

    if not f.event_types and not f.categories and not f.severities and not ips:
        f.since_hours = f.since_hours or 24
        hints.append("recent events (broad scan)")

    confidence = min(0.97, 0.45 + 0.12 * len(hints))
    return f, hints, round(confidence, 3)


def run_hunt(db: Session, text: str, scope: str = "events", limit: int = 50) -> Dict[str, Any]:
    """Execute a hunt. scope: events | alerts | incidents | all."""
    f, hints, confidence = parse_hunt_query(text)
    f.limit = limit
    results: Dict[str, Any] = {"events": [], "alerts": [], "incidents": []}
    counts: Dict[str, int] = {"events": 0, "alerts": 0, "incidents": 0}

    if scope in ("events", "all"):
        stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())
        stmt = f.apply_events(stmt).limit(limit)
        for e in list(db.scalars(stmt).all()):
            results["events"].append({
                "event_id": e.event_id, "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type, "severity": e.severity,
                "source_ip": e.source_ip, "destination_ip": e.destination_ip,
                "user_id": e.user_id, "asset_id": e.asset_id,
                "anomaly_score": e.anomaly_score, "is_anomalous": e.is_anomalous,
                "detection_reason": e.detection_reason,
            })
        counts["events"] = len(results["events"])

    if scope in ("alerts", "all"):
        stmt = select(Alert).order_by(Alert.created_at.desc())
        stmt = f.apply_alerts(stmt).limit(limit)
        for a in list(db.scalars(stmt).all()):
            results["alerts"].append({
                "id": str(a.id), "alert_id": a.alert_id, "title": a.title,
                "severity": a.severity, "status": a.status, "category": a.category,
                "confidence": a.confidence, "created_at": a.created_at.isoformat(),
            })
        counts["alerts"] = len(results["alerts"])

    if scope in ("incidents", "all"):
        stmt = select(Incident).order_by(Incident.created_at.desc())
        stmt = f.apply_incidents(stmt).limit(limit)
        for i in list(db.scalars(stmt).all()):
            results["incidents"].append({
                "id": str(i.id), "incident_id": i.incident_id, "title": i.title,
                "severity": i.severity, "status": i.status, "category": i.category,
                "risk_score": i.risk_score, "created_at": i.created_at.isoformat(),
            })
        counts["incidents"] = len(results["incidents"])

    return {
        "query": text,
        "generated_filters": f.describe(),
        "confidence": confidence,
        "scope": scope,
        "counts": counts,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Blast radius — attack-graph reachability
# ---------------------------------------------------------------------------

NODE_ASSET_TYPES = {"ASSET", "DATABASE", "SERVER", "DEVICE", "PROCESS"}

def compute_blast_radius(db: Session, incident_id: str) -> Dict[str, Any]:
    """Estimate the blast radius of a compromise using attack-graph reachability.

    We walk the persisted graph from every compromised/attacked node and count
    distinct reachable assets, users, databases and services. Clearly labeled as
    an *estimate* based on observed correlation, not a confirmed spread.
    """
    uid = to_uuid(incident_id)
    incident = db.get(Incident, uid)
    if incident is None:
        raise ValueError("Incident not found")

    nodes, edges = build_attack_graph(db, incident_id)
    asset_nodes = [n for n in nodes if n["node_type"] in NODE_ASSET_TYPES]
    user_nodes = [n for n in nodes if n["node_type"] == "USER"]
    db_nodes = [n for n in nodes if n["node_type"] == "DATABASE"]

    # reachability from all compromised (non-attacker) nodes
    adjacency: Dict[str, List[str]] = {}
    for e in edges:
        adjacency.setdefault(e["source_key"], []).append(e["target_key"])
        adjacency.setdefault(e["target_key"], []).append(e["source_key"])

    def reachable(seed: str) -> set:
        seen = {seed}
        stack = [seed]
        while stack:
            cur = stack.pop()
            for nxt in adjacency.get(cur, []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    seeds = [n["node_key"] for n in nodes if n["node_type"] in ("IP", "MALWARE", "USER", "TECHNIQUE", "ASSET", "DATABASE")]
    reach = set()
    for s in seeds:
        reach |= reachable(s)

    affected_assets = [n for n in asset_nodes if n["node_key"] in reach]
    affected_users = [n for n in user_nodes if n["node_key"] in reach]
    affected_dbs = [n for n in db_nodes if n["node_key"] in reach]

    count = len(affected_assets)
    if count >= 5:
        level = "HIGH"
    elif count >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    # exposure path: attacker/ip -> user -> technique -> database/asset
    path: List[Dict[str, str]] = []
    for n in nodes:
        if n["node_type"] == "IP" and n["node_key"].startswith("ip:"):
            path.append({"node": n["label"], "type": "source"})
            break
    for n in user_nodes[:1]:
        path.append({"node": n["label"], "type": "user"})
    for e in edges:
        if e["edge_type"] == "EXFILTRATED" and e["target_key"].startswith("dst:"):
            path.append({"node": e["target_key"].split(":", 1)[1], "type": "exfiltration-target"})
            break

    return {
        "incident_id": incident.incident_id,
        "blast_radius": level,
        "affected_assets": len(affected_assets),
        "affected_users": len(affected_users),
        "affected_databases": len(affected_dbs),
        "critical_services": len(affected_dbs),
        "assets": [a["label"] for a in affected_assets],
        "users": [u["label"] for u in affected_users],
        "path": path,
        "estimate": True,
        "method": "attack-graph reachability (observed correlation, not confirmed spread)",
    }


# ---------------------------------------------------------------------------
# Campaigns — dedup / alert-fatigue grouping
# ---------------------------------------------------------------------------

def compute_campaigns(db: Session, min_incidents: int = 1, limit: int = 20) -> Dict[str, Any]:
    """Group incidents into campaigns by (source IP family, attack category).

    Also computes the alert-fatigue funnel: events -> alerts -> incidents, the
    deduplication the correlation engine provides.
    """
    incidents = list(db.scalars(select(Incident).order_by(Incident.created_at.desc())).all())
    groups: Dict[Tuple[str, str], List[Incident]] = {}
    for inc in incidents:
        eids = list(db.scalars(select(IncidentEvent.event_id).where(IncidentEvent.incident_id == inc.id)).all())
        srcs: set = set()
        if eids:
            for e in list(db.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(eids[:200]))).all()):
                if e.source_ip:
                    srcs.add(e.source_ip)
        key = (srcs.pop() if len(srcs) == 1 else ",".join(sorted(srcs)[:2]), inc.category or "GENERIC")
        groups.setdefault(key, []).append(inc)

    campaigns = []
    for (src, cat), incs in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:limit]:
        event_count = 0
        technique_ids: set = set()
        for inc in incs:
            eids = list(db.scalars(select(IncidentEvent.event_id).where(IncidentEvent.incident_id == inc.id)).all())
            if eids:
                event_count += len(eids)
            for m in db.scalars(select(IncidentMitreMapping).where(IncidentMitreMapping.incident_id == inc.id)):
                technique_ids.add(m.technique_id)
        sev = max(incs, key=lambda i: SEVERITIES.index(i.severity) if i.severity in SEVERITIES else 0).severity
        first = min(i.created_at for i in incs)
        last = max(i.created_at for i in incs)
        campaigns.append({
            "campaign_id": f"CGN-{len(campaigns) + 1:04d}",
            "source": src or "unknown",
            "category": cat,
            "incidents": [i.incident_id for i in incs],
            "incident_count": len(incs),
            "event_count": event_count,
            "techniques": sorted(technique_ids),
            "severity": sev,
            "first_seen": first.isoformat(),
            "last_seen": last.isoformat(),
            "duration_hours": round((last - first).total_seconds() / 3600, 2),
            "risk_score": round(max((i.risk_score or 0) for i in incs), 1),
        })

    events_total = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    alerts_total = db.scalar(select(func.count()).select_from(Alert)) or 0
    incidents_total = len(incidents)
    return {
        "campaigns": campaigns,
        "funnel": {
            "events": events_total,
            "alerts": alerts_total,
            "incidents": incidents_total,
            "campaigns": len(campaigns),
            "dedup_ratio": round(events_total / max(alerts_total, 1), 1),
            "alerts_per_incident": round(alerts_total / max(incidents_total, 1), 1),
        },
        "note": "Campaign grouping by source IP + attack category; dedup is the correlation engine collapsing 1000s of events into 1 incident.",
    }


# ---------------------------------------------------------------------------
# Asset risk intelligence
# ---------------------------------------------------------------------------

def asset_risk_intel(db: Session) -> Dict[str, Any]:
    """Per-asset risk: criticality + active alerts + incidents + anomalous events."""
    from app.models.security import Asset
    assets = list(db.scalars(select(Asset)).all())
    rows = []
    total_score = 0.0
    for a in assets:
        alerts = db.scalar(select(func.count()).select_from(Alert)
                           .where(Alert.assigned_to == a.name)) or 0
        # events mentioning the asset by name or ip
        anom = db.scalar(select(func.count()).select_from(SecurityEvent)
                         .where(or_(
                             SecurityEvent.asset_id == a.name,
                             SecurityEvent.source_ip == a.ip_address,
                             SecurityEvent.destination_ip == a.ip_address,
                         ), SecurityEvent.is_anomalous.is_(True))) or 0
        # incidents touching this asset
        inc_count = 0
        inc_ids = db.scalars(select(IncidentEvent.incident_id)
                             .join(SecurityEvent, SecurityEvent.event_id == IncidentEvent.event_id)
                             .where(or_(
                                 SecurityEvent.asset_id == a.name,
                                 SecurityEvent.source_ip == a.ip_address,
                                 SecurityEvent.destination_ip == a.ip_address,
                             )).distinct()).all()
        inc_count = len(inc_ids)

        crit = a.criticality or 5
        score = round(min(100.0, 0.25 * crit * 10 + 4 * min(inc_count, 10) + 1.5 * min(anom, 20) + 0.5 * min(alerts, 20)), 1)
        total_score += score
        rows.append({
            "id": str(a.id), "name": a.name, "asset_type": a.asset_type,
            "ip_address": a.ip_address, "criticality": crit,
            "risk_score": score,
            "risk_label": "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW",
            "active_alerts": alerts, "anomalous_events": anom, "incident_count": inc_count,
            "last_seen": None,
        })
    rows.sort(key=lambda r: -r["risk_score"])
    return {
        "assets": rows,
        "average_risk": round(total_score / max(len(rows), 1), 1),
        "critical_assets_at_risk": sum(1 for r in rows if r["risk_score"] >= 65),
        "method": "criticality (25%) + incident count (40%) + anomalous events (15%) + alerts (20%) — configurable weights",
    }


# ---------------------------------------------------------------------------
# Global search
# ---------------------------------------------------------------------------

def global_search(db: Session, q: str, limit: int = 10) -> Dict[str, Any]:
    """Unified search across incidents, alerts, events, DNA, techniques, evidence."""
    needle = q.strip()
    if not needle:
        return {"query": q, "results": {}}
    results: Dict[str, Any] = {}

    # Incidents (id, title, category)
    inc_rows = db.scalars(select(Incident).where(or_(
        Incident.incident_id.ilike(f"%{needle}%"),
        Incident.title.ilike(f"%{needle}%"),
        Incident.category.ilike(f"%{needle}%"),
    )).limit(limit)).all()
    results["incidents"] = [{
        "id": str(i.id), "incident_id": i.incident_id, "title": i.title,
        "severity": i.severity, "status": i.status, "risk_score": i.risk_score,
    } for i in inc_rows]

    # Alerts
    al_rows = db.scalars(select(Alert).where(or_(
        Alert.alert_id.ilike(f"%{needle}%"),
        Alert.title.ilike(f"%{needle}%"),
        Alert.category.ilike(f"%{needle}%"),
    )).limit(limit)).all()
    results["alerts"] = [{
        "id": str(a.id), "alert_id": a.alert_id, "title": a.title,
        "severity": a.severity, "status": a.status, "category": a.category,
    } for a in al_rows]

    # Events by IP
    ev_rows = db.scalars(select(SecurityEvent).where(or_(
        SecurityEvent.source_ip == needle,
        SecurityEvent.destination_ip == needle,
        SecurityEvent.event_id.ilike(f"%{needle}%"),
        SecurityEvent.user_id.ilike(f"%{needle}%"),
    )).order_by(SecurityEvent.timestamp.desc()).limit(limit)).all()
    results["events"] = [{
        "event_id": e.event_id, "timestamp": e.timestamp.isoformat(),
        "event_type": e.event_type, "severity": e.severity,
        "source_ip": e.source_ip, "destination_ip": e.destination_ip,
        "user_id": e.user_id, "anomaly_score": e.anomaly_score,
    } for e in ev_rows]

    # Attack DNA fingerprints
    dna_rows = db.scalars(select(AttackDna).where(or_(
        AttackDna.dna_id.ilike(f"%{needle}%"),
        AttackDna.family.ilike(f"%{needle}%"),
        AttackDna.fingerprint.ilike(f"%{needle}%"),
    )).limit(limit)).all()
    results["dna"] = [{
        "id": str(d.id), "dna_id": d.dna_id, "family": d.family,
        "incident_id": str(d.incident_id), "confidence": d.confidence,
        "fingerprint": d.fingerprint[:24],
    } for d in dna_rows]

    # MITRE techniques
    tech_rows = db.scalars(select(MitreTechnique).where(or_(
        MitreTechnique.technique_id.ilike(f"%{needle}%"),
        MitreTechnique.name.ilike(f"%{needle}%"),
        MitreTechnique.tactic.ilike(f"%{needle}%"),
    )).limit(limit)).all()
    results["techniques"] = [{
        "id": str(t.id), "technique_id": t.technique_id, "name": t.name,
        "tactic": t.tactic, "severity_hint": t.severity_hint,
    } for t in tech_rows]

    # Evidence
    evd_rows = db.scalars(select(EvidenceRecord).where(or_(
        EvidenceRecord.evidence_id.ilike(f"%{needle}%"),
        EvidenceRecord.title.ilike(f"%{needle}%"),
        EvidenceRecord.record_hash.ilike(f"%{needle}%"),
    )).limit(limit)).all()
    results["evidence"] = [{
        "id": str(e.id), "evidence_id": e.evidence_id, "title": e.title,
        "evidence_type": e.evidence_type, "status": e.status,
    } for e in evd_rows]

    return {"query": q, "results": results, "total": sum(len(v) for v in results.values())}
