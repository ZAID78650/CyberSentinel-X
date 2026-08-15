"""Dashboard summary + 3D threat-analysis routes."""
import logging
import math
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.investigation import ApprovalRequest, AIAgentRun
from app.models.security import Alert, Incident, SecurityEvent
from app.models.user import User
from app.schemas.dashboard import AgentStatus, DashboardSummary, KpiCard

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

AGENT_KEYS = [
    ("Detection Agent", "detection"),
    ("Investigation Agent", "investigation"),
    ("Threat Intel Agent", "threat_intel"),
    ("Risk Engine", "risk"),
    ("Response Agent", "response"),
]


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    alerts_total = db.scalar(select(func.count()).select_from(Alert)) or 0
    alerts_critical = db.scalar(select(func.count()).select_from(Alert).where(Alert.severity == "CRITICAL")) or 0
    incidents_open = db.scalar(select(func.count()).select_from(Incident).where(Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"]))) or 0

    high_risk = db.scalar(
        select(func.max(Incident.risk_score)).where(Incident.risk_score.isnot(None))
    ) or 0
    anomalies = db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.is_anomalous.is_(True))) or 0
    pending_approvals = db.scalar(select(func.count()).select_from(ApprovalRequest).where(ApprovalRequest.status == "PENDING")) or 0

    kpis = [
        KpiCard(label="Total Alerts", value=alerts_total, color="#38bdf8"),
        KpiCard(label="Critical Alerts", value=alerts_critical, color="#f87171"),
        KpiCard(label="Active Incidents", value=incidents_open, color="#fb923c"),
        KpiCard(label="High Risk Score", value=round(float(high_risk), 1), color="#f472b6"),
        KpiCard(label="Anomalous Events", value=anomalies, color="#a78bfa"),
        KpiCard(label="Pending Approvals", value=pending_approvals, color="#facc15"),
    ]

    # Alerts by severity / category
    sev_rows = db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()
    cat_rows = db.execute(select(Alert.category, func.count()).group_by(Alert.category)).all()
    alerts_by_severity = {r[0]: r[1] for r in sev_rows}
    alerts_by_category = {r[0]: r[1] for r in cat_rows}

    # Risk over time (last 7 risk records by day)
    from app.models.investigation import RiskScore
    risk_rows = db.execute(
        select(func.date(RiskScore.created_at), func.avg(RiskScore.score))
        .group_by(func.date(RiskScore.created_at)).order_by(func.date(RiskScore.created_at))
    ).all()
    risk_over_time = [{"date": str(r[0]), "avg_risk": round(float(r[1]), 1)} for r in risk_rows]

    # Top threat sources
    ip_rows = db.execute(
        select(SecurityEvent.source_ip, func.count())
        .where(SecurityEvent.source_ip.isnot(None))
        .group_by(SecurityEvent.source_ip).order_by(func.count().desc()).limit(6)
    ).all()
    top_threat_sources = [{"source": r[0], "count": r[1]} for r in ip_rows]

    # Recent events (last 12)
    recent_events = db.execute(
        select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(12)
    ).scalars().all()
    recent_events_out = [
        {
            "event_id": e.event_id, "event_type": e.event_type, "severity": e.severity,
            "source_ip": e.source_ip, "user_id": e.user_id, "timestamp": e.timestamp,
            "is_anomalous": e.is_anomalous,
        }
        for e in recent_events
    ]

    recent_incidents = db.execute(
        select(Incident).order_by(Incident.created_at.desc()).limit(6)
    ).scalars().all()
    recent_incidents_out = [
        {
            "id": str(i.id), "incident_id": i.incident_id, "title": i.title, "severity": i.severity,
            "status": i.status, "risk_score": i.risk_score, "risk_label": i.risk_label,
            "category": i.category, "created_at": i.created_at,
        }
        for i in recent_incidents
    ]

    # Agent statuses
    agent_statuses = []
    for display, key in AGENT_KEYS:
        last_run = db.scalar(
            select(AIAgentRun).where(AIAgentRun.agent_name == display).order_by(AIAgentRun.created_at.desc())
        )
        status = "ONLINE"
        if last_run and last_run.status == "RUNNING":
            status = "RUNNING"
        elif key == "response" and pending_approvals:
            status = "WAITING"
        agent_statuses.append(AgentStatus(
            name=display, status=status,
            last_run=last_run.created_at.isoformat() if last_run else None,
            detail=last_run.result_summary if last_run else None,
        ))

    # AI investigation summary + response recommendation from latest incident
    latest_incident = db.execute(
        select(Incident).order_by(Incident.created_at.desc()).limit(1)
    ).scalars().first()
    ai_summary = None
    response_rec = None
    if latest_incident:
        from app.models.investigation import Investigation, ResponseRecommendation
        inv = db.scalar(select(Investigation).where(Investigation.incident_id == latest_incident.id)
                        .order_by(Investigation.created_at.desc()))
        if inv and inv.summary:
            ai_summary = {
                "incident_id": str(latest_incident.id),
                "incident_title": latest_incident.title,
                "summary": inv.summary,
                "verdict": inv.verdict,
                "confidence": inv.confidence,
            }
        rec = db.scalar(select(ResponseRecommendation)
                        .where(ResponseRecommendation.incident_id == latest_incident.id)
                        .order_by(ResponseRecommendation.created_at.desc()))
        if rec:
            response_rec = {
                "incident_id": str(latest_incident.id),
                "action": rec.action, "impact": rec.impact, "status": rec.status,
            }

    return DashboardSummary(
        kpis=kpis,
        alerts_by_severity=alerts_by_severity,
        alerts_by_category=alerts_by_category,
        risk_over_time=risk_over_time,
        top_threat_sources=top_threat_sources,
        recent_events=recent_events_out,
        recent_incidents=recent_incidents_out,
        agent_statuses=agent_statuses,
        ai_investigation_summary=ai_summary,
        response_recommendation=response_rec,
    )


# ---------------------------------------------------------------------------
# 3D threat analysis (UNSW-NB15 flow space)
# ---------------------------------------------------------------------------

_CACHE: dict = {"ts": 0.0, "data": None}


def _log10(v) -> float:
    try:
        return round(math.log10(max(float(v), 0.0) + 1.0), 3)
    except (TypeError, ValueError):
        return 0.0


def _cached(key: str, ttl: float, builder):
    entry = _CACHE.setdefault(key, {"ts": 0.0, "data": None})
    now = time.time()
    if entry["data"] is not None and now - entry["ts"] < ttl:
        return entry["data"]
    entry["data"] = builder()
    entry["ts"] = now
    return entry["data"]


@router.get("/threat-space")
def threat_space(
    limit: int = Query(1500, ge=100, le=4000),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Stratified 3D point cloud of network flows (bytes in/out vs rate)."""

    def build():
        sample = db.execute(
            select(SecurityEvent).order_by(func.random()).limit(min(limit * 3, 6000))
        ).scalars().all()
        points = []
        for e in sample:
            meta = e.metadata_ or {}
            if meta.get("dataset") != "unsw-nb15":
                continue
            points.append({
                "x": _log10(meta.get("sbytes", 0)),
                "y": _log10(meta.get("dbytes", 0)),
                "z": _log10(meta.get("rate", 0)),
                "spkts": int(meta.get("spkts") or 0),
                "dpkts": int(meta.get("dpkts") or 0),
                "category": meta.get("attack_cat") or e.event_type,
                "severity": e.severity,
                "is_anomalous": e.is_anomalous,
                "anomaly_score": e.anomaly_score,
                "event_type": e.event_type,
                "source_ip": e.source_ip,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            })
            if len(points) >= limit:
                break
        return points

    return _cached("threat_space", 30.0, build)


@router.get("/attack-distribution")
def attack_distribution(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """3D-bar data: attack family x hour-of-day counts (24h rhythm)."""

    def build():
        rows = db.execute(
            select(SecurityEvent.metadata_, SecurityEvent.timestamp)
            .where(SecurityEvent.is_anomalous.is_(True))
        ).all()
        agg: dict = {}
        for meta, ts in rows:
            cat = (meta or {}).get("attack_cat") or "Normal"
            hour = ts.hour if ts else 0
            key = (cat, hour)
            agg[key] = agg.get(key, 0) + 1
        out = [
            {"category": cat, "hour": hour, "count": count}
            for (cat, hour), count in sorted(agg.items())
        ]
        return out

    return _cached("attack_distribution", 60.0, build)


@router.get("/events-timeseries")
def events_timeseries(
    hours: int = Query(48, ge=6, le=168),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Hourly event volume (total + anomalous) for the live flow charts."""

    def build():
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = db.execute(
            select(SecurityEvent.timestamp, SecurityEvent.is_anomalous)
            .where(SecurityEvent.timestamp >= cutoff)
        ).all()
        buckets: dict = {}
        for ts, anom in rows:
            key = ts.replace(minute=0, second=0, microsecond=0) if ts else None
            if key is None:
                continue
            b = buckets.setdefault(key, {"time": key.isoformat(), "total": 0, "anomalous": 0})
            b["total"] += 1
            if anom:
                b["anomalous"] += 1
        return sorted(buckets.values(), key=lambda b: b["time"])

    return _cached("events_timeseries", 30.0, build)
