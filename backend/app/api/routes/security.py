"""Security / firewall / assets / playbooks routes."""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import cast, func, select, String
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.core.firewall import firewall_stats, firewall_summary, malware_guard_test_payload
from app.ml.evaluate import run_evaluation
from app.models.intel import KnowledgeDocument
from app.models.security import Asset, Incident, SecurityEvent
from app.models.user import User
from app.schemas.common import Paginated
from app.threat_intel.adapter import ThreatIntelAdapter

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/firewall")
def get_firewall(_user: User = Depends(get_current_user)):
    return firewall_summary()


@router.get("/firewall/layers")
def get_firewall_layers(_user: User = Depends(get_current_user)):
    return {"layers": firewall_stats()}


@router.get("/firewall/blocks")
def get_firewall_blocks(limit: int = Query(50, ge=1, le=200), _user: User = Depends(get_current_user)):
    """Most recent firewall block events (in-memory ring buffer, newest first)."""
    from app.core.firewall import firewall_block_log
    return {"blocks": firewall_block_log(limit)}


@router.post("/firewall/test-malware")
def test_malware_guard(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Demo endpoint: sends a payload referencing a known malware hash. The
    MALWARE_GUARD middleware intercepts it first and returns 403 — this route
    only runs when the payload does not match the feed (honest no-match path)."""
    hit = malware_guard_test_payload()
    from app.core.firewall import _load_malware_set
    matched = str(hit.get("hash", "")).lower() in _load_malware_set()
    return {
        "tested": True,
        "matched": matched,
        "payload": hit,
        "hint": "A matching request is blocked by the middleware with 403 before this route runs." if matched
                else "The test hash is not in the current feed — the request passed through.",
    }


class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=512)


@router.post("/analyze")
def analyze_threat(req: AnalyzeRequest, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """One-click threat analyzer: intel match + event history + explainable
    risk + next-stage prediction + firewall verdict for any indicator.
    Every value is computed from the stores — no fabricated analysis."""
    from app.models.forensics import AttackPrediction

    q = req.query.strip()
    adapter = ThreatIntelAdapter(db)
    intel = adapter.search(q)

    # --- event history ----------------------------------------------------
    ql = q.lower()
    stmt = select(SecurityEvent).where(
        (func.lower(SecurityEvent.source_ip) == ql)
        | (func.lower(SecurityEvent.destination_ip) == ql)
        | (func.lower(SecurityEvent.user_id) == ql)
        | (func.lower(SecurityEvent.asset_id) == ql)
        | (func.lower(SecurityEvent.event_id) == ql)
        | (cast(SecurityEvent.metadata_, String).ilike(f"%{ql}%"))
    )
    events = list(db.scalars(stmt.limit(500)).all())
    total_matched = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    anomaly_count = sum(1 for e in events if e.is_anomalous)
    incident_ids: set = set()
    incident_rows: List[Dict[str, Any]] = []
    for e in events[:500]:
        eids = [e.event_id]
        from app.models.security import IncidentEvent
        for ie in db.scalars(select(IncidentEvent).where(IncidentEvent.event_id.in_(eids))):
            if ie.incident_id not in incident_ids:
                incident_ids.add(ie.incident_id)
    if incident_ids:
        incs = list(db.scalars(select(Incident).where(Incident.id.in_(list(incident_ids)[:10]))).all())
        for inc in sorted(incs, key=lambda i: i.created_at, reverse=True)[:5]:
            incident_rows.append({
                "incident_id": inc.incident_id, "title": inc.title,
                "severity": inc.severity, "status": inc.status,
            })

    def _naive(dt):
        if dt is None:
            return None
        if dt.tzinfo is not None:
            return dt.astimezone().replace(tzinfo=None)
        return dt

    history = {
        "seen": bool(events),
        "count": total_matched,
        "first_seen": min((_naive(e.timestamp) for e in events), default=None),
        "last_seen": max((_naive(e.timestamp) for e in events), default=None),
        "anomaly_ratio": round(anomaly_count / len(events), 3) if events else None,
        "related_incidents": incident_rows,
    }

    # --- explainable risk -------------------------------------------------
    intel_score = 0.0
    intel_evidence = "no intel match"
    if intel:
        top = intel[0]
        sev_rank = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}.get(top["severity"], 25)
        intel_score = sev_rank * top["confidence"]
        intel_evidence = f"{top['value']} ({top['indicator_type']}) severity {top['severity']} confidence {top['confidence']:.2f}"
    history_score = 0.0
    if events:
        presence = min(100.0, 20 + len(events) * 2)
        anomaly = (history["anomaly_ratio"] or 0.0) * 100
        history_score = 0.6 * presence + 0.4 * anomaly
    incident_score = min(100.0, len(incident_rows) * 20 + 30 if incident_rows else 0.0)
    components = [
        {"component": "Threat intelligence", "contribution": round(intel_score * 0.35, 1), "evidence": intel_evidence},
        {"component": "Observed activity", "contribution": round(history_score * 0.30, 1),
         "evidence": f"{history['count']} events, {history['anomaly_ratio'] or 0:.0%} anomalous"},
        {"component": "Incident association", "contribution": round(incident_score * 0.35, 1),
         "evidence": f"{len(incident_rows)} related incident(s)"},
    ]
    risk_total = round(sum(c["contribution"] for c in components), 1)
    from app.risk.engine import band

    # --- next-stage prediction -------------------------------------------
    prediction = None
    if incident_rows:
        first = db.scalar(select(Incident).where(Incident.incident_id == incident_rows[0]["incident_id"]))
        if first is not None:
            p = db.scalar(
                select(AttackPrediction)
                .where(AttackPrediction.incident_id == first.id)
                .order_by(AttackPrediction.created_at.desc())
                .limit(1)
            )
            if p is not None:
                prediction = {
                    "current_stage": p.current_stage,
                    "predicted_stage": p.predicted_stage,
                    "probability": p.probability,
                    "confidence": p.confidence,
                    "incident_id": first.incident_id,
                }

    # --- firewall verdict -------------------------------------------------
    from app.core.firewall import _MALWARE_INDICATOR_TYPES
    malware_types = {h["indicator_type"] for h in intel}
    malware_guard = bool(
        malware_types.intersection(_MALWARE_INDICATOR_TYPES)
        and any(h["severity"] in ("CRITICAL", "HIGH") for h in intel)
    )
    firewall = {
        "malware_guard": malware_guard,
        "malware_guard_note": "Would be blocked by MALWARE_GUARD on control-plane endpoints." if malware_guard else "No CRITICAL/HIGH malware indicator match.",
        "ip_watch": False,
        "ip_watch_note": "IP watchlist is only enforced when blocked IPs are configured." if any(h["indicator_type"] == "IP" for h in intel) else "Query is not an IP.",
        "blocked_indicators": [h["value"] for h in intel if h["indicator_type"] in _MALWARE_INDICATOR_TYPES],
    }

    return {
        "query": q,
        "intel": intel,
        "history": history,
        "risk": {"score": risk_total, "band": band(risk_total), "components": components},
        "prediction": prediction,
        "firewall": firewall,
        "provenance": {"mode": "DATASET", "basis": "UNSW-NB15 event corpus + local threat-intel feed; predictions are MODEL PREDICTION"},
    }


@router.get("/detection-accuracy")
def get_detection_accuracy(_user: User = Depends(get_current_user)):
    """Live-measured detection accuracy over the labeled evaluation corpus."""
    return run_evaluation()


@router.post("/test-email")
def test_email(user: User = Depends(require_roles("ADMIN"))):
    """Send a test email to the configured ops address (verifies SMTP)."""
    from app.core.email import email_enabled, send_ops_alert
    if not email_enabled():
        return {"sent": False, "configured": False,
                "message": "SMTP not configured. Set SMTP_USER and SMTP_PASSWORD in backend/.env."}
    ok = send_ops_alert(
        "CyberSentinel X — SMTP test",
        "This is a test email from CyberSentinel X. SMTP is configured and working.",
        "<p>This is a <b>test email</b> from CyberSentinel X.</p><p>SMTP is configured and working.</p>",
    )
    return {"sent": ok, "configured": True, "message": "Test email sent." if ok else "Sending failed — check SMTP credentials."}


@router.get("/assets", response_model=Paginated[dict])
def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    asset_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(Asset).order_by(Asset.criticality.desc(), Asset.name)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    total = len(list(db.scalars(stmt).all()))
    items = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[dict](
        items=[_asset_dict(a) for a in items], total=total, page=page, page_size=page_size, pages=pages
    )


@router.get("/playbooks", response_model=Paginated[dict])
def list_playbooks(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    stmt = select(KnowledgeDocument).where(KnowledgeDocument.doc_type.in_(["playbook", "policy", "cve", "mitre"]))
    total = len(list(db.scalars(stmt).all()))
    items = list(db.scalars(stmt.order_by(KnowledgeDocument.title).offset((page - 1) * page_size).limit(page_size)).all())
    pages = max((total + page_size - 1) // page_size, 1)
    return Paginated[dict](
        items=[_doc_dict(d) for d in items], total=total, page=page, page_size=page_size, pages=pages
    )


@router.post("/playbooks/{doc_id}/simulate")
def simulate_playbook(doc_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Playbook what-if: projects the risk reduction of deploying this playbook
    over the assets it would affect. Every number is a labeled SIMULATION
    projection from current asset exposure — never presented as measured
    impact, and never applied automatically."""
    from uuid import UUID
    try:
        doc_uuid = UUID(doc_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Playbook document not found")
    doc = db.get(KnowledgeDocument, doc_uuid)
    if doc is None or doc.doc_type not in ("playbook", "policy", "cve", "mitre"):
        raise HTTPException(status_code=404, detail="Playbook document not found")

    from sqlalchemy import func as sa_func

    # ---- current per-asset exposure (from stored telemetry) ---------------
    assets = list(db.scalars(select(Asset).order_by(Asset.criticality.desc()).limit(100)).all())
    rows: List[Dict[str, Any]] = []
    for a in assets:
        counts = db.scalar(
            select(sa_func.count()).select_from(SecurityEvent).where(SecurityEvent.asset_id == a.name)
        ) or 0
        if not counts:
            continue
        anomalous = db.scalar(
            select(sa_func.count()).select_from(SecurityEvent).where(
                SecurityEvent.asset_id == a.name, SecurityEvent.is_anomalous.is_(True)
            )
        ) or 0
        intel_hits = db.scalar(
            select(sa_func.count()).select_from(SecurityEvent).where(
                SecurityEvent.asset_id == a.name,
                SecurityEvent.detection_reason.ilike("%Threat intel match%"),
            )
        ) or 0
        crit = a.criticality or 1
        exposure = round(min(100.0, crit * 10 + min(40.0, anomalous * 4) + min(30.0, intel_hits * 10) + 8), 1)
        if exposure >= 10 or crit >= 4:
            rows.append({"name": a.name, "asset_type": a.asset_type, "criticality": crit,
                         "ip_address": a.ip_address, "exposure": exposure,
                         "anomalous_events": anomalous, "intel_hits": intel_hits,
                         "observed": True})
    # Assets never seen in telemetry but high criticality still matter.
    for a in assets:
        if len(rows) >= 25:
            break
        if (a.criticality or 0) >= 4 and not any(r["name"] == a.name for r in rows):
            crit = a.criticality or 1
            rows.append({"name": a.name, "asset_type": a.asset_type, "criticality": crit,
                         "ip_address": a.ip_address,
                         "exposure": round(min(100.0, crit * 10), 1),
                         "anomalous_events": 0, "intel_hits": 0, "observed": False})
    rows.sort(key=lambda r: -r["exposure"])
    rows = rows[:25]

    # ---- projected reduction (labeled SIMULATION) -------------------------
    base = {"playbook": 0.30, "cve": 0.25, "mitre": 0.20, "policy": 0.15}.get(doc.doc_type, 0.2)
    content = (doc.content or "").lower()
    control_keywords = ["block", "isolate", "contain", "quarantine", "revoke", "patch", "disable"]
    matched_keywords = [k for k in control_keywords if k in content]
    ratio = min(0.6, base + 0.05 * len(matched_keywords))

    per_asset = []
    for r in rows:
        eff = ratio * (0.7 if not r["observed"] else 1.0)
        after = round(r["exposure"] * (1 - eff), 1)
        per_asset.append({
            **r,
            "exposure_after": after,
            "reduction_points": round(r["exposure"] - after, 1),
            "reduction_pct": round(eff * 100, 1),
        })

    before = round(sum(r["exposure"] for r in rows) / max(len(rows), 1), 1) if rows else 0.0
    after = round(sum(r["exposure_after"] for r in per_asset) / max(len(per_asset), 1), 1) if per_asset else 0.0

    return {
        "simulation": True,
        "playbook": {"id": str(doc.id), "title": doc.title, "doc_type": doc.doc_type, "source": doc.source},
        "affected_assets": per_asset,
        "asset_count": len(per_asset),
        "exposure_before": before,
        "exposure_after": after,
        "projected_reduction_pct": round((1 - after / max(before, 1e-9)) * 100, 1) if before else 0.0,
        "reduction_ratio": round(ratio, 2),
        "control_signals": matched_keywords,
        "provenance": {"mode": "SIMULATED",
                        "basis": "what-if projection from current per-asset exposure (criticality + anomalous events + intel hits); not measured impact"},
        "note": "Projection assumes the playbook controls are fully deployed. Numbers are labeled SIMULATION and never applied automatically.",
    }


def _asset_dict(a: Asset) -> dict:
    return {
        "id": str(a.id),
        "name": a.name,
        "asset_type": a.asset_type,
        "ip_address": a.ip_address,
        "hostname": a.hostname,
        "criticality": a.criticality,
        "owner": a.owner,
        "description": a.description,
    }


def _doc_dict(d: KnowledgeDocument) -> dict:
    return {
        "id": str(d.id),
        "title": d.title,
        "source": d.source,
        "doc_type": d.doc_type,
        "chunk_count": d.chunk_count,
        "tags": d.tags,
        "content_preview": d.content[:400] + ("…" if len(d.content) > 400 else ""),
    }
