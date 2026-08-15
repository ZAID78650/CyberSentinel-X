"""SOC analyst tooling routes: threat hunting, blast radius, campaigns,
asset risk intelligence, global search, and resilience tooling."""
import asyncio
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.models.user import User
from app.agents.orchestrator import Orchestrator
from app.core.websocket_manager import ws_manager
from app.services.audit import log_action
from app.services.resilience import (
    LIVE_SCENARIO_IP,
    compliance_posture,
    cyber_resilience,
    model_center,
    run_live_scenario,
    simulate_attack,
)
from app.services.soc_analytics import (
    asset_risk_intel,
    compute_blast_radius,
    compute_campaigns,
    global_search,
    run_hunt,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/soc", tags=["soc-tools"])


class HuntRequest(BaseModel):
    query: str
    scope: str = "all"  # events | alerts | incidents | all


class HuntSave(BaseModel):
    query: str
    name: str
    scope: str = "all"


class SimulateRequest(BaseModel):
    asset_id: str
    starting_stage: str = "Initial Access"
    scenario: str = "generic"


# ---------------------------------------------------------------------------
# Threat hunting
# ---------------------------------------------------------------------------
@router.post("/threat-hunting")
def hunt(req: HuntRequest, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Translate a natural-language hunt into safe structured filters and run it.

    Never executes user-supplied SQL — only whitelisted filters are applied.
    """
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    if len(req.query) > 500:
        raise HTTPException(status_code=400, detail="Query too long (max 500 chars)")
    return run_hunt(db, req.query, scope=req.scope, limit=100)


@router.post("/threat-hunting/save")
def save_hunt(req: HuntSave, db: Session = Depends(get_db), user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST"))):
    """Persist a hunt for reuse. Stored as an audit record (searchable history)."""
    from app.services.audit import log_action
    record = log_action(db, actor=user.email, action="THREAT_HUNT.SAVED",
                        target_type="hunt", target_id=req.name,
                        detail={"query": req.query, "scope": req.scope})
    return {"saved": True, "hunt_id": str(record.id), "name": req.name, "query": req.query}


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------
@router.get("/blast-radius/{incident_id}")
def blast_radius(incident_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Estimate the blast radius of a compromise via attack-graph reachability."""
    try:
        return compute_blast_radius(db, str(incident_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------
@router.get("/campaigns")
def campaigns(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    from app.services.cache import get_or_build
    # TTL cache: campaign computation is an N+1 read over incidents/events.
    return get_or_build(f"campaigns:{limit}", 20.0, lambda: compute_campaigns(db, limit=limit))


# ---------------------------------------------------------------------------
# Asset risk intelligence
# ---------------------------------------------------------------------------
@router.get("/asset-risk")
def asset_risk(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return asset_risk_intel(db)


# ---------------------------------------------------------------------------
# What-if attack simulator (SIMULATION only)
# ---------------------------------------------------------------------------
@router.post("/simulate")
def simulate(
    req: SimulateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    """What-if simulation: project a kill-chain from an asset entry point.
    Clearly labeled SIMULATION — never a confirmed attack."""
    try:
        return simulate_attack(db, req.asset_id, req.starting_stage, req.scenario)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Live scenario replay
# ---------------------------------------------------------------------------
@router.post("/simulate/run-live")
async def simulate_run_live(
    req: SimulateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    """Replay the simulated kill chain through the REAL detection pipeline.

    Events are labeled SIMULATED and flow through detection -> alert ->
    incident -> full orchestrator pipeline (DNA, prediction, evidence,
    risk, response, report). Watch it happen live via WebSocket.
    """
    try:
        result = run_live_scenario(db, req.asset_id, req.starting_stage, actor=user.email)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    # Stream the replayed events so the UI updates in real time
    for e in result["timeline"]:
        await ws_manager.broadcast("new_event", {
            "event_id": None, "event_type": e["event_type"], "severity": e["severity"],
            "is_anomalous": e["is_anomalous"], "source_ip": LIVE_SCENARIO_IP,
            "timestamp": e["timestamp"],
        })
    await ws_manager.broadcast("agent_status", {
        "name": "Detection Agent", "key": "detection", "status": "COMPLETED",
        "detail": f"Evaluated {result['events_ingested']} SIMULATED events; "
                  f"{result['anomalous_count']} anomalous.",
    })

    if result.get("incident_id"):
        await ws_manager.broadcast("new_alert", {
            "alert_id": result["alert_id"], "severity": result["severity"],
            "title": "Simulated kill-chain replay correlated",
            "confidence": None,
        })
        await ws_manager.broadcast("new_incident", {
            "incident_id": result["incident_id"], "severity": result["severity"],
        })
        orchestrator = Orchestrator()
        asyncio.create_task(orchestrator.run_pipeline(result["incident"]))
        log_action(db, actor=user.email, action="SIMULATION.LIVE", target_type="scenario",
                   target_id=req.starting_stage,
                   detail={"asset": req.asset_id, "incident_id": result["incident_id"],
                           "events": result["events_ingested"]})
    else:
        log_action(db, actor=user.email, action="SIMULATION.LIVE", target_type="scenario",
                   target_id=req.starting_stage,
                   detail={"asset": req.asset_id, "alert": None})

    return result


# ---------------------------------------------------------------------------
# Cyber resilience score
# ---------------------------------------------------------------------------
@router.get("/resilience")
def resilience(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return cyber_resilience(db)


# ---------------------------------------------------------------------------
# Compliance center
# ---------------------------------------------------------------------------
@router.get("/compliance")
def compliance(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return compliance_posture(db)


# ---------------------------------------------------------------------------
# Model center
# ---------------------------------------------------------------------------
@router.get("/model-center")
def model_center_api(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Production detection model + measured evaluation metrics."""
    try:
        return model_center()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


# ---------------------------------------------------------------------------
# Global search
# ---------------------------------------------------------------------------
@router.get("/search")
def search(
    q: str = Query("", max_length=200),
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return global_search(db, q, limit=limit)
