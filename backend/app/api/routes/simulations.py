"""Synthetic attack simulation routes (safe, demo-only)."""
import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.agents.detection_agent import DetectionAgent
from app.agents.orchestrator import Orchestrator
from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.core.websocket_manager import ws_manager
from app.models.user import User
from app.services.audit import log_action
from app.services.event_service import ingest_batch
from app.services.simulator import SCENARIOS, build_scenario_events

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/simulations", tags=["simulations"])

SCENARIO_MAP = {
    "account-takeover": "account-takeover",
    "brute-force": "brute-force",
    "malware": "malware",
    "data-exfiltration": "data-exfiltration",
    "privilege-escalation": "privilege-escalation",
}


@router.post("/{scenario}")
async def run_simulation(
    scenario: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    key = SCENARIO_MAP.get(scenario.lower())
    if key is None:
        raise HTTPException(status_code=404, detail=f"Unknown scenario. Choose from: {', '.join(SCENARIO_MAP)}")

    payloads = build_scenario_events(key)
    events = ingest_batch(db, payloads, source="simulator")

    for e in events:
        await ws_manager.broadcast("new_event", {
            "event_id": e.event_id, "event_type": e.event_type, "severity": e.severity,
            "is_anomalous": e.is_anomalous, "source_ip": e.source_ip, "user_id": e.user_id,
            "timestamp": e.timestamp.isoformat(),
        })

    # Detection Agent evaluates the batch
    detection = DetectionAgent(db)
    result = detection.evaluate_batch(events, actor=user.email)
    await ws_manager.broadcast("agent_status", {
        "name": "Detection Agent", "key": "detection", "status": "COMPLETED",
        "detail": result.get("summary", ""),
    })

    if result.get("incident"):
        await ws_manager.broadcast("new_alert", {
            "alert_id": result["alert_id"], "severity": result["severity"],
            "title": "Simulated attack correlated", "confidence": result["confidence"],
        })
        await ws_manager.broadcast("new_incident", {
            "incident_id": result["incident_id"], "severity": result["severity"],
        })
        orchestrator = Orchestrator()
        asyncio.create_task(orchestrator.run_pipeline(result["incident"]))
        log_action(db, actor=user.email, action="SIMULATION.RUN", target_type="scenario",
                   target_id=key, detail={"incident_id": result["incident_id"]})
        return {
            "scenario": key,
            "events_ingested": len(events),
            "suspicious_count": result["suspicious_count"],
            "alert_id": result["alert_id"],
            "incident_id": result["incident_id"],
            "severity": result["severity"],
            "pipeline": "started",
            "message": f"Simulated {SCENARIOS[key]} — pipeline launched.",
        }

    log_action(db, actor=user.email, action="SIMULATION.RUN", target_type="scenario",
               target_id=key, detail={"events": len(events), "alert": None})
    return {
        "scenario": key,
        "events_ingested": len(events),
        "suspicious_count": 0,
        "alert_id": None,
        "incident_id": None,
        "severity": None,
        "pipeline": "not-started",
        "message": "Simulation ingested events; no alert triggered.",
    }


@router.get("", response_model=dict)
def list_scenarios(_user: User = Depends(get_current_user)):
    return {"scenarios": [{"key": k, "label": v} for k, v in SCENARIOS.items()]}
