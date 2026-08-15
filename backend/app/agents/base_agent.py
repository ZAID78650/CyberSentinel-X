"""Base agent: run tracking, status broadcasting, error containment."""
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.websocket_manager import ws_manager
from app.models.investigation import AIAgentRun

logger = logging.getLogger(__name__)

AGENT_DISPLAY_NAMES = {
    "detection": "Detection Agent",
    "investigation": "Investigation Agent",
    "threat_intel": "Threat Intel Agent",
    "risk": "Risk Engine",
    "response": "Response Agent",
    "report": "Report Agent",
    "orchestrator": "Orchestrator",
}


class BaseAgent:
    """Common behavior for pipeline agents."""

    name = "base"

    def __init__(self, db: Session, incident_id: Optional[str] = None) -> None:
        self.db = db
        self.incident_id = incident_id
        self.run_id = f"run-{uuid.uuid4().hex[:12]}"

    # ------------------------------------------------------------------
    def start_run(self, agent_name: str) -> AIAgentRun:
        record = AIAgentRun(
            agent_name=agent_name,
            run_id=self.run_id,
            incident_id=self.incident_id,
            status="RUNNING",
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(record)
        self.db.commit()
        return record

    def finish_run(self, record: AIAgentRun, tools_used: List[str], summary: Optional[str],
                   error: Optional[str] = None) -> None:
        record.status = "FAILED" if error else "COMPLETED"
        record.completed_at = datetime.now(timezone.utc)
        record.tools_used = tools_used
        record.result_summary = summary
        record.error = error
        self.db.commit()

    # ------------------------------------------------------------------
    async def broadcast_status(self, agent_key: str, status: str, detail: Optional[str] = None) -> None:
        try:
            await ws_manager.broadcast("agent_status", {
                "name": AGENT_DISPLAY_NAMES.get(agent_key, agent_key),
                "key": agent_key,
                "status": status,
                "detail": detail,
                "incident_id": self.incident_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as exc:  # pragma: no cover
            logger.debug("broadcast failed: %s", exc)

    async def broadcast_progress(self, event: str, payload: Dict[str, Any]) -> None:
        try:
            await ws_manager.broadcast(event, payload)
        except Exception as exc:  # pragma: no cover
            logger.debug("broadcast failed: %s", exc)

    # ------------------------------------------------------------------
    async def safe_run(self, agent_key: str, fn, *args, **kwargs) -> Any:
        """Run a stage, broadcasting status, and never crashing the caller."""
        await self.broadcast_status(agent_key, "RUNNING")
        try:
            result = await asyncio.to_thread(fn, *args, **kwargs)
            await self.broadcast_status(agent_key, "COMPLETED")
            return result
        except Exception as exc:
            logger.exception("agent %s failed", agent_key)
            await self.broadcast_status(agent_key, "FAILED", detail=str(exc)[:300])
            raise
