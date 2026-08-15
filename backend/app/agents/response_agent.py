"""Response Agent.

Generates controlled response recommendations for an incident and raises
human approval requests for high-impact actions. Never executes real
destructive actions — execution is simulated in the demo environment.
"""
import logging
from typing import Any, Dict

from sqlalchemy import select

from app.agents.base_agent import BaseAgent
from app.core.utils import to_uuid
from app.models.investigation import ApprovalRequest
from app.response.engine import generate_recommendations

logger = logging.getLogger(__name__)


class ResponseAgent(BaseAgent):
    name = "response"

    def recommend(self, incident_id: str) -> Dict[str, Any]:
        run = self.start_run("Response Agent")
        recs = generate_recommendations(self.db, incident_id, actor="response-agent")
        uid = to_uuid(incident_id)
        pending = len(list(self.db.scalars(
            select(ApprovalRequest).where(
                ApprovalRequest.incident_id == uid,
                ApprovalRequest.status == "PENDING",
            )
        ).all()))
        summary = (f"Response Agent generated {len(recs)} recommendations "
                   f"({pending} awaiting human approval).")
        self.tools_used = ["evaluate_response_actions"]
        self.finish_run(run, self.tools_used, summary)
        return {"recommendations": len(recs), "pending_approvals": pending, "summary": summary}
