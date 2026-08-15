"""Agent orchestrator.

Runs the incident pipeline as a controlled state machine:

  DETECT -> INVESTIGATE -> THREAT_INTEL -> MITRE -> ATTACK_GRAPH
         -> RISK -> RESPONSE -> APPROVAL -> SIMULATED_RESPONSE -> REPORT

Each stage is isolated, broadcast over WebSocket, and a failure in one
stage never crashes the pipeline (stages are marked FAILED and the flow
continues where safe).
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import select

from app.agents.base_agent import BaseAgent
from app.agents.investigation_agent import InvestigationAgent
from app.agents.response_agent import ResponseAgent
from app.agents.threat_intel_agent import ThreatIntelAgent
from app.core.database import SessionLocal
from app.models.security import Incident
from app.risk.engine import compute_risk
from app.services.audit import log_action

logger = logging.getLogger(__name__)


class Orchestrator(BaseAgent):
    name = "orchestrator"

    def __init__(self) -> None:
        super().__init__(SessionLocal(), None)

    # ------------------------------------------------------------------
    async def run_pipeline(self, incident_id: str) -> Dict[str, Any]:
        """Asynchronously drive the full pipeline for an incident."""
        self.incident_id = incident_id
        await self.broadcast_status("orchestrator", "RUNNING",
                                    detail=f"Pipeline started for incident {incident_id}")

        stages = [
            ("investigation", self._stage_investigate),
            ("threat_intel", self._stage_threat_intel),
            ("risk", self._stage_risk),
            ("response", self._stage_response),
            ("report", self._stage_report),
            ("forensics", self._stage_forensics),
        ]

        results: Dict[str, Any] = {}
        for key, stage in stages:
            try:
                results[key] = await self.safe_run(key, stage, incident_id)
            except Exception as exc:
                logger.error("pipeline stage %s failed for %s: %s", key, incident_id, exc)
                results[key] = {"error": str(exc)[:300]}
                await self.broadcast_progress("pipeline_stage_failed", {
                    "incident_id": incident_id, "stage": key, "error": str(exc)[:300],
                })

        await self.broadcast_status("orchestrator", "COMPLETED",
                                    detail=f"Pipeline finished for incident {incident_id}")
        await self.broadcast_progress("incident_updated", {"incident_id": incident_id, "reason": "pipeline-complete"})
        return results

    # ------------------------------------------------------------------
    def _stage_investigate(self, incident_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            agent = InvestigationAgent(db, incident_id)
            return agent.investigate(incident_id)
        finally:
            db.close()

    def _stage_threat_intel(self, incident_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            agent = ThreatIntelAgent(db, incident_id)
            result = agent.enrich(incident_id)
            return {"hits": result.get("hits", []), "summary": result.get("summary")}
        finally:
            db.close()

    def _stage_risk(self, incident_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            risk = compute_risk(db, incident_id)
            return {"score": risk["score"], "severity_label": risk["severity_label"]}
        finally:
            db.close()

    def _stage_response(self, incident_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            agent = ResponseAgent(db, incident_id)
            return agent.recommend(incident_id)
        finally:
            db.close()

    def _stage_report(self, incident_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            from app.reports.generator import generate_report
            report = generate_report(db, incident_id, actor="report-agent")
            return {"report_id": report.report_id}
        finally:
            db.close()

    def _stage_forensics(self, incident_id: str) -> Dict[str, Any]:
        """Generate Attack DNA, predict the next stage, record evidence and
        anchor it into the mined evidence ledger."""
        db = SessionLocal()
        try:
            from app.core.utils import to_uuid
            from app.models.security import Incident
            from app.services.attack_dna import AttackDnaService
            from app.services.evidence import EvidenceService
            from app.services.prediction import PredictionService

            uid = to_uuid(incident_id)
            incident = db.get(Incident, uid)
            if incident is None:
                return {"error": "incident not found"}

            dna = AttackDnaService(db).generate(incident)
            prediction = PredictionService(db).predict(incident)

            evidence = EvidenceService(db)
            evidence.create_evidence(
                incident_id=uid,
                evidence_type="ATTACK_DNA",
                title=f"Attack DNA fingerprint {dna.dna_id} — {incident.title[:80]}",
                description=(
                    f"Behavioral fingerprint for {incident.incident_id} (family={dna.family}, "
                    f"behaviors={', '.join(dna.behaviors[:5]) or 'none'})."
                ),
                payload={
                    "dna_id": dna.dna_id, "fingerprint": dna.fingerprint,
                    "family": dna.family, "confidence": dna.confidence,
                    "techniques": [t.get("id") for t in dna.techniques],
                    "behaviors": dna.behaviors,
                    "historical_similarity": dna.historical_similarity,
                    "similar_to": dna.similar_to,
                },
                data_source="MODEL",
                created_by="forensics-agent",
            )
            evidence.create_evidence(
                incident_id=uid,
                evidence_type="PREDICTION",
                title=f"Predicted next stage: {prediction.predicted_stage}",
                description=prediction.rationale,
                payload={
                    "current_stage": prediction.current_stage,
                    "predicted_stage": prediction.predicted_stage,
                    "probability": prediction.probability,
                    "confidence": prediction.confidence,
                    "recommended_control": prediction.recommended_control,
                    "is_prediction": True,
                },
                data_source="MODEL",
                created_by="forensics-agent",
            )

            block = evidence.mine_block(created_by="forensics-agent")
            return {
                "dna_id": dna.dna_id,
                "prediction": prediction.predicted_stage,
                "block_index": block.block_index,
                "block_hash": block.block_hash[:16],
            }
        finally:
            db.close()

    # ------------------------------------------------------------------
    async def on_approval_decided(self, incident_id: str) -> None:
        """Called after an approval decision; updates incident status."""
        from app.core.utils import to_uuid
        uid = to_uuid(incident_id)
        db = SessionLocal()
        try:
            incident = db.scalar(select(Incident).where(Incident.id == uid))
            if incident is None:
                return
            from app.models.investigation import ApprovalRequest, ResponseRecommendation
            pending = list(db.scalars(select(ApprovalRequest).where(
                ApprovalRequest.incident_id == uid,
                ApprovalRequest.status == "PENDING",
            )).all())
            all_decided = len(pending) == 0
            executed = list(db.scalars(select(ResponseRecommendation).where(
                ResponseRecommendation.incident_id == uid,
                ResponseRecommendation.status == "EXECUTED",
            )).all())
            if incident.status in ("OPEN", "INVESTIGATING"):
                incident.status = "CONTAINED"
            if all_decided and executed and incident.status in ("OPEN", "INVESTIGATING", "CONTAINED"):
                incident.status = "RESOLVED"
                incident.resolved_at = datetime.now(timezone.utc)
                log_action(db, actor="orchestrator", action="INCIDENT.RESOLVED",
                           target_type="incident", target_id=str(incident_id))
            db.commit()
        finally:
            db.close()
        await self.broadcast_progress("incident_updated", {
            "incident_id": incident_id, "reason": "approval-decided",
        })


async def start_pipeline(incident_id: str) -> None:
    """Fire-and-forget entry point for the pipeline."""
    orchestrator = Orchestrator()
    asyncio.create_task(orchestrator.run_pipeline(incident_id))
