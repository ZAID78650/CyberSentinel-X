"""Investigation Agent.

Given an incident, this agent:
1. Identifies involved entities (user, device, IP, asset)
2. Searches related events and entity histories
3. Checks IP reputation and threat intelligence
4. Retrieves knowledge-base context (RAG)
5. Maps activity to MITRE ATT&CK
6. Reconstructs the attack graph
7. Computes risk
8. Builds a timeline, evidence list, summary, verdict and confidence

Only allowlisted tools (see agents/tools.py) are used. Hidden chain-of-
thought is never exposed — only concise, evidence-based summaries.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.base_agent import BaseAgent
from app.agents.llm import get_llm
from app.agents.tools import TOOL_REGISTRY
from app.models.investigation import Investigation, InvestigationEvidence
from app.models.security import Incident, IncidentEvent, SecurityEvent
from app.risk.engine import compute_risk
from app.services.mitre_service import map_incident_to_mitre

logger = logging.getLogger(__name__)

VERDICT_MAP = {
    "HIGH-CONFIDENCE MALICIOUS ACTIVITY": "HIGH_CONFIDENCE_MALICIOUS",
    "SUSPICIOUS ACTIVITY — INVESTIGATION RECOMMENDED": "SUSPICIOUS",
    "LOW-RISK ANOMALY — MONITOR": "LOW_RISK_ANOMALY",
}


class InvestigationAgent(BaseAgent):
    name = "investigation"

    def __init__(self, db: Session, incident_id: Optional[str] = None) -> None:
        super().__init__(db, incident_id)
        self.tools_used: List[str] = []

    def _call_tool(self, name: str, **kwargs) -> Dict[str, Any]:
        fn = TOOL_REGISTRY.get(name)
        if fn is None:
            raise ValueError(f"Unknown tool: {name}")
        self.tools_used.append(name)
        result = fn(self.db, **kwargs)
        logger.info("tool %s -> %s", name, result.get("summary", ""))
        return result

    # ------------------------------------------------------------------
    def investigate(self, incident_id: str) -> Dict[str, Any]:
        """Run the full investigation pipeline for an incident."""
        from app.core.utils import to_uuid
        uid = to_uuid(incident_id)
        run = self.start_run("Investigation Agent")
        incident = self.db.scalar(select(Incident).where(Incident.id == uid))
        if incident is None:
            self.finish_run(run, [], "Incident not found", "incident missing")
            raise ValueError("Incident not found")

        self.incident_id = str(incident_id)
        inv = Investigation(
            incident_id=uid,
            status="RUNNING",
            started_at=datetime.now(timezone.utc),
            agent_run_id=run.run_id,
        )
        self.db.add(inv)
        self.db.commit()
        self.db.refresh(inv)

        try:
            result = self._investigate_core(incident, inv)
            inv.status = "COMPLETED"
            inv.completed_at = datetime.now(timezone.utc)
            inv.summary = result["summary"]
            inv.verdict = result["verdict"]
            inv.confidence = result["confidence"]
            inv.timeline = result["timeline"]
            inv.evidence_summary = result["evidence"]
            self.db.commit()
            self.finish_run(run, self.tools_used, result["summary"])
            return result
        except Exception as exc:
            logger.exception("investigation failed for %s", incident_id)
            inv.status = "FAILED"
            inv.completed_at = datetime.now(timezone.utc)
            inv.summary = f"Investigation failed: {str(exc)[:300]}"
            self.db.commit()
            self.finish_run(run, self.tools_used, None, str(exc)[:500])
            raise

    # ------------------------------------------------------------------
    def _investigate_core(self, incident: Incident, inv: Investigation) -> Dict[str, Any]:
        # 1. Gather correlated events
        links = list(self.db.scalars(
            select(IncidentEvent).where(IncidentEvent.incident_id == incident.id)
        ).all())
        event_ids = [lnk.event_id for lnk in links]
        events: List[SecurityEvent] = []
        if event_ids:
            events = list(self.db.scalars(
                select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))
            ).all())

        users = sorted({e.user_id for e in events if e.user_id})
        src_ips = sorted({e.source_ip for e in events if e.source_ip})
        devices = sorted({e.device_id for e in events if e.device_id})

        # 2. Entity analysis via allowlisted tools
        entity_findings: List[str] = []
        if users:
            for u in users[:2]:
                r = self._call_tool("get_user_history", user_id=u)
                entity_findings.append(r["summary"])
        if src_ips:
            for ip in src_ips[:2]:
                r = self._call_tool("check_ip_reputation", ip=ip)
                entity_findings.append(r["summary"])
        if devices:
            for d in devices[:2]:
                r = self._call_tool("get_device_history", device_id=d)
                entity_findings.append(r["summary"])

        # 3. Threat intelligence over the dominant entity
        intel_findings: List[str] = []
        search_term = users[0] if users else (src_ips[0] if src_ips else incident.category)
        r = self._call_tool("search_threat_intelligence", query=search_term)
        intel_hits = r.get("data") or []
        for hit in intel_hits[:3]:
            intel_findings.append(f"Intel match: {hit['value']} ({hit['indicator_type']}, {hit['severity']})")

        # 4. RAG knowledge base
        rag_findings: List[str] = []
        rag_query = self._rag_query(incident, events)
        r = self._call_tool("search_knowledge_base", query=rag_query, k=3)
        for doc in (r.get("data") or [])[:3]:
            rag_findings.append(f"Playbook: {doc['title']}")

        # 5. MITRE mapping
        mappings = map_incident_to_mitre(self.db, str(incident.id))
        mapped = [f"{m.technique_id} ({m.confidence:.0%})" for m in mappings]

        # 6. Attack graph + risk
        self._call_tool("create_attack_graph", incident_id=str(incident.id))
        risk = compute_risk(self.db, str(incident.id))

        # 7. Evidence compilation
        evidence = self._build_evidence(events, entity_findings, intel_findings, rag_findings, mapped, risk)
        for ev in evidence:
            self.db.add(InvestigationEvidence(
                investigation_id=inv.id,
                category=ev["category"],
                description=ev["description"],
                detail=ev.get("detail"),
                source=ev.get("source", "correlation"),
            ))

        # 8. Timeline (JSON-safe values only)
        timeline = [
            {"timestamp": e.timestamp.isoformat(), "event": f"{e.event_type} ({e.severity})",
             "detail": {"source_ip": e.source_ip, "user_id": e.user_id}}
            for e in sorted(events, key=lambda x: x.timestamp)
        ]

        # 9. Summary + verdict via LLM abstraction
        llm = get_llm()
        summary = llm.summarize_investigation(
            incident_title=incident.title,
            evidence=evidence,
            timeline_events=[t["event"] for t in timeline],
            context={
                "event_count": len(events),
                "source_count": len({e.source for e in events}),
                "user": users[0] if users else None,
                "source_ip": src_ips[0] if src_ips else None,
            },
        )
        verdict_info = llm.verdict(evidence=evidence, risk_score=risk["score"])
        verdict = verdict_info["verdict"]
        confidence = round(verdict_info["confidence"], 1)

        # 10. Persist evidence records
        self.db.commit()

        evidence_out = [
            {"category": ev["category"], "description": ev["description"], "source": ev.get("source", "correlation")}
            for ev in evidence
        ]
        return {
            "investigation_id": str(inv.id),
            "summary": summary,
            "verdict": verdict,
            "confidence": confidence,
            "timeline": timeline,
            "evidence": evidence_out,
            "mitre_mappings": mapped,
            "risk": {"score": risk["score"], "severity_label": risk["severity_label"]},
            "tools_used": self.tools_used,
            "event_count": len(events),
        }

    # ------------------------------------------------------------------
    def _rag_query(self, incident: Incident, events: List[SecurityEvent]) -> str:
        category = incident.category.lower().replace("_", " ")
        if "exfil" in category:
            return "data exfiltration response playbook"
        if "malware" in category:
            return "malware detection response playbook"
        if "privilege" in category:
            return "privilege escalation playbook"
        if "credential" in category or "takeover" in category:
            return "account takeover and brute force playbook"
        etypes = {e.event_type for e in events}
        if "LOGIN_FAILURE" in etypes:
            return "brute force playbook"
        return "incident response playbook"

    def _build_evidence(self, events: List[SecurityEvent], entity_findings: List[str],
                        intel_findings: List[str], rag_findings: List[str],
                        mapped: List[str], risk: Dict[str, Any]) -> List[Dict[str, Any]]:
        evidence: List[Dict[str, Any]] = []
        etypes = [e.event_type for e in events]

        def add(category: str, condition: bool, description: str, source: str = "event-correlation") -> None:
            if condition:
                evidence.append({"category": category, "description": description, "source": source})

        failures = sum(1 for e in etypes if e == "LOGIN_FAILURE")
        add("brute-force", failures >= 3, f"{failures} failed login attempts observed in the incident window")
        add("new-device", "NEW_DEVICE" in etypes, "Successful login from a device with no prior history")
        add("unusual-location", "UNUSUAL_LOCATION" in etypes, "Login from an atypical geographic location")
        add("privilege-escalation", "PRIVILEGE_ESCALATION" in etypes,
            "Privilege escalation detected for the affected account")
        add("sensitive-access", "DATABASE_ACCESS" in etypes or "DATA_DOWNLOAD" in etypes or "FILE_ACCESS" in etypes,
            "Access to sensitive data resources (database / files)")
        add("malware", "MALWARE_DETECTED" in etypes, "Malware detected on an affected endpoint")
        add("exfiltration", "DATA_EXFILTRATION" in etypes, "Suspected data transfer to an external destination")
        add("intel-match", bool(intel_findings), "; ".join(intel_findings[:2]), "threat-intelligence")
        add("anomaly", any(e.is_anomalous for e in events),
            f"{sum(1 for e in events if e.is_anomalous)} events scored as anomalous by the ML engine", "ml-anomaly")
        add("timeline", len(events) >= 5,
            f"Attack chain reconstructed across {len(events)} correlated events ({len(mapped)} MITRE techniques)", "attack-graph")
        return evidence[:10]
