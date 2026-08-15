"""Threat Intelligence Agent.

Dedicated run that enriches an incident with indicator intelligence.
Reuses the adapter so live STIX/TAXII feeds can be added later.
"""
import logging
from typing import Any, Dict, List

from sqlalchemy import select

from app.agents.base_agent import BaseAgent
from app.models.security import Incident, IncidentEvent, SecurityEvent
from app.threat_intel.adapter import ThreatIntelAdapter

logger = logging.getLogger(__name__)


class ThreatIntelAgent(BaseAgent):
    name = "threat_intel"

    def enrich(self, incident_id: str) -> Dict[str, Any]:
        from app.core.utils import to_uuid
        uid = to_uuid(incident_id)
        run = self.start_run("Threat Intel Agent")
        incident = self.db.scalar(select(Incident).where(Incident.id == uid))
        if incident is None:
            self.finish_run(run, [], None, "incident missing")
            return {"hits": []}

        links = list(self.db.scalars(
            select(IncidentEvent).where(IncidentEvent.incident_id == uid)
        ).all())
        event_ids = [lnk.event_id for lnk in links]
        events: List[SecurityEvent] = []
        if event_ids:
            events = list(self.db.scalars(
                select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))
            ).all())

        adapter = ThreatIntelAdapter(self.db)
        hits: List[Dict[str, Any]] = []
        for e in events:
            hits.extend(adapter.check_event({
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "event_type": e.event_type,
                "metadata": e.metadata_ or {},
            }))

        # de-dup
        seen = set()
        unique = []
        for h in hits:
            k = (h["type"], h["indicator"])
            if k not in seen:
                seen.add(k)
                unique.append(h)

        summary = f"Threat Intelligence Agent matched {len(unique)} known indicators for this incident."
        self.tools_used = ["check_ip_reputation", "search_threat_intelligence"]
        self.finish_run(run, self.tools_used, summary)
        return {"hits": unique, "summary": summary, "source_count": len(adapter.list_sources())}
