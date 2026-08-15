"""Detection Agent.

Evaluates ingested events flagged as anomalous (by rules + ML + intel),
groups them into an alert, and opens an incident for investigation.
"""
import logging
from typing import Any, Dict, List


from app.agents.base_agent import BaseAgent
from app.models.security import SecurityEvent
from app.services.alert_service import create_alert_from_events, create_incident_from_alert
from app.services.feedback import BASE_DETECTION_FLOOR, load_correlation_floors

logger = logging.getLogger(__name__)


class DetectionAgent(BaseAgent):
    name = "detection"

    def evaluate_batch(self, events: List[SecurityEvent], actor: str = "detection-agent") -> Dict[str, Any]:
        """Analyze a batch of freshly ingested events; create alert + incident if warranted.

        The anomaly floor per event type is read from the audited correlation
        settings (set via retrain-with-consent); a raised floor means fewer
        alerts for a category analysts have shown to be noisy.
        """
        floors = load_correlation_floors(self.db)
        suspicious = [
            e for e in events
            if e.is_anomalous or (e.anomaly_score or 0) >= BASE_DETECTION_FLOOR + floors.get(e.event_type, 0.0)
        ]
        if not suspicious:
            return {"alert": None, "incident": None, "suspicious_count": 0}

        # Group suspicious events by user then by source IP for correlation
        groups: Dict[str, List[SecurityEvent]] = {}
        for e in suspicious:
            key = e.user_id or e.source_ip or "unknown"
            groups.setdefault(key, []).append(e)
        primary_key = max(groups, key=lambda k: len(groups[k]))
        cluster = groups[primary_key]

        severity = max((e.severity for e in cluster), key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(s, 0))
        title = self._title_for(cluster, severity)

        alert = create_alert_from_events(self.db, cluster, title, actor=actor)
        incident = create_incident_from_alert(self.db, alert, actor=actor)

        result = {
            "alert": str(alert.id),
            "alert_id": alert.alert_id,
            "incident": str(incident.id),
            "incident_id": incident.incident_id,
            "suspicious_count": len(cluster),
            "severity": severity,
            "confidence": alert.confidence,
            "summary": (
                f"Detection Agent evaluated {len(events)} events; {len(cluster)} exhibited anomalous behavior "
                f"and were correlated into alert {alert.alert_id} and incident {incident.incident_id}."
            ),
        }
        self.incident_id = str(incident.id)
        logger.info("detection agent: %s", result["summary"])
        return result

    def _title_for(self, cluster: List[SecurityEvent], severity: str) -> str:
        etypes = {e.event_type for e in cluster}
        has_escalation = "PRIVILEGE_ESCALATION" in etypes
        has_malware = "MALWARE_DETECTED" in etypes or "SUSPICIOUS_PROCESS" in etypes
        has_exfil = "DATA_EXFILTRATION" in etypes
        has_brute = "BRUTE_FORCE" in etypes or "LOGIN_FAILURE" in etypes
        has_takeover = "LOGIN_SUCCESS" in etypes or "NEW_DEVICE" in etypes or "UNUSUAL_LOCATION" in etypes
        if has_malware:
            return f"[{severity}] Malware Activity Detected"
        if has_exfil:
            return f"[{severity}] Data Exfiltration Attempt"
        if has_escalation and has_takeover:
            return f"[{severity}] Account Takeover with Privilege Escalation"
        if has_escalation:
            return f"[{severity}] Privilege Escalation Detected"
        if has_brute and has_takeover:
            return f"[{severity}] Credential Attack Resulting in Account Access"
        if has_brute:
            return f"[{severity}] Brute Force Attack"
        if has_takeover:
            return f"[{severity}] Suspicious Account Activity"
        return f"[{severity}] Suspicious Activity Cluster"
