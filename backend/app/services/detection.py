"""Hybrid detection engine.

Combines:
1. Deterministic rules (repeated failures, new device, escalation, ...)
2. Isolation Forest anomaly scoring (see app/ml/anomaly.py)
3. Local threat intelligence lookups

The LLM is never the sole detection mechanism; AI reasoning is used for
alert enrichment and investigation only.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ml.anomaly import AnomalyDetector
from app.models.security import SecurityEvent
from app.threat_intel.adapter import ThreatIntelAdapter

logger = logging.getLogger(__name__)

# module-level detector shared across requests (lazily refit)
_detector = AnomalyDetector()
_detector_fit_count = 0


class DetectionService:
    """Per-request detection service. Holds a DB session."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.intel = ThreatIntelAdapter(db)

    # ------------------------------------------------------------------
    def _recent_events(self, minutes: int = 60, limit: int = 2000) -> List[SecurityEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.timestamp >= cutoff)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(limit)
        )
        return list(db_scalars(self.db, stmt))

    # ------------------------------------------------------------------
    def _refit_if_needed(self, total_events: int) -> None:
        global _detector_fit_count
        if total_events >= 12 and total_events > _detector_fit_count * 1.5:
            events = self._recent_events(minutes=24 * 60, limit=3000)
            dicts = [event_to_dict(e) for e in events]
            _detector.fit(dicts)
            _detector_fit_count = total_events

    # ------------------------------------------------------------------
    def process_event(self, data: Dict[str, Any]) -> SecurityEvent:
        """Score an event, run rules, and build the persisted record."""
        total = count_events(self.db)
        self._refit_if_needed(total)

        # Rule hits based on DB context
        rule_hits = self.run_rules(data)

        # Threat intel check
        intel_hits = self.intel.check_event(data)

        # ML anomaly score
        anomaly_score = _detector.score(data)
        is_anomalous = (
            anomaly_score >= 0.55
            or bool(rule_hits)          # any deterministic rule fired
            or bool(intel_hits)         # any threat-intel match
        )

        reason_parts = [h["reason"] for h in rule_hits]
        for hit in intel_hits:
            reason_parts.append(hit["reason"])

        severity = max(
            [data.get("severity", "LOW")] + [h["severity"] for h in rule_hits] + [h["severity"] for h in intel_hits],
            key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(s, 0),
        )

        return SecurityEvent(
            event_id=data["event_id"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            severity=severity,
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            user_id=data.get("user_id"),
            device_id=data.get("device_id"),
            asset_id=data.get("asset_id"),
            source=data.get("source", "api"),
            metadata_=data.get("metadata"),
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
            detection_reason="; ".join(reason_parts) if reason_parts else None,
        )

    # ------------------------------------------------------------------
    def run_rules(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Deterministic detection rules. Returns a list of rule hits."""
        hits: List[Dict[str, Any]] = []
        etype = data["event_type"]
        user = data.get("user_id")
        src_ip = data.get("source_ip") or "unknown"
        now = data["timestamp"]

        def recent(q) -> List[SecurityEvent]:
            stmt = select(SecurityEvent).where(q).where(SecurityEvent.timestamp >= now - timedelta(minutes=60))
            return list(db_scalars(self.db, stmt.order_by(SecurityEvent.timestamp.desc()).limit(500)))

        # 1. Repeated failed logins. A brute-force burst is concentrated on
        #    ONE account (or a single hostile source). Scattered typos across
        #    users sharing an office IP must NOT count as an attack.
        if etype == "LOGIN_FAILURE":
            user_failures = recent(SecurityEvent.event_type == "LOGIN_FAILURE")
            same_user = [e for e in user_failures if e.user_id == user]
            same_ip = [e for e in user_failures if e.source_ip == src_ip]
            if len(same_user) >= 5:
                hits.append({"rule": "repeated_failed_logins", "severity": "HIGH",
                             "reason": f"{len(same_user)} failed logins for user '{user}' within 60 minutes (brute force)"})
            elif len(same_ip) >= 15:
                hits.append({"rule": "repeated_failed_logins_ip", "severity": "MEDIUM",
                             "reason": f"{len(same_ip)} failed logins from {src_ip} within 60 minutes"})

        # 2. Login success after a burst of failures on the SAME account
        #    (account takeover signature).
        if etype == "LOGIN_SUCCESS":
            failures = [e for e in recent(SecurityEvent.event_type == "LOGIN_FAILURE")
                        if e.user_id == user]
            if len(failures) >= 5:
                hits.append({"rule": "login_after_failures", "severity": "HIGH",
                             "reason": f"Successful login for '{user}' following {len(failures)} failed attempts"})

        # 3. New device login — but only when the device is NOT a
        #    registered corporate asset (MDM-enrolled machines are normal).
        if etype in ("NEW_DEVICE", "LOGIN_SUCCESS"):
            meta = data.get("metadata") or {}
            is_new = etype == "NEW_DEVICE" or (data.get("device_id") and meta.get("is_new_device"))
            if is_new and not meta.get("is_registered"):
                hits.append({"rule": "new_device_login", "severity": "MEDIUM",
                             "reason": f"Login from an unregistered device for user '{user}'"})

        # 4. Unusual location — tolerated for flagged travelers with a
        #    registered device; otherwise suspicious.
        if etype == "UNUSUAL_LOCATION":
            meta = data.get("metadata") or {}
            if not (meta.get("traveler") and meta.get("is_registered")):
                hits.append({"rule": "unusual_location", "severity": "MEDIUM",
                             "reason": f"Login for '{user}' from an atypical geographic location"})

        # 5. Privilege escalation
        if etype == "PRIVILEGE_ESCALATION":
            hits.append({"rule": "privilege_escalation", "severity": "HIGH",
                         "reason": f"Privilege escalation detected for user '{user}'"})

        # 6. Sensitive resource access — only when the target is actually
        #    sensitive (credentials, payroll, customer PII, admin config, ...)
        #    or the volume/pattern is clearly abnormal. Prevents false
        #    positives on routine database/file access.
        if etype in ("DATABASE_ACCESS", "FILE_ACCESS", "DATA_DOWNLOAD"):
            meta = data.get("metadata") or {}
            target = meta.get("resource") or data.get("asset_id") or ""
            target_l = str(target).lower()
            sensitive_marker = any(k in target_l for k in (
                "payroll", "customer", "credential", "shadow", "secret", "admin",
                "employee", "pii", "restricted", "confidential", ".env", "password",
                "token", "key", "config", "shadow", "accounts", "registry",
            ))
            rows = meta.get("rows") or 0
            bytes_xfer = meta.get("bytes") or 0
            volume_abnormal = (isinstance(rows, (int, float)) and rows >= 5000) or \
                              (isinstance(bytes_xfer, (int, float)) and bytes_xfer >= 50 * 1024 * 1024)
            classification = str(meta.get("data_classification", "")).upper()
            if sensitive_marker or volume_abnormal or classification in ("RESTRICTED", "CONFIDENTIAL", "TOP SECRET"):
                hits.append({"rule": "sensitive_access", "severity": "MEDIUM",
                             "reason": f"Access to sensitive resource {target} by '{user}'"})

        # 7. Malware / exfiltration / scan
        if etype == "MALWARE_DETECTED":
            hits.append({"rule": "malware_detected", "severity": "CRITICAL",
                         "reason": f"Malware detection on asset '{data.get('asset_id') or 'unknown'}'"})
        if etype == "DATA_EXFILTRATION":
            hits.append({"rule": "data_exfiltration", "severity": "CRITICAL",
                         "reason": f"Suspected data exfiltration to {data.get('destination_ip') or 'external destination'}"})
        if etype == "BRUTE_FORCE":
            hits.append({"rule": "brute_force", "severity": "HIGH",
                         "reason": "Brute-force pattern detected"})
        if etype == "PORT_SCAN":
            hits.append({"rule": "port_scan", "severity": "LOW",
                         "reason": f"Port scanning activity from {src_ip}"})
        if etype == "SUSPICIOUS_NETWORK_CONNECTION":
            hits.append({"rule": "suspicious_connection", "severity": "MEDIUM",
                         "reason": f"Suspicious outbound connection from {src_ip} to {data.get('destination_ip')}"})

        return hits


def event_to_dict(e: SecurityEvent) -> Dict[str, Any]:
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp,
        "event_type": e.event_type,
        "severity": e.severity,
        "source_ip": e.source_ip,
        "destination_ip": e.destination_ip,
        "user_id": e.user_id,
        "device_id": e.device_id,
        "asset_id": e.asset_id,
        "source": e.source,
        "metadata": e.metadata_ or {},
    }


def count_events(db: Session) -> int:
    from sqlalchemy import func
    return db.scalar(select(func.count()).select_from(SecurityEvent)) or 0


def db_scalars(db: Session, stmt):
    return db.scalars(stmt).all()
