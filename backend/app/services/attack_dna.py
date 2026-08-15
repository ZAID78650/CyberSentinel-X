"""Attack DNA — behavioral fingerprinting of incidents.

For each significant incident a fixed-length feature vector is derived from
the correlated events (event-type distribution, severity, anomaly scores,
IP/asset cardinality, protocol mix, flow statistics, MITRE techniques,
threat-intel hits, risk). The vector is hashed into a stable fingerprint and
compared to historical fingerprints with cosine similarity, so analysts can
find "attacks that look like this one".
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.forensics import AttackDna
from app.models.investigation import RiskScore
from app.models.intel import IncidentMitreMapping, MitreTechnique
from app.models.security import Incident, IncidentEvent, SecurityEvent

logger = logging.getLogger(__name__)

# Event types we track in the DNA feature vector (stable ordering).
DNA_EVENT_TYPES = [
    "LOGIN_SUCCESS", "LOGIN_FAILURE", "NEW_DEVICE", "UNUSUAL_LOCATION",
    "PRIVILEGE_ESCALATION", "SUSPICIOUS_PROCESS", "FILE_ACCESS", "DATABASE_ACCESS",
    "DATA_DOWNLOAD", "DATA_EXFILTRATION", "MALWARE_DETECTED", "PORT_SCAN",
    "BRUTE_FORCE", "SUSPICIOUS_NETWORK_CONNECTION",
]

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _behaviors(events: List[SecurityEvent], etypes: set[str]) -> List[str]:
    """Human-readable behavior labels derived from actual event patterns."""
    behaviors: List[str] = []
    if "BRUTE_FORCE" in etypes or "LOGIN_FAILURE" in etypes:
        behaviors.append("Abnormal authentication")
    if "PORT_SCAN" in etypes:
        behaviors.append("Network reconnaissance")
    if "PRIVILEGE_ESCALATION" in etypes:
        behaviors.append("Privilege escalation")
    if "MALWARE_DETECTED" in etypes or "SUSPICIOUS_PROCESS" in etypes:
        behaviors.append("Malicious payload execution")
    if "DATA_EXFILTRATION" in etypes or "DATA_DOWNLOAD" in etypes:
        behaviors.append("Data exfiltration pattern")
    if "SUSPICIOUS_NETWORK_CONNECTION" in etypes:
        behaviors.append("Anomalous outbound communication")
    if "NEW_DEVICE" in etypes or "UNUSUAL_LOCATION" in etypes:
        behaviors.append("Unfamiliar identity context")
    src_ips = {e.source_ip for e in events if e.source_ip}
    dst_ips = {e.destination_ip for e in events if e.destination_ip}
    if len(src_ips) >= 2 and "PORT_SCAN" in etypes:
        behaviors.append("Distributed source scanning")
    if len(dst_ips) >= 2:
        behaviors.append("Multiple destinations (lateral spread)")
    return behaviors


def _feature_vector(events: List[SecurityEvent], techniques: List[str],
                    anomaly_mean: float, risk_score: Optional[float]) -> List[float]:
    """Fixed-length numeric vector used for similarity + hashing."""
    total = max(len(events), 1)
    counts = {t: 0 for t in DNA_EVENT_TYPES}
    sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    src: set[str] = set()
    dst: set[str] = set()
    assets: set[str] = set()
    protos: set[str] = set()
    bytes_sum = pkt_sum = rate_sum = 0.0
    for e in events:
        counts[e.event_type] = counts.get(e.event_type, 0) + 1
        sev_counts[e.severity] = sev_counts.get(e.severity, 0) + 1
        if e.source_ip:
            src.add(e.source_ip)
        if e.destination_ip:
            dst.add(e.destination_ip)
        if e.asset_id:
            assets.add(e.asset_id)
        meta = e.metadata_ or {}
        if meta.get("proto"):
            protos.add(str(meta["proto"]))
        bytes_sum += float(meta.get("sbytes") or 0) + float(meta.get("dbytes") or 0)
        pkt_sum += float(meta.get("spkts") or 0) + float(meta.get("dpkts") or 0)
        rate_sum += float(meta.get("rate") or 0)

    vec: List[float] = [counts[t] / total for t in DNA_EVENT_TYPES]                      # 14
    vec += [sev_counts[s] / total for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]]       # 4
    vec += [math.log10(len(src) + 1), math.log10(len(dst) + 1),                         # 2
            math.log10(len(assets) + 1), math.log10(len(protos) + 1),                   # 2
            math.log10(bytes_sum / total + 1), math.log10(pkt_sum / total + 1),         # 2
            math.log10(rate_sum / total + 1), anomaly_mean,                             # 2
            (risk_score or 0.0) / 100.0,                                                # 1
            len(techniques) / 10.0]                                                     # 1
    return vec


def _normalize(v: List[float]) -> List[float]:
    norm = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / norm for x in v]


def cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    na, nb = _normalize(a), _normalize(b)
    return round(sum(x * y for x, y in zip(na, nb)), 4)


def next_dna_id(db: Session) -> str:
    count = db.scalar(select(func.count()).select_from(AttackDna)) or 0
    return f"AD-{count + 1:04d}"


class AttackDnaService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    def generate(self, incident: Incident) -> AttackDna:
        """Compute the DNA for an incident (idempotent: returns existing)."""
        existing = self.db.scalar(
            select(AttackDna).where(AttackDna.incident_id == incident.id)
        )
        if existing:
            return existing

        event_ids = list(self.db.scalars(
            select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
        ).all())
        events: List[SecurityEvent] = []
        if event_ids:
            events = list(self.db.scalars(
                select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids[:400]))
            ).all())

        techniques: List[str] = []
        for mapping in self.db.scalars(
            select(IncidentMitreMapping).where(IncidentMitreMapping.incident_id == incident.id)
        ):
            tech = self.db.scalar(
                select(MitreTechnique).where(MitreTechnique.technique_id == mapping.technique_id)
            )
            if tech:
                techniques.append(f"{tech.technique_id} {tech.name}")

        risk = self.db.scalar(
            select(RiskScore).where(RiskScore.incident_id == incident.id)
            .order_by(RiskScore.created_at.desc()).limit(1)
        )
        anomaly_scores = [e.anomaly_score for e in events if e.anomaly_score is not None]
        anomaly_mean = round(sum(anomaly_scores) / len(anomaly_scores), 4) if anomaly_scores else 0.5

        etypes = {e.event_type for e in events}
        behaviors = _behaviors(events, etypes)
        vec = _feature_vector(events, techniques, anomaly_mean,
                              risk.score if risk else incident.risk_score)
        fingerprint = hashlib.sha256(
            json.dumps({"v": [round(x, 6) for x in vec],
                        "b": behaviors, "t": techniques}, sort_keys=True).encode()
        ).hexdigest()

        family = _family_for(incident, etypes)
        confidence = round(min(0.98, 0.45 + 0.4 * anomaly_mean +
                               0.1 * (risk.score / 100 if risk else 0.5)), 3)

        # Historical similarity vs. every earlier DNA.
        historical = list(self.db.scalars(select(AttackDna).order_by(AttackDna.created_at)).all())
        best_sim, best_id = 0.0, None
        for h in historical:
            sim = cosine_similarity(vec, h.features.get("vector", []))
            if sim > best_sim:
                best_sim, best_id = sim, h.dna_id

        dna = AttackDna(
            incident_id=incident.id,
            dna_id=next_dna_id(self.db),
            fingerprint=fingerprint,
            family=family,
            confidence=confidence,
            severity=incident.severity,
            risk_score=risk.score if risk else incident.risk_score,
            techniques=[{"id": t.split(" ", 1)[0], "name": t.split(" ", 1)[1]} if " " in t else {"id": t, "name": t}
                        for t in techniques],
            behaviors=behaviors,
            features={"vector": [round(x, 6) for x in vec], "event_count": len(events),
                      "source_ips": sorted({e.source_ip for e in events if e.source_ip})[:20],
                      "dest_ips": sorted({e.destination_ip for e in events if e.destination_ip})[:20],
                      "anomaly_mean": anomaly_mean},
            historical_similarity=best_sim if best_id else None,
            similar_to=best_id,
            meta={"events_analyzed": len(events), "technique_count": len(techniques)},
        )
        self.db.add(dna)
        self.db.commit()
        self.db.refresh(dna)
        logger.info("attack dna %s generated for %s (family=%s, sim=%s)",
                    dna.dna_id, incident.incident_id, family, best_sim)
        return dna

    # ------------------------------------------------------------------
    def search_similar(self, incident_id: Optional[UUID] = None, top_k: int = 5) -> List[Dict[str, Any]]:
        """Return the most similar DNAs, optionally seeded by one incident."""
        target: Optional[AttackDna] = None
        if incident_id is not None:
            target = self.db.scalar(select(AttackDna).where(AttackDna.incident_id == incident_id))
        pool = list(self.db.scalars(select(AttackDna)).all())
        if not pool:
            return []
        target_vec = target.features.get("vector", []) if target else None
        scored = []
        for dna in pool:
            if target is not None and dna.id == target.id:
                continue
            if target_vec is not None:
                sim = cosine_similarity(target_vec, dna.features.get("vector", []))
            else:
                sim = 0.0
            scored.append({
                "dna_id": dna.dna_id,
                "incident_id": str(dna.incident_id),
                "family": dna.family,
                "severity": dna.severity,
                "confidence": dna.confidence,
                "risk_score": dna.risk_score,
                "fingerprint": dna.fingerprint[:16],
                "behaviors": dna.behaviors,
                "techniques": [t.get("id") for t in (dna.techniques or [])],
                "similarity": sim,
                "created_at": dna.created_at.isoformat(),
            })
        scored.sort(key=lambda s: s["similarity"], reverse=True)
        return scored[:top_k]


def _family_for(incident: Incident, etypes: set[str]) -> str:
    """Map an incident to an attack-family label from its category + event mix."""
    category = (incident.category or "").upper()
    if category in ("MALWARE",):
        return "Malware"
    if category in ("EXFILTRATION", "DATA_BREACH"):
        return "Data Exfiltration"
    if category in ("PRIVILEGE_ESCALATION",):
        return "Privilege Escalation"
    if category in ("CREDENTIAL_ATTACK", "ACCOUNT_TAKEOVER"):
        return "Credential Attack"
    if category in ("RECONNAISSANCE",):
        return "Reconnaissance"
    if "MALWARE_DETECTED" in etypes or "SUSPICIOUS_PROCESS" in etypes:
        return "Malware"
    if "DATA_EXFILTRATION" in etypes:
        return "Data Exfiltration"
    if "PRIVILEGE_ESCALATION" in etypes:
        return "Privilege Escalation"
    if "BRUTE_FORCE" in etypes or "LOGIN_FAILURE" in etypes:
        return "Credential Attack"
    if "PORT_SCAN" in etypes:
        return "Reconnaissance"
    return incident.category.title() if incident.category else "Generic"
