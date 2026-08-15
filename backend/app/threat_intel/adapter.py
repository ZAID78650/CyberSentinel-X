"""Threat intelligence adapter.

Consumers talk to `ThreatIntelAdapter`, which resolves against the local
synthetic feed. A live STIX/TAXII or vendor API can be wired in by adding a
provider to `_providers` without changing any consumer code.
"""
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.intel import ThreatIndicator, ThreatIntelligenceSource
from app.threat_intel.local_intel import LOCAL_INDICATORS

logger = logging.getLogger(__name__)


class ThreatIntelAdapter:
    """Resolves indicators against the local feed (and future APIs)."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self._ensure_loaded()

    def _ensure_loaded(self) -> None:
        count = self.db.scalar(select(func.count()).select_from(ThreatIndicator)) or 0
        if count == 0:
            seed_local_indicators(self.db)

    # ------------------------------------------------------------------
    def check_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check an event's IPs / hashes against the feed."""
        hits: List[Dict[str, Any]] = []
        src_ip = event.get("source_ip")
        dst_ip = event.get("destination_ip")
        meta = event.get("metadata") or {}

        candidates: List[Dict[str, str]] = []
        if src_ip:
            candidates.append({"type": "IP", "value": src_ip})
        if dst_ip:
            candidates.append({"type": "IP", "value": dst_ip})
        for key in ("file_hash", "hash"):
            if meta.get(key):
                candidates.append({"type": "HASH", "value": meta[key]})
        if event.get("event_type") == "MALWARE_DETECTED" and meta.get("malware"):
            candidates.append({"type": "MALWARE", "value": meta["malware"]})
        if meta.get("cve"):
            candidates.append({"type": "CVE", "value": meta["cve"]})
        if meta.get("domain"):
            candidates.append({"type": "DOMAIN", "value": meta["domain"]})

        for cand in candidates:
            ind = self.db.scalar(
                select(ThreatIndicator).where(
                    ThreatIndicator.indicator_type == cand["type"],
                    ThreatIndicator.value == cand["value"],
                )
            )
            if ind:
                hits.append({
                    "indicator": ind.value,
                    "type": ind.indicator_type,
                    "severity": ind.severity,
                    "confidence": ind.confidence,
                    "reason": f"Threat intel match: {ind.value} ({ind.indicator_type}) — {ind.description or 'known malicious indicator'}",
                    "tags": ind.tags,
                })
        return hits

    # ------------------------------------------------------------------
    def search(self, query: str, indicator_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Free-text search over the indicator feed."""
        q = query.strip().lower()
        stmt = select(ThreatIndicator)
        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type.upper())
        indicators = list(self.db.scalars(stmt).all())

        hits: List[Dict[str, Any]] = []
        for ind in indicators:
            haystack = " ".join(
                [ind.value, ind.description or "", ind.indicator_type, " ".join(ind.tags or [])]
            ).lower()
            if q in haystack or q in ind.value.lower():
                hits.append({
                    "indicator_type": ind.indicator_type,
                    "value": ind.value,
                    "confidence": ind.confidence,
                    "severity": ind.severity,
                    "source": ind.source,
                    "tags": ind.tags,
                    "description": ind.description,
                    "match_reason": self._match_reason(q, ind),
                })
        # Exact value match ranks first
        hits.sort(key=lambda h: (h["value"].lower() != q, -h["confidence"]))
        return hits

    def _match_reason(self, q: str, ind: ThreatIndicator) -> str:
        if q == ind.value.lower():
            return "Exact indicator match"
        if q in ind.value.lower():
            return "Substring match on indicator value"
        return "Matched description/tags"

    # ------------------------------------------------------------------
    def list_indicators(self, page: int = 1, page_size: int = 50, indicator_type: Optional[str] = None) -> tuple:
        stmt = select(ThreatIndicator).order_by(ThreatIndicator.severity.desc(), ThreatIndicator.last_seen.desc())
        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type.upper())
        total = len(list(self.db.scalars(stmt).all()))
        items = list(self.db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
        return items, total

    def list_sources(self) -> List[ThreatIntelligenceSource]:
        return list(self.db.scalars(select(ThreatIntelligenceSource)).all())


def seed_local_indicators(db: Session) -> None:
    """Insert the synthetic local feed if the table is empty."""
    count = db.scalar(select(func.count()).select_from(ThreatIndicator)) or 0
    if count:
        return
    for ind in LOCAL_INDICATORS:
        db.add(ThreatIndicator(
            indicator_type=ind["indicator_type"],
            value=ind["value"],
            confidence=ind["confidence"],
            severity=ind["severity"],
            source=ind["source"],
            tags=ind["tags"],
            description=ind["description"],
        ))
    source_count = db.scalar(select(func.count()).select_from(ThreatIntelligenceSource)) or 0
    if source_count == 0:
        from app.threat_intel.local_intel import LOCAL_SOURCES
        for s in LOCAL_SOURCES:
            db.add(ThreatIntelligenceSource(
                name=s["name"], source_type=s["source_type"], status=s["status"], description=s["description"]
            ))
    db.commit()
    logger.info("seeded %d threat indicators", len(LOCAL_INDICATORS))
