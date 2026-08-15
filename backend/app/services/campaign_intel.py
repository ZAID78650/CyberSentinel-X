"""Campaign intelligence engines.

Attack velocity, campaign momentum, campaign similarity, campaign-mutation
detection, MITRE detection coverage and business-impact estimation. Every
value is computed from the correlated events/incidents in the store — no
random or hardcoded numbers.

All functions accept a campaign dict as returned by
``app.services.soc_analytics.compute_campaigns`` (or resolve a campaign id
via :func:`campaign_from_id`), so the frontend can request them per campaign.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.intel import IncidentMitreMapping, MitreTechnique
from app.models.security import Asset, Incident, IncidentEvent, SecurityEvent
from app.services.prediction import STAGE_EVENT_MAP
from app.services.soc_analytics import compute_campaigns

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# MITRE tactic (as stored on MitreTechnique.tactic) expected per kill-chain stage.
STAGE_TACTIC = {
    "Reconnaissance": "reconnaissance",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Exfiltration": "exfiltration",
}

EXFIL_TYPES = {"DATA_EXFILTRATION", "DATA_DOWNLOAD", "SUSPICIOUS_NETWORK_CONNECTION"}
DATA_STORE_TYPES = {"DATABASE_ACCESS", "DATA_DOWNLOAD", "DATA_EXFILTRATION", "FILE_ACCESS"}


def stage_for_event(event_type: str) -> str:
    """Map an event type to its kill-chain stage (Unknown when unmapped)."""
    for stage, etypes in STAGE_EVENT_MAP:
        if event_type in etypes:
            return stage
    return "Unknown"


# ---------------------------------------------------------------------------
# Campaign resolution + shared data access
# ---------------------------------------------------------------------------

def campaign_from_id(db: Session, campaign_id: str) -> Optional[Dict[str, Any]]:
    """Resolve a campaign id (CGN-####) or incident id to a campaign dict."""
    if campaign_id.upper().startswith("CGN"):
        data = compute_campaigns(db, limit=50)
        for c in data["campaigns"]:
            if c["campaign_id"].upper() == campaign_id.upper():
                return c
        return None
    inc = db.scalar(select(Incident).where(Incident.incident_id == campaign_id))
    if inc is None:
        return None
    eids = list(db.scalars(
        select(IncidentEvent.event_id).where(IncidentEvent.incident_id == inc.id)
    ).all())
    techniques = list(db.scalars(
        select(IncidentMitreMapping.technique_id).where(IncidentMitreMapping.incident_id == inc.id)
    ).all())
    return {
        "campaign_id": campaign_id,
        "source": campaign_id,
        "category": inc.category or "GENERIC",
        "incidents": [inc.incident_id],
        "incident_count": 1,
        "event_count": len(eids),
        "techniques": sorted(set(techniques)),
        "severity": inc.severity,
        "first_seen": inc.created_at.isoformat(),
        "last_seen": inc.created_at.isoformat(),
        "duration_hours": 0.0,
        "risk_score": inc.risk_score or 0.0,
    }


def _campaign_incidents(db: Session, campaign: Dict[str, Any]) -> List[Incident]:
    ids = [i for i in campaign.get("incidents") or [] if i]
    if not ids:
        return []
    return list(db.scalars(select(Incident).where(Incident.incident_id.in_(ids))).all())


def _campaign_events(db: Session, campaign: Dict[str, Any], cap: int = 6000) -> List[SecurityEvent]:
    """Events correlated to a campaign's incidents (memory-bounded)."""
    incs = _campaign_incidents(db, campaign)
    if not incs:
        return []
    eids = list(db.scalars(
        select(IncidentEvent.event_id)
        .where(IncidentEvent.incident_id.in_([i.id for i in incs]))
        .limit(cap)
    ).all())
    events: List[SecurityEvent] = []
    for i in range(0, len(eids), 500):  # stay under SQLite's variable limit
        events.extend(
            db.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(eids[i:i + 500]))).all()
        )
    return events


def _campaign_techniques(db: Session, campaign: Dict[str, Any]) -> Set[str]:
    incs = _campaign_incidents(db, campaign)
    out: Set[str] = set()
    for inc in incs:
        out.update(db.scalars(
            select(IncidentMitreMapping.technique_id).where(IncidentMitreMapping.incident_id == inc.id)
        ).all())
    return out


def _jaccard(a: Set[Any], b: Set[Any]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / max(len(a | b), 1)


def _cosine(a: Counter, b: Counter) -> float:
    keys = set(a) | set(b)
    va = [a.get(k, 0) for k in keys]
    vb = [b.get(k, 0) for k in keys]
    dot = sum(x * y for x, y in zip(va, vb))
    na = sum(x * x for x in va) ** 0.5
    nb = sum(x * x for x in vb) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


# ---------------------------------------------------------------------------
# Feature 5 — Attack velocity
# ---------------------------------------------------------------------------

def attack_velocity(db: Session, campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Stage transition times, velocity (stages/hour) and acceleration."""
    events = _campaign_events(db, campaign)
    cid = campaign["campaign_id"]
    if not events:
        return {
            "campaign_id": cid, "band": "LOW", "attack_velocity": 0.0,
            "acceleration": 0.0, "campaign_escalation_detected": False,
            "stages_observed": [], "stage_transitions": [],
            "evidence": "No correlated events — velocity not computable.",
        }

    ordered = sorted(events, key=lambda e: e.timestamp)
    first = ordered[0].timestamp
    last = ordered[-1].timestamp
    duration_hours = max((last - first).total_seconds() / 3600.0, 1e-9)

    staged: Dict[str, datetime] = {}
    for e in ordered:
        s = stage_for_event(e.event_type)
        if s != "Unknown":
            staged.setdefault(s, e.timestamp)
    stage_seq = sorted(staged.items(), key=lambda kv: kv[1])

    transitions: List[Dict[str, Any]] = []
    prev: Optional[tuple] = None
    for stage, ts in stage_seq:
        if prev is not None:
            transitions.append({
                "from": prev[0], "to": stage,
                "minutes": round((ts - prev[1]).total_seconds() / 60.0, 1),
            })
        prev = (stage, ts)

    stages_advanced = len(stage_seq)
    velocity = (stages_advanced - 1) / duration_hours if stages_advanced > 1 else 0.0

    mid = first + (last - first) / 2
    early = sum(1 for _, ts in stage_seq if ts <= mid)
    late = sum(1 for _, ts in stage_seq if ts > mid)
    accel = (late - early) / max(early, 1)

    if velocity >= 3.0:
        band = "CRITICAL"
    elif velocity >= 1.5:
        band = "HIGH"
    elif velocity >= 0.5:
        band = "MEDIUM"
    else:
        band = "LOW"
    escalation = accel > 0.5 and band in ("HIGH", "CRITICAL")

    return {
        "campaign_id": cid,
        "stages_observed": [s for s, _ in stage_seq],
        "stage_transitions": transitions,
        "duration_hours": round(duration_hours, 2),
        "attack_velocity": round(velocity, 3),
        "acceleration": round(accel, 3),
        "band": band,
        "campaign_escalation_detected": escalation,
        "evidence": (
            f"{stages_advanced} stages advanced across {duration_hours:.1f}h "
            f"({velocity:.2f} stages/h)" + ("; late-stage burst detected" if escalation else "")
        ),
    }


# ---------------------------------------------------------------------------
# Feature 6 — Campaign momentum
# ---------------------------------------------------------------------------

def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + 2.71828 ** (-x))


def campaign_momentum(db: Session, campaign: Dict[str, Any]) -> Dict[str, Any]:
    """0-100 momentum from event-rate change, new assets/techniques, severity
    and anomaly signals between the first and second half of the campaign."""
    cid = campaign["campaign_id"]
    events = sorted(_campaign_events(db, campaign), key=lambda e: e.timestamp)
    if len(events) < 4:
        return {
            "campaign_id": cid, "momentum": 0.0, "status": "INSUFFICIENT_DATA",
            "new_assets": 0, "new_techniques": 0, "event_rate_change_pct": 0.0,
            "note": "Fewer than 4 correlated events — momentum not computable.",
        }

    mid = events[len(events) // 2].timestamp
    early = [e for e in events if e.timestamp <= mid]
    late = [e for e in events if e.timestamp > mid]

    def rate(xs: List[SecurityEvent]) -> float:
        if len(xs) < 2:
            return float(len(xs))
        span = max((xs[-1].timestamp - xs[0].timestamp).total_seconds() / 3600.0, 1e-9)
        return len(xs) / span

    rate_early, rate_late = rate(early), rate(late)
    rate_change = (rate_late - rate_early) / max(rate_early, 1e-9)

    assets_early = {e.asset_id for e in early if e.asset_id}
    assets_late = {e.asset_id for e in late if e.asset_id}
    new_assets = len(assets_late - assets_early)

    # Techniques whose incidents were created after the campaign midpoint.
    tech_first_seen: Dict[str, datetime] = {}
    for inc in _campaign_incidents(db, campaign):
        for tid in db.scalars(
            select(IncidentMitreMapping.technique_id).where(IncidentMitreMapping.incident_id == inc.id)
        ).all():
            tech_first_seen.setdefault(tid, inc.created_at)
    new_tech = {tid for tid, ts in tech_first_seen.items() if ts > mid}

    sev_early = max((SEVERITY_RANK.get(e.severity, 0) for e in early), default=0)
    sev_late = max((SEVERITY_RANK.get(e.severity, 0) for e in late), default=0)
    anom_late = sum(1 for e in late if e.is_anomalous) / max(len(late), 1)
    exfil = any(e.event_type in EXFIL_TYPES for e in late)

    components = {
        "event_rate_change": round(_sigmoid(rate_change), 3),
        "new_assets": round(min(1.0, new_assets / 5.0), 3),
        "anomaly_ratio": round(anom_late, 3),
        "severity_change": round(max(0.0, (sev_late - sev_early) / 4.0), 3),
        "exfiltration": 1.0 if exfil else 0.0,
    }
    weights = {"event_rate_change": 0.35, "new_assets": 0.20, "anomaly_ratio": 0.20,
               "severity_change": 0.15, "exfiltration": 0.10}
    momentum = round(100 * sum(components[k] * weights[k] for k in weights), 1)
    status = "ESCALATING" if momentum >= 65 else ("STABLE" if momentum >= 35 else "CONTAINED")

    return {
        "campaign_id": cid,
        "momentum": momentum,
        "status": status,
        "new_assets": new_assets,
        "new_techniques": len(new_tech),
        "event_rate_change_pct": round(rate_change * 100, 1),
        "severity_escalated": sev_late > sev_early,
        "anomaly_ratio_late": round(anom_late, 3),
        "components": components,
        "note": "Weighted signals: event-rate change, new assets, anomaly ratio, severity change, exfiltration.",
    }


# ---------------------------------------------------------------------------
# Feature 3 — Campaign similarity (explainable)
# ---------------------------------------------------------------------------

def _campaign_features(db: Session, campaign: Dict[str, Any]) -> Dict[str, Any]:
    events = _campaign_events(db, campaign, cap=4000)
    return {
        "techniques": _campaign_techniques(db, campaign),
        "event_types": Counter(e.event_type for e in events),
        "severities": Counter(e.severity for e in events),
        "protocols": Counter((e.metadata_ or {}).get("proto", "-") for e in events),
        "src_ips": {e.source_ip for e in events if e.source_ip},
        "dst_ips": {e.destination_ip for e in events if e.destination_ip},
        "count": len(events),
    }


# (label, feature key, comparison kind, weight)
SIMILARITY_COMPONENTS = [
    ("MITRE technique similarity", "techniques", "jaccard", 0.30),
    ("Event-type behavior", "event_types", "cosine", 0.25),
    ("Severity profile", "severities", "cosine", 0.15),
    ("Network protocol mix", "protocols", "cosine", 0.15),
    ("Source entity overlap", "src_ips", "jaccard", 0.15),
]


def similarity_between(db: Session, a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    fa, fb = _campaign_features(db, a), _campaign_features(db, b)
    parts = []
    for name, key, kind, weight in SIMILARITY_COMPONENTS:
        x, y = fa[key], fb[key]
        c = _jaccard(x, y) if kind == "jaccard" else _cosine(x, y)
        parts.append((name, weight, c))
    overall = round(100 * sum(c * w for _, w, c in parts), 1)
    top = sorted(parts, key=lambda p: -p[2])[:3]
    return {
        "similarity": overall,
        "components": [{"name": name, "weight": w, "score": round(100 * c, 1)} for name, w, c in parts],
        "top_reasons": [name for name, _, _ in top],
    }


def similar_campaigns(db: Session, campaign_id: str, limit: int = 10) -> Dict[str, Any]:
    """Rank all other campaigns by explainable similarity to the selected one."""
    base = campaign_from_id(db, campaign_id)
    if base is None:
        raise ValueError(f"Campaign {campaign_id} not found")
    data = compute_campaigns(db, limit=50)
    results = []
    for other in data["campaigns"]:
        if other["campaign_id"] == base["campaign_id"]:
            continue
        sim = similarity_between(db, base, other)
        results.append({
            "campaign_id": other["campaign_id"],
            "category": other.get("category"),
            "severity": other.get("severity"),
            "similarity": sim["similarity"],
            "components": sim["components"],
            "top_reasons": sim["top_reasons"],
        })
    results.sort(key=lambda r: -r["similarity"])
    return {"campaign_id": campaign_id, "similar": results[:limit],
            "note": "Similarity = weighted technique/behavior/severity/protocol/source components."}


# ---------------------------------------------------------------------------
# Feature 17 — Campaign mutation detection
# ---------------------------------------------------------------------------

def campaign_mutation(db: Session, campaign_id: str) -> Dict[str, Any]:
    """Flag campaigns with high behavioral similarity but low IOC overlap."""
    base = campaign_from_id(db, campaign_id)
    if base is None:
        raise ValueError(f"Campaign {campaign_id} not found")
    fb = _campaign_features(db, base)
    results = []
    data = compute_campaigns(db, limit=50)
    for other in data["campaigns"]:
        if other["campaign_id"] == base["campaign_id"]:
            continue
        fo = _campaign_features(db, other)
        behavioral = (0.5 * _cosine(fb["event_types"], fo["event_types"])
                      + 0.3 * _jaccard(fb["techniques"], fo["techniques"])
                      + 0.2 * _cosine(fb["protocols"], fo["protocols"]))
        ioc_sim = 0.5 * _jaccard(fb["src_ips"], fo["src_ips"]) + 0.5 * _jaccard(fb["dst_ips"], fo["dst_ips"])
        technique_sim = _jaccard(fb["techniques"], fo["techniques"])
        if behavioral >= 0.65:
            results.append({
                "campaign_id": other["campaign_id"],
                "behavioral_similarity": round(100 * behavioral, 1),
                "ioc_similarity": round(100 * ioc_sim, 1),
                "technique_similarity": round(100 * technique_sim, 1),
                "possible_mutation": behavioral >= 0.65 and ioc_sim < 0.4,
            })
    results.sort(key=lambda r: -r["behavioral_similarity"])
    return {
        "campaign_id": campaign_id,
        "mutations": results[:10],
        "note": "Possible mutation = behavioral similarity >= 65% with IOC overlap < 40%.",
    }


# ---------------------------------------------------------------------------
# Feature 19 — MITRE detection coverage
# ---------------------------------------------------------------------------

def mitre_coverage(db: Session, campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Expected vs detected MITRE techniques per kill-chain tactic."""
    detected = _campaign_techniques(db, campaign)
    techniques = list(db.scalars(select(MitreTechnique)).all())
    by_tactic: Dict[str, Set[str]] = {}
    for t in techniques:
        by_tactic.setdefault((t.tactic or "").lower(), set()).add(t.technique_id)

    stages: List[Dict[str, Any]] = []
    detected_total = expected_total = 0
    for stage, tactic in STAGE_TACTIC.items():
        expected = by_tactic.get(tactic, set())
        if not expected:
            continue
        have = detected & expected
        coverage = len(have) / len(expected)
        detected_total += len(have)
        expected_total += len(expected)
        stages.append({
            "stage": stage,
            "tactic": tactic,
            "expected_techniques": sorted(expected),
            "detected_techniques": sorted(have),
            "coverage": round(100 * coverage, 1),
        })
    overall = round(100 * detected_total / max(expected_total, 1), 1) if expected_total else 0.0
    gaps = sorted({t for s in stages for t in s["expected_techniques"]} - detected)
    return {
        "campaign_id": campaign["campaign_id"],
        "overall_coverage": overall,
        "stages": stages,
        "detection_gaps": gaps[:25],
        "observed_techniques": sorted(detected),
        "note": "Coverage = observed techniques / techniques expected for the stage's tactic.",
    }


# ---------------------------------------------------------------------------
# Feature 29 — Business impact (qualitative, evidence-based)
# ---------------------------------------------------------------------------

def business_impact(db: Session, campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Translate technical risk into operational impact (no invented financials)."""
    events = _campaign_events(db, campaign, cap=4000)
    asset_names = {e.asset_id for e in events if e.asset_id}
    assets: List[Asset] = []
    if asset_names:
        assets = list(db.scalars(select(Asset).where(Asset.name.in_(list(asset_names)))).all())
    critical_assets = [a for a in assets if (a.criticality or 0) >= 8]
    users = sorted({e.user_id for e in events if e.user_id})
    data_events = [e for e in events if e.event_type in DATA_STORE_TYPES]
    data_stores = sorted({e.destination_ip or e.asset_id for e in data_events if e.destination_ip or e.asset_id})
    endpoints = sorted({(e.destination_ip, (e.metadata_ or {}).get("proto", "-")) for e in events if e.destination_ip})

    if critical_assets or data_stores:
        impact = "HIGH"
    elif assets or users:
        impact = "MEDIUM"
    else:
        impact = "LOW"

    return {
        "campaign_id": campaign["campaign_id"],
        "critical_assets": [a.name for a in critical_assets],
        "critical_services": [f"{ip} ({proto})" for ip, proto in endpoints[:20]],
        "sensitive_data_stores": data_stores[:20],
        "affected_users": users[:20],
        "impact": impact,
        "evidence": (
            f"{len(critical_assets)} critical assets, {len(data_stores)} sensitive "
            f"data stores, {len(users)} users, {len(endpoints)} external endpoints"
        ),
    }
