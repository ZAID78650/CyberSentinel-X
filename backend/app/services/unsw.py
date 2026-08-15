"""UNSW-NB15 network-traffic dataset ingestion + automatic detection.

The UNSW-NB15 dataset (https://research.unsw.edu.au/projects/unsw-nb15-dataset)
is a labeled corpus of ~2.5M real network flows covering nine attack families
plus normal traffic. This module:

1. Parses the training/testing CSVs (pandas, fast).
2. Maps each flow to the CyberSentinel X event model:
   - attack category -> event type + severity
   - flows -> synthesized source/destination IPs (the public CSVs ship
     without IP columns), deterministic per row
   - all raw UNSW features preserved in event metadata for 3D analysis
3. Runs the hybrid detection engine (Isolation Forest fit on a stratified
   sample + category rules) and bulk-inserts scored events.
4. Auto-correlates attack flows into aggregated alerts and incidents
   (one alert per attack family, incidents for the most severe families),
   so the SOC console lights up without any manual triage.

Ingestion is capped, resumable, and safe to re-run (it clears dataset
events first). Progress is tracked in :data:`UNSW_STATE` for the UI.
"""
from __future__ import annotations

import hashlib
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.ml.anomaly import AnomalyDetector
from app.models.investigation import (
    AttackEdge,
    AttackNode,
    IncidentReport,
    Investigation,
    InvestigationEvidence,
    ResponseRecommendation,
    RiskScore,
    ApprovalRequest,
)
from app.models.intel import IncidentMitreMapping
from app.models.security import Alert, Incident, IncidentEvent, SecurityEvent
from app.services.alert_service import create_alert_from_events, create_incident_from_alert

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# UNSW-NB15 -> CyberSentinel X mapping
# ---------------------------------------------------------------------------

# Column -> float coercion for metadata; non-numeric (proto/service/state)
# are kept as strings.
NUMERIC_COLUMNS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
    "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports",
]
STRING_COLUMNS = ["proto", "service", "state"]

# UNSW attack family -> (event_type, severity)
ATTACK_MAP: Dict[str, Tuple[str, str]] = {
    "Reconnaissance": ("PORT_SCAN", "LOW"),
    "Fuzzers": ("SUSPICIOUS_NETWORK_CONNECTION", "MEDIUM"),
    "Analysis": ("SUSPICIOUS_PROCESS", "MEDIUM"),
    "Backdoor": ("MALWARE_DETECTED", "CRITICAL"),
    "DoS": ("SUSPICIOUS_NETWORK_CONNECTION", "HIGH"),
    "Exploits": ("PRIVILEGE_ESCALATION", "CRITICAL"),
    "Generic": ("SUSPICIOUS_NETWORK_CONNECTION", "MEDIUM"),
    "Shellcode": ("MALWARE_DETECTED", "CRITICAL"),
    "Worms": ("MALWARE_DETECTED", "CRITICAL"),
}
NORMAL_TYPES = ["LOGIN_SUCCESS", "FILE_ACCESS", "DATABASE_ACCESS"]

# Alert category per attack family
ALERT_CATEGORY: Dict[str, str] = {
    "Reconnaissance": "RECONNAISSANCE",
    "Fuzzers": "FUZZING",
    "Analysis": "ANALYSIS",
    "Backdoor": "BACKDOOR",
    "DoS": "DENIAL_OF_SERVICE",
    "Exploits": "EXPLOITATION",
    "Generic": "GENERIC_ATTACK",
    "Shellcode": "MALWARE",
    "Worms": "MALWARE",
}

ASSET_POOL = ["ast-app-server", "ast-prod-api", "ast-file-share", "ast-email-gw"]

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _hash(s: str) -> int:
    return int(hashlib.md5(s.encode()).hexdigest(), 16)


def synthesize_ips(prefix: str, row_id: int, label: int) -> Tuple[str, str]:
    """Deterministic pseudo-IPs for a flow (UNSW CSVs ship without IPs)."""
    h = _hash(f"{prefix}:{row_id}")
    if label == 0:  # benign internal client
        src = f"10.{(h >> 8) % 32}.{(h >> 4) % 64}.{h % 254 + 1}"
    else:            # hostile external source
        src = f"45.{(h >> 8) % 240 + 1}.{(h >> 4) % 254 + 1}.{h % 254 + 1}"
    dst = f"10.0.2.{h % 254 + 1}"
    return src, dst


def _event_timestamp(row_id: int, total: int, span_days: int = 7) -> datetime:
    """Deterministically spread flows over the last `span_days` days.

    Row 1 is the oldest; the final row lands at (nearly) now.
    """
    total = max(total, 1)
    fraction = (row_id - 1) / max(total - 1, 1)
    age = timedelta(days=span_days * (1.0 - fraction))
    return datetime.now(timezone.utc) - age


def map_row(prefix: str, row_id: int, seq: int, total: int, row: Dict[str, Any]) -> Dict[str, Any]:
    """Map one UNSW-NB15 CSV row to a canonical event payload.

    ``row_id`` is the per-file row index (used for stable event IDs); ``seq``
    is the global position across all files (used to spread timestamps so the
    merged corpus ends at "now").
    """
    attack_cat = str(row.get("attack_cat") or "").strip() or "Normal"
    label = int(row.get("label") or 0)
    is_attack = label == 1 and attack_cat.lower() != "normal"

    if is_attack:
        event_type, severity = ATTACK_MAP.get(
            attack_cat, ("SUSPICIOUS_NETWORK_CONNECTION", "MEDIUM")
        )
    else:
        event_type = NORMAL_TYPES[row_id % len(NORMAL_TYPES)]
        severity = "LOW"

    src_ip, dst_ip = synthesize_ips(prefix, row_id, label)

    metadata: Dict[str, Any] = {"dataset": "unsw-nb15", "unsw_id": row_id, "attack_cat": attack_cat, "label": label}
    for col in STRING_COLUMNS:
        metadata[col] = str(row.get(col) or "-")
    for col in NUMERIC_COLUMNS:
        try:
            val = row.get(col)
            metadata[col] = float(val) if val is not None and str(val).strip() not in ("", "-") else 0.0
        except (TypeError, ValueError):
            metadata[col] = 0.0

    return {
        "event_id": f"unsw-{prefix}-{row_id}",
        "timestamp": _event_timestamp(seq, total),
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "user_id": None,
        "device_id": None,
        "asset_id": ASSET_POOL[row_id % len(ASSET_POOL)],
        "source": "unsw-bulk",
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Detection scoring (bulk, no per-event DB queries)
# ---------------------------------------------------------------------------

def _rule_score_for(data: Dict[str, Any]) -> Tuple[float, Optional[str]]:
    """Category-based rule score + detection reason (dataset ground truth)."""
    meta = data.get("metadata") or {}
    attack_cat = meta.get("attack_cat") or "Normal"
    label = meta.get("label") or 0
    if label == 1 and attack_cat.lower() != "normal":
        proto = meta.get("proto", "-")
        state = meta.get("state", "-")
        sbytes = meta.get("sbytes", 0)
        dbytes = meta.get("dbytes", 0)
        sev = ATTACK_MAP.get(attack_cat, ("", "MEDIUM"))[1]
        base = {"LOW": 0.55, "MEDIUM": 0.65, "HIGH": 0.8, "CRITICAL": 0.92}[sev]
        return base, (
            f"UNSW-NB15 {attack_cat} attack detected "
            f"({proto}/{state}, {sbytes:.0f}B -> {dbytes:.0f}B)"
        )
    return 0.0, None


def fit_detector(events: List[Dict[str, Any]], fit_sample: int = 20000) -> AnomalyDetector:
    """Fit the Isolation Forest on a stratified ~50/50 normal/attack sample."""
    detector = AnomalyDetector(contamination=0.06)
    normals = [e for e in events if (e["metadata"].get("label") or 0) == 0]
    attacks = [e for e in events if (e["metadata"].get("label") or 0) == 1]
    sample = normals[: fit_sample // 2] + attacks[: fit_sample // 2]
    if len(sample) >= 12:
        detector.fit(sample)
        logger.info("unsw: IsolationForest fitted on %d sampled flows", len(sample))
    return detector


def score_with_detector(detector: AnomalyDetector, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Score events with an already-fitted detector (rule score wins ties)."""
    scored: List[Dict[str, Any]] = []
    for e in events:
        ml = detector.score(e)
        rule, reason = _rule_score_for(e)
        score = round(max(ml, rule), 4)
        is_anomalous = score >= 0.55
        if not reason and is_anomalous:
            reason = f"Isolation Forest anomaly score {score:.2f} on network flow"
        e["anomaly_score"] = score
        e["is_anomalous"] = is_anomalous
        e["detection_reason"] = reason
        scored.append(e)
    return scored


def score_and_annotate(events: List[Dict[str, Any]], fit_sample: int = 20000) -> List[Dict[str, Any]]:
    """Fit the Isolation Forest on a stratified sample and score every event.

    Returns the same dicts with ``anomaly_score`` / ``is_anomalous`` /
    ``detection_reason`` filled in.
    """
    detector = fit_detector(events, fit_sample)
    return score_with_detector(detector, events)


# ---------------------------------------------------------------------------
# Correlation into alerts + incidents
# ---------------------------------------------------------------------------

def _build_correlations(scored: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group anomalous flows by (attack family) and summarize clusters."""
    groups: Dict[str, Dict[str, Any]] = {}
    for e in scored:
        if not e["is_anomalous"]:
            continue
        meta = e.get("metadata") or {}
        attack_cat = meta.get("attack_cat") or "Normal"
        key = attack_cat if attack_cat.lower() != "normal" else e["event_type"]
        g = groups.setdefault(key, {
            "attack_cat": attack_cat, "event_type": e["event_type"],
            "count": 0, "severity_rank": 0, "severity": "LOW",
            "anomaly_sum": 0.0, "event_ids": [],
        })
        g["count"] += 1
        g["anomaly_sum"] += e.get("anomaly_score") or 0.0
        if SEVERITY_RANK.get(e["severity"], 0) > g["severity_rank"]:
            g["severity_rank"] = SEVERITY_RANK.get(e["severity"], 0)
            g["severity"] = e["severity"]
        if len(g["event_ids"]) < 250:
            g["event_ids"].append(e["event_id"])
    return sorted(
        groups.values(),
        key=lambda g: (g["severity_rank"], g["count"]),
        reverse=True,
    )


def create_correlated_incidents(
    db: Session,
    clusters: List[Dict[str, Any]],
    actor: str = "unsw-detection-agent",
    max_alerts: int = 24,
    max_incidents: int = 12,
) -> Tuple[int, int]:
    """Turn flow clusters into aggregated Alerts + Incidents (automatic detection)."""
    alert_count = incident_count = 0
    for g in clusters[:max_alerts]:
        attack_cat = g["attack_cat"]
        severity = g["severity"]
        category = ALERT_CATEGORY.get(attack_cat, "GENERIC_ATTACK")
        confidence = round(min(0.98, 0.55 + 0.35 * (1 - pow(2.718, -g["count"] / 5000.0))), 2)
        title = f"[{severity}] {attack_cat} Campaign Detected — UNSW-NB15"

        events = list(db.scalars(
            select(SecurityEvent).where(SecurityEvent.event_id.in_(g["event_ids"]))
        ).all())
        if not events:
            continue
        alert = create_alert_from_events(db, events, title, actor=actor)
        alert.category = category
        alert.confidence = confidence
        alert.description = (
            f"Automatic detection correlated {g['count']} UNSW-NB15 {attack_cat} flows "
            f"(max anomaly score {g['anomaly_sum'] / max(g['count'], 1):.2f})."
        )
        db.commit()
        alert_count += 1

        if incident_count >= max_incidents:
            continue
        incident = create_incident_from_alert(db, alert, actor=actor)
        incident.description = (
            f"{g['count']} correlated {attack_cat} flows from the UNSW-NB15 dataset "
            f"triggered automatic detection. {alert.detection_reason or ''}"
        )[:2000]
        db.commit()
        incident_count += 1
        logger.info("unsw: correlated %s -> alert %s, incident %s", attack_cat, alert.alert_id, incident.incident_id)
    return alert_count, incident_count


# ---------------------------------------------------------------------------
# CSV parsing + orchestrated ingestion
# ---------------------------------------------------------------------------

def read_rows(path: str, nrows: Optional[int] = None, skiprows: Optional[int] = None) -> List[Dict[str, Any]]:
    """Read a slice of the CSV into record dicts (memory-bounded for streaming)."""
    import pandas as pd  # deferred import keeps app startup light

    df = pd.read_csv(path, nrows=nrows, skiprows=skiprows)
    df = df.fillna("")
    df.columns = [c.strip().lower() for c in df.columns]
    return df.to_dict(orient="records")


def count_rows(path: str) -> int:
    """Cheap row count for a CSV (reads a single column)."""
    import pandas as pd  # deferred import keeps app startup light

    return int(pd.read_csv(path, usecols=[0]).shape[0])


# Global ingestion progress/state (single worker at a time)
UNSW_STATE: Dict[str, Any] = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "total_rows": 0,
    "processed_rows": 0,
    "inserted_rows": 0,
    "attack_flows": 0,
    "normal_flows": 0,
    "alerts_created": 0,
    "incidents_created": 0,
    "files": [],
    "limit": 0,
}
_UNSW_LOCK = threading.Lock()


def _clear_dataset_events(db: Session) -> int:
    """Delete existing UNSW-bulk events and the incidents/alerts they fed.

    Uses subqueries / single-table deletes instead of giant IN clauses to
    stay under SQLite's variable limit with 250k+ event rows.
    """
    count = db.scalar(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.source == "unsw-bulk")
    ) or 0
    if count == 0:
        return 0

    # Incidents and alerts created from this dataset carry the family title.
    incident_ids = list(db.scalars(
        select(Incident.id).where(Incident.title.like("%UNSW-NB15%"))
    ).all())
    alert_ids = list(db.scalars(
        select(Alert.id).where(Alert.title.like("%UNSW-NB15%"))
    ).all())

    # Incident-adjacent rows (chunked IN to respect SQLite limits)
    for model in (IncidentMitreMapping, RiskScore, ResponseRecommendation, ApprovalRequest,
                  AttackNode, AttackEdge, IncidentReport):
        _delete_by_incident_ids(db, model, incident_ids, key="incident_id")
    inv_ids = []
    for i in range(0, len(incident_ids), 400):
        inv_ids.extend(db.scalars(select(Investigation.id).where(
            Investigation.incident_id.in_(incident_ids[i : i + 400])
        )).all())
    _delete_by_incident_ids(db, InvestigationEvidence, inv_ids, key="investigation_id")
    _delete_by_incident_ids(db, Investigation, incident_ids, key="incident_id")
    _delete_by_incident_ids(db, IncidentEvent, incident_ids, key="incident_id")
    _delete_by_incident_ids(db, Incident, incident_ids, key="id")
    if alert_ids:
        db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
    # Events themselves — single statement, no IN list.
    db.execute(delete(SecurityEvent).where(SecurityEvent.source == "unsw-bulk"))
    db.commit()
    logger.info("unsw: removed %d dataset events, %d incidents, %d alerts",
                count, len(incident_ids), len(alert_ids))
    return count


def _delete_by_incident_ids(db: Session, model, incident_ids, key: str = "incident_id", chunk: int = 400):
    if not incident_ids:
        return
    for i in range(0, len(incident_ids), chunk):
        ids = incident_ids[i : i + chunk]
        db.execute(delete(model).where(getattr(model, key).in_(ids)))


def ingest_unsw_files(
    paths: List[str],
    limit: int = 0,
    span_days: int = 7,
    fit_sample: int = 20000,
    clear_existing: bool = True,
) -> Dict[str, Any]:
    """Ingest UNSW-NB15 CSVs end-to-end. Runs in a worker thread.

    ``clear_existing=False`` appends to the corpus instead of replacing it
    (used for analyst-uploaded datasets so they don't wipe the main feed).
    """
    with _UNSW_LOCK:
        if UNSW_STATE["running"]:
            return {"error": "An ingestion job is already running."}
        UNSW_STATE.update(
            running=True, started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None, last_error=None, total_rows=0, processed_rows=0,
            inserted_rows=0, attack_flows=0, normal_flows=0,
            alerts_created=0, incidents_created=0, files=list(paths), limit=limit,
        )

    db = SessionLocal()
    try:
        if clear_existing:
            _clear_dataset_events(db)

        # --- stream the CSVs in bounded batches -----------------------------
        # Peak memory stays proportional to one batch (CHUNK rows) instead of
        # the whole corpus — the Render free tier only has 512 MB RAM and the
        # previous all-at-once load (raw + events + scored lists) was OOM-killed.
        CHUNK = 5000
        BULK = 5000

        file_totals = [count_rows(p) for p in paths]
        grand_total = sum(file_totals)
        if limit and limit > 0:
            grand_total = min(grand_total, limit)

        detector = None
        inserted = 0
        anomaly_events: List[Dict[str, Any]] = []
        seq = 0
        total_rows = 0
        for fi, (p, ftotal) in enumerate(zip(paths, file_totals)):
            if total_rows >= grand_total:
                break
            if "train" in p.lower():
                prefix = "train"
            elif "test" in p.lower():
                prefix = "test"
            else:
                prefix = f"set{fi}"
            file_seen = 0
            while file_seen < ftotal and total_rows < grand_total:
                take = min(CHUNK, ftotal - file_seen, grand_total - total_rows)
                rows = read_rows(p, nrows=take, skiprows=file_seen or None)
                if not rows:
                    break
                events = [
                    map_row(prefix, file_seen + i + 1, seq + i + 1, grand_total, row)
                    for i, row in enumerate(rows)
                ]
                del rows
                seq += len(events)
                total_rows += len(events)
                file_seen += len(events)
                UNSW_STATE["total_rows"] = total_rows

                if detector is None:
                    detector = fit_detector(events, fit_sample)
                scored = score_with_detector(detector, events)
                anomaly_events.extend(e for e in scored if e["is_anomalous"])

                for start in range(0, len(scored), BULK):
                    chunk = scored[start : start + BULK]
                    db.bulk_insert_mappings(
                        SecurityEvent,
                        [
                            {
                                "event_id": e["event_id"],
                                "timestamp": e["timestamp"],
                                "event_type": e["event_type"],
                                "severity": e["severity"],
                                "source_ip": e.get("source_ip"),
                                "destination_ip": e.get("destination_ip"),
                                "user_id": e.get("user_id"),
                                "device_id": e.get("device_id"),
                                "asset_id": e.get("asset_id"),
                                "source": "unsw-bulk",
                                "metadata_": e.get("metadata"),
                                "anomaly_score": e.get("anomaly_score"),
                                "is_anomalous": e.get("is_anomalous", False),
                                "detection_reason": e.get("detection_reason"),
                            }
                            for e in chunk
                        ],
                    )
                    db.commit()
                    inserted += len(chunk)
                    UNSW_STATE["processed_rows"] = inserted
                del scored, events

        UNSW_STATE["inserted_rows"] = inserted
        UNSW_STATE["attack_flows"] = len(anomaly_events)
        UNSW_STATE["normal_flows"] = inserted - len(anomaly_events)

        # --- automatic correlation -> alerts + incidents --------------------
        clusters = _build_correlations(anomaly_events)
        alerts, incidents = create_correlated_incidents(db, clusters)
        UNSW_STATE["alerts_created"] = alerts
        UNSW_STATE["incidents_created"] = incidents
        UNSW_STATE["last_error"] = None
        logger.info(
            "unsw: ingested %d flows (%d attack, %d normal), %d alerts, %d incidents",
            inserted, len(anomaly_events), UNSW_STATE["normal_flows"],
            alerts, incidents,
        )
        return {
            "inserted": inserted,
            "attack_flows": len(anomaly_events),
            "normal_flows": UNSW_STATE["normal_flows"],
            "alerts_created": alerts,
            "incidents_created": incidents,
        }
    except Exception as exc:  # pragma: no cover
        logger.exception("unsw ingestion failed")
        UNSW_STATE["last_error"] = str(exc)[:500]
        return {"error": str(exc)}
    finally:
        db.close()
        UNSW_STATE["finished_at"] = datetime.now(timezone.utc).isoformat()
        UNSW_STATE["running"] = False


def start_ingestion(paths: List[str], limit: int = 0, clear_existing: bool = True) -> bool:
    """Kick off ingestion on a daemon thread; returns False if already running."""
    with _UNSW_LOCK:
        if UNSW_STATE["running"]:
            return False
    thread = threading.Thread(
        target=ingest_unsw_files,
        args=(paths, limit),
        kwargs={"clear_existing": clear_existing},
        daemon=True,
        name="unsw-ingest",
    )
    thread.start()
    return True
