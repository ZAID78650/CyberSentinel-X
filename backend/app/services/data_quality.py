"""Data quality center + ML model drift monitoring.

* :func:`data_quality` — missing values, duplicates, schema errors, class
  imbalance, staleness and ingestion failures over the event store.
* :func:`model_drift` — Population Stability Index / KL divergence between the
  reference anomaly-score distribution and the recent window.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.security import SecurityEvent

logger = logging.getLogger(__name__)

# columns we expect every event to carry (schema conformance)
REQUIRED_COLUMNS = {
    "event_type": SecurityEvent.event_type,
    "severity": SecurityEvent.severity,
    "timestamp": SecurityEvent.timestamp,
    "source_ip": SecurityEvent.source_ip,
}


def data_quality(db: Session) -> Dict[str, Any]:
    """Real completeness/consistency metrics over the stored events."""
    total = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    if total == 0:
        return {"quality": 0.0, "pipeline": "EMPTY",
                "note": "No events ingested — quality not computable.",
                "events": 0, "missing_rates": {}, "duplicates": 0}

    missing_rates: Dict[str, float] = {}
    for name, col in REQUIRED_COLUMNS.items():
        n_missing = db.scalar(select(func.count()).where(col.is_(None))) or 0
        missing_rates[name] = round(100.0 * n_missing / total, 2)

    duplicates = db.scalar(
        select(func.count()).select_from(
            select(SecurityEvent.event_id).group_by(SecurityEvent.event_id)
            .having(func.count() > 1).subquery()
        )
    ) or 0

    anomalous = db.scalar(select(func.count()).where(SecurityEvent.is_anomalous.is_(True))) or 0
    imbalance = abs(anomalous / total - 0.5) * 2.0  # 0 = balanced, 1 = extreme

    latest = db.scalar(select(func.max(SecurityEvent.timestamp)))
    stale_hours = 0.0
    if latest is not None:
        if latest.tzinfo is None:  # SQLite stores naive datetimes
            latest = latest.replace(tzinfo=timezone.utc)
        stale_hours = max(0.0, (datetime.now(timezone.utc) - latest).total_seconds() / 3600.0)

    # ingestion health (the running job's last error)
    ingest_failed = False
    try:
        from app.services.unsw import UNSW_STATE
        ingest_failed = bool(UNSW_STATE.get("last_error"))
    except Exception:  # pragma: no cover
        pass

    avg_missing = sum(missing_rates.values()) / max(len(missing_rates), 1)
    dup_penalty = min(15.0, duplicates * 5.0)
    imbalance_penalty = 15.0 * imbalance
    stale_penalty = 10.0 if stale_hours > 24 else (5.0 if stale_hours > 6 else 0.0)
    ingest_penalty = 15.0 if ingest_failed else 0.0

    quality = round(max(0.0, 100.0 - avg_missing - dup_penalty - imbalance_penalty
                        - stale_penalty - ingest_penalty), 1)
    pipeline = "HEALTHY" if quality >= 90 else ("DEGRADED" if quality >= 70 else "POOR")

    return {
        "quality": quality,
        "pipeline": pipeline,
        "events": total,
        "missing_rates": missing_rates,
        "duplicates": duplicates,
        "class_imbalance": round(imbalance, 3),
        "anomalous_ratio": round(anomalous / total, 3),
        "stale_hours": round(stale_hours, 1),
        "ingestion_healthy": not ingest_failed,
        "penalties": {
            "missing": round(avg_missing, 2),
            "duplicates": round(dup_penalty, 2),
            "class_imbalance": round(imbalance_penalty, 2),
            "staleness": stale_penalty,
            "ingestion_failure": ingest_penalty,
        },
    }


# ---------------------------------------------------------------------------
# Feature 18 — Model drift (PSI / KL)
# ---------------------------------------------------------------------------

def _psi(reference: List[float], current: List[float], bins: int = 10) -> float:
    """Population Stability Index between two score distributions."""
    if not reference or not current:
        return 0.0
    import numpy as np

    edges = np.percentile(reference, np.linspace(0, 100, bins + 1))
    edges[0], edges[-1] = -1e9, 1e9
    ref_counts = np.histogram(reference, bins=edges)[0]
    cur_counts = np.histogram(current, bins=edges)[0]
    ref_share = ref_counts / max(ref_counts.sum(), 1)
    cur_share = cur_counts / max(cur_counts.sum(), 1)
    # clip to avoid log(0) — PSI convention
    ref_share = np.clip(ref_share, 1e-4, None)
    cur_share = np.clip(cur_share, 1e-4, None)
    return float(np.sum((cur_share - ref_share) * np.log(cur_share / ref_share)))


def _kl(reference: List[float], current: List[float], bins: int = 10) -> float:
    """KL divergence between binned empirical distributions."""
    if not reference or not current:
        return 0.0
    import numpy as np

    lo = min(min(reference), min(current))
    hi = max(max(reference), max(current))
    if hi <= lo:
        return 0.0
    ref_hist, _ = np.histogram(reference, bins=bins, range=(lo, hi))
    cur_hist, _ = np.histogram(current, bins=bins, range=(lo, hi))
    p = ref_hist / max(ref_hist.sum(), 1)
    q = cur_hist / max(cur_hist.sum(), 1)
    p = np.clip(p, 1e-6, None)
    q = np.clip(q, 1e-6, None)
    return float(np.sum(p * np.log(p / q)))


def model_drift(db: Session, window: int = 500, reference_ratio: float = 0.5) -> Dict[str, Any]:
    """Compare the reference anomaly-score distribution with the recent window."""
    scores = list(db.scalars(
        select(SecurityEvent.anomaly_score)
        .where(SecurityEvent.anomaly_score.isnot(None))
        .order_by(SecurityEvent.timestamp)
    ).all())
    if len(scores) < 100:
        return {
            "drift": "LOW", "psi": 0.0, "kl_divergence": 0.0,
            "status": "HEALTHY", "reference_events": len(scores), "window_events": len(scores),
            "note": "Fewer than 100 scored events — drift not statistically meaningful.",
        }
    split = int(len(scores) * reference_ratio)
    reference = scores[:split]
    current = scores[-window:]
    psi = _psi(reference, current)
    kl = _kl(reference, current)
    if psi > 0.25:
        level, status = "HIGH", "RETRAINING RECOMMENDED"
    elif psi > 0.1:
        level, status = "MODERATE", "MONITOR"
    else:
        level, status = "LOW", "HEALTHY"

    return {
        "model": "Hybrid Detection (Isolation Forest + category rules)",
        "drift": level,
        "status": status,
        "psi": round(psi, 4),
        "kl_divergence": round(kl, 4),
        "reference_events": len(reference),
        "window_events": len(current),
        "thresholds": {"low": 0.1, "moderate": 0.25},
        "note": "PSI between the reference half and the most recent scored events.",
    }
