"""Analyst feedback loop.

Analysts label alerts TRUE_POSITIVE / FALSE_POSITIVE / BENIGN / UNKNOWN.
The stats endpoint reports how many signals were correlated into alerts, the
label distribution, and the observed false-positive rate — all explainable
and audited (every label is a row in `analyst_feedback`).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.feedback import AnalystFeedback, CorrelationSetting
from app.models.investigation import ActionLog
from app.models.security import Alert, SecurityEvent

LABELS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "UNKNOWN"]

# Base anomaly-score floor used by the Detection Agent to flag events.
BASE_DETECTION_FLOOR = 0.55

# Retrain rules (visible, explainable — never a black box).
RAISE_STEP = 0.15   # noisy category: raise the floor by this much
LOWER_STEP = 0.05   # clean category: lower the floor by this much
FPR_NOISE = 0.5     # FP rate above this (with >=2 labels) triggers a raise
PRECISION_CLEAN = 0.8  # precision at/above this (with low FPR) triggers a lower


def load_correlation_floors(db: Session) -> Dict[str, float]:
    """event_type -> floor adjustment, for the Detection Agent's scoring."""
    rows = db.scalars(select(CorrelationSetting)).all()
    return {r.category: r.floor_adjustment for r in rows}


def submit_feedback(db: Session, alert_id: UUID, label: str, analyst: str, note: Optional[str] = None) -> AnalystFeedback:
    """Record an analyst label for an alert (replacing the analyst's prior label).

    Returns the stored row. Raises ValueError on an unknown label.
    """
    normalized = label.upper()
    if normalized not in LABELS:
        raise ValueError(f"label must be one of {LABELS}")

    alert = db.get(Alert, alert_id)
    if alert is None:
        raise ValueError("alert not found")

    # Latest label wins per (alert, analyst) — delete then insert keeps the audit simple.
    db.execute(
        delete(AnalystFeedback).where(
            AnalystFeedback.alert_id == alert_id,
            AnalystFeedback.analyst == analyst,
        )
    )
    fb = AnalystFeedback(alert_id=alert_id, label=normalized, note=note, analyst=analyst)
    db.add(fb)
    db.add(
        ActionLog(
            actor=analyst,
            action="analyst_feedback",
            target_type="alert",
            target_id=str(alert.alert_id),
            detail={"label": normalized, "note": note or ""},
        )
    )
    db.commit()
    db.refresh(fb)
    return fb


def latest_labels(db: Session) -> Dict[str, str]:
    """alert_id (str) -> most recent label, for alerts that have feedback."""
    rows = db.execute(
        select(AnalystFeedback.alert_id, AnalystFeedback.label, AnalystFeedback.created_at)
        .order_by(AnalystFeedback.created_at.desc())
    ).all()
    latest: Dict[str, str] = {}
    for alert_id, label, _ in rows:
        key = str(alert_id)
        if key not in latest:
            latest[key] = label
    return latest


def feedback_stats(db: Session) -> Dict[str, Any]:
    """Correlation + feedback statistics: signals before correlation vs alerts,
    label distribution, observed precision and false-positive rate.
    """
    signals_before = (
        db.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.is_anomalous.is_(True))
        )
        or 0
    )
    alerts_after = db.scalar(select(func.count()).select_from(Alert)) or 0

    labels = latest_labels(db)
    counts: Dict[str, int] = {lbl: 0 for lbl in LABELS}
    for lbl in labels.values():
        if lbl in counts:
            counts[lbl] += 1

    decisive = counts["TRUE_POSITIVE"] + counts["FALSE_POSITIVE"]
    precision = round(counts["TRUE_POSITIVE"] / decisive, 4) if decisive else None
    fpr = round(counts["FALSE_POSITIVE"] / decisive, 4) if decisive else None

    # Per-category quality: which alert categories generate noise vs value.
    category_rows = db.execute(select(Alert.category, Alert.id)).all()
    by_category: Dict[str, Dict[str, Any]] = {}
    for cat, alert_id in category_rows:
        lbl = labels.get(str(alert_id))
        if lbl is None or lbl == "UNKNOWN":
            continue
        row = by_category.setdefault(
            cat or "GENERIC", {"total": 0, "true_positive": 0, "false_positive": 0, "benign": 0}
        )
        row["total"] += 1
        if lbl == "TRUE_POSITIVE":
            row["true_positive"] += 1
        elif lbl == "FALSE_POSITIVE":
            row["false_positive"] += 1
        elif lbl == "BENIGN":
            row["benign"] += 1

    applied_settings: List[Dict[str, Any]] = [
        {"category": r.category, "base_floor": r.base_floor,
         "floor_adjustment": r.floor_adjustment,
         "effective_floor": round(r.base_floor + r.floor_adjustment, 3),
         "applied_by": r.applied_by, "rationale": r.rationale}
        for r in db.scalars(select(CorrelationSetting).order_by(CorrelationSetting.category)).all()
    ]

    category_stats: List[Dict[str, Any]] = []
    for cat, row in sorted(by_category.items(), key=lambda kv: -kv[1]["total"]):
        decisive = row["true_positive"] + row["false_positive"]
        prec = round(row["true_positive"] / decisive, 4) if decisive else None
        fpr_c = round(row["false_positive"] / decisive, 4) if decisive else None
        suggestion = None
        if decisive >= 2 and fpr_c is not None and fpr_c > 0.5:
            suggestion = f"{cat} produces {row['false_positive']}/{decisive} false positives in analyst feedback — consider raising its correlation threshold or reviewing its detection rules."
        elif decisive >= 2 and prec is not None and prec >= 0.8:
            suggestion = f"{cat} feedback is largely true positives — no threshold change recommended."
        category_stats.append({
            "category": cat,
            **row,
            "precision": prec,
            "false_positive_rate": fpr_c,
            "suggestion": suggestion,
        })

    return {
        "signals_before_correlation": signals_before,
        "alerts_after_correlation": alerts_after,
        "correlation_ratio": round(alerts_after / signals_before, 4) if signals_before else None,
        "labeled_alerts": len(labels),
        "label_counts": counts,
        "false_positive_rate": fpr,          # FP / (TP + FP) — observed on labeled alerts
        "precision": precision,              # TP / (TP + FP)
        "category_stats": category_stats,    # per-category precision/FPR + plain-language suggestions
        "applied_settings": applied_settings,  # explicit, audited threshold adjustments
        "provenance": {
            "mode": "ANALYST FEEDBACK",
            "basis": "labels stored in analyst_feedback; signals = anomalous events before correlation",
        },
    }


def apply_suggestions(db: Session, analyst: str) -> Dict[str, Any]:
    """Retrain correlation with consent: apply per-category floor adjustments
    derived from analyst feedback, record before/after, and audit every change.

    Returns the applied changes; nothing is applied silently and nothing
    requires more than an explicit admin call.
    """
    stats = feedback_stats(db)
    changes: List[Dict[str, Any]] = []
    for row in stats["category_stats"]:
        if row["total"] < 2:
            continue
        fpr = row["false_positive_rate"]
        prec = row["precision"]
        if fpr is not None and fpr > FPR_NOISE:
            action, adj = "raise", RAISE_STEP
        elif prec is not None and prec >= PRECISION_CLEAN and (fpr or 0) <= 0.3:
            action, adj = "lower", -LOWER_STEP
        else:
            continue
        setting = db.get(CorrelationSetting, row["category"])
        before = setting.floor_adjustment if setting else 0.0
        if setting is None:
            setting = CorrelationSetting(
                category=row["category"], base_floor=BASE_DETECTION_FLOOR,
                floor_adjustment=adj, applied_by=analyst, rationale=row["suggestion"],
            )
            db.add(setting)
        else:
            setting.floor_adjustment = adj
            setting.applied_by = analyst
            setting.rationale = row["suggestion"]
        changes.append({
            "category": row["category"], "action": action,
            "old_adjustment": before, "new_adjustment": adj,
            "old_floor": round(BASE_DETECTION_FLOOR + before, 3),
            "new_floor": round(BASE_DETECTION_FLOOR + adj, 3),
            "rationale": row["suggestion"],
        })
    db.commit()
    for c in changes:
        db.add(ActionLog(actor=analyst, action="CORRELATION.RETRAINED",
                         target_type="category", target_id=c["category"], detail=c))
    db.commit()
    return {
        "applied": changes,
        "note": "Threshold adjustments apply to the Detection Agent's anomaly floor on the next evaluation. Every change is logged and audited.",
    }
