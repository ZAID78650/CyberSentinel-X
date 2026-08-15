"""Dataset management routes (UNSW-NB15 ingestion, uploads, status, reset)."""
import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.config import get_settings
from app.core.database import SessionLocal, get_db
from app.models.investigation import (
    AIAgentRun,
    ApprovalRequest,
    AttackEdge,
    AttackNode,
    IncidentReport,
    Investigation,
    InvestigationEvidence,
    ResponseRecommendation,
    RiskScore,
)
from app.models.intel import IncidentMitreMapping
from app.models.security import (
    Alert,
    Incident,
    IncidentEvent,
    Notification,
    SecurityEvent,
)
from app.models.user import User
from app.services.audit import log_action
from app.services.unsw import UNSW_STATE, start_ingestion

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dataset", tags=["dataset"])

# ---------------------------------------------------------------------------
# Uploaded dataset registry (analyst-provided CSVs)
# ---------------------------------------------------------------------------

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _uploads_dir() -> str:
    d = get_settings().dataset_upload_dir
    os.makedirs(d, exist_ok=True)
    return d


def _manifest_path() -> str:
    return os.path.join(_uploads_dir(), "manifest.json")


def _load_manifest() -> Dict[str, dict]:
    p = _manifest_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_manifest(manifest: Dict[str, dict]) -> None:
    with open(_manifest_path(), "w") as f:
        json.dump(manifest, f, indent=2)


def _csv_preview(path: str) -> dict:
    """Row count + column names for an uploaded CSV (cheap: header + first col)."""
    import pandas as pd

    header = pd.read_csv(path, nrows=0)
    cols = [str(c).strip() for c in header.columns]
    try:
        rows = int(pd.read_csv(path, usecols=[0]).shape[0])
    except Exception:
        rows = 0
    return {"rows": rows, "columns": cols}


# The bundled UNSW-NB15 sample ships inside the image (backend/data/samples)
# so the demo corpus survives ephemeral-disk redeploys.
BUNDLED_SAMPLE_SRC = os.path.join("data", "samples", "unsw_sample.csv")
BUNDLED_SAMPLE_NAME = "UNSW_NB15-training-set.csv"


def restore_bundled_sample() -> Dict[str, Any]:
    """Copy the bundled UNSW sample into the uploads dir + manifest on startup.

    The free-tier uploads dir is ephemeral — every redeploy wipes it, which
    previously forced a manual re-upload. This makes the demo corpus self-heal:
    if the sample is missing after a deploy, it is restored from the image and
    registered, so Data Sources and the Dataset Scanner always have data.
    """
    import shutil

    if get_settings().environment == "test":
        return {"restored": False, "reason": "test env"}
    upload_dir = _uploads_dir()
    dest = os.path.join(upload_dir, BUNDLED_SAMPLE_NAME)
    if os.path.exists(dest):
        return {"restored": False, "reason": "already present"}
    if not os.path.exists(BUNDLED_SAMPLE_SRC):
        logger.info("bundled sample not found at %s — skipping restore", BUNDLED_SAMPLE_SRC)
        return {"restored": False, "reason": "bundled sample not found"}
    try:
        shutil.copyfile(BUNDLED_SAMPLE_SRC, dest)
        preview = _csv_preview(dest)
    except Exception as exc:  # pragma: no cover
        logger.warning("bundled sample restore failed: %s", exc)
        return {"restored": False, "reason": str(exc)}
    manifest = _load_manifest()
    manifest[BUNDLED_SAMPLE_NAME] = {
        "name": BUNDLED_SAMPLE_NAME,
        "size_bytes": os.path.getsize(dest),
        "rows": preview["rows"],
        "columns": preview["columns"],
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": "system (bundled sample)",
    }
    _save_manifest(manifest)
    logger.info("restored bundled UNSW sample (%d rows)", preview["rows"])
    return {"restored": True, "rows": preview["rows"]}


def resolve_dataset_path(name: str) -> Optional[str]:
    """Resolve a dataset name to an absolute CSV path (uploads dir first,
    then the configured UNSW dataset directory)."""
    upload_dir = _uploads_dir()
    candidate = os.path.join(upload_dir, name)
    if os.path.exists(candidate):
        return candidate
    for f in _dataset_files():
        if os.path.basename(f) == name or f == name:
            return f
    if os.path.exists(name):
        return name
    return None


@router.post("/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    """Upload a CSV dataset into the platform's dataset registry."""
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are supported.")
    name = os.path.basename(file.filename)
    if not _SAFE_NAME.match(name):
        raise HTTPException(status_code=400, detail="Filename contains unsupported characters.")
    if name.lower().endswith("manifest.json"):
        raise HTTPException(status_code=400, detail="Invalid filename.")

    dest = os.path.join(_uploads_dir(), name)
    if os.path.exists(dest):
        raise HTTPException(status_code=409, detail=f"A dataset named '{name}' already exists.")

    size = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1 << 20):
            out.write(chunk)
            size += len(chunk)

    try:
        preview = _csv_preview(dest)
    except Exception as exc:
        os.remove(dest)
        raise HTTPException(status_code=400, detail=f"Not a readable CSV: {exc}") from exc

    manifest = _load_manifest()
    manifest[name] = {
        "name": name,
        "size_bytes": size,
        "rows": preview["rows"],
        "columns": preview["columns"],
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": user.email,
    }
    _save_manifest(manifest)

    log_action(db, actor=user.email, action="DATASET.UPLOAD", target_type="dataset",
               target_id=name, detail={"rows": preview["rows"], "size_bytes": size})
    return {"uploaded": True, "name": name, **manifest[name]}


@router.get("/uploads")
def list_uploads(_user: User = Depends(get_current_user)):
    """List all available datasets: uploaded CSVs + configured UNSW files."""
    manifest = _load_manifest()
    uploads = []
    for name, meta in manifest.items():
        path = os.path.join(_uploads_dir(), name)
        if not os.path.exists(path):
            continue
        uploads.append({
            "name": name, "source": "uploaded", "path": path,
            "size_bytes": meta.get("size_bytes", 0), "rows": meta.get("rows", 0),
            "columns": meta.get("columns", []),
            "uploaded_at": meta.get("uploaded_at"),
        })
    for f in _dataset_files():
        uploads.append({
            "name": os.path.basename(f), "source": "unsw", "path": f,
            "size_bytes": os.path.getsize(f) if os.path.exists(f) else 0,
            "rows": 0, "columns": [], "uploaded_at": None,
        })
    uploads.sort(key=lambda u: (u["source"] != "uploaded", u["name"]))
    return {"datasets": uploads}


@router.post("/uploads/{name}/ingest")
async def ingest_upload(
    name: str,
    limit: Optional[int] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    """Ingest an uploaded CSV through the same detection pipeline as UNSW-NB15."""
    manifest = _load_manifest()
    if name not in manifest:
        raise HTTPException(status_code=404, detail="Dataset not found in uploads.")
    path = os.path.join(_uploads_dir(), name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Dataset file missing on disk.")
    if UNSW_STATE["running"]:
        raise HTTPException(status_code=409, detail="An ingestion job is already running.")

    effective_limit = limit if limit is not None else get_settings().unsw_ingest_limit
    # Append to the corpus — uploading + ingesting a file must never wipe the
    # main UNSW-NB15 feed.
    if not start_ingestion([path], limit=effective_limit, clear_existing=False):
        raise HTTPException(status_code=409, detail="An ingestion job is already running.")

    log_action(db, actor=user.email, action="DATASET.INGEST_UPLOAD", target_type="dataset",
               target_id=name, detail={"limit": effective_limit})
    return {
        "started": True,
        "message": f"Ingestion of '{name}' started (appends to the existing corpus). Poll /api/dataset/status for progress.",
        "name": name,
        "limit": effective_limit,
    }


@router.delete("/uploads/{name}")
async def delete_upload(
    name: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    """Delete an uploaded dataset (files from the configured UNSW dir are read-only)."""
    if not _SAFE_NAME.match(name):
        raise HTTPException(status_code=400, detail="Invalid filename.")
    manifest = _load_manifest()
    if name not in manifest:
        raise HTTPException(status_code=404, detail="Dataset not found in uploads.")
    path = os.path.join(_uploads_dir(), name)
    if os.path.exists(path):
        os.remove(path)
    manifest.pop(name, None)
    _save_manifest(manifest)
    log_action(db, actor=user.email, action="DATASET.DELETE_UPLOAD", target_type="dataset",
               target_id=name, detail={})
    return {"deleted": True, "name": name}


INCIDENT_RELATED = [
    IncidentMitreMapping, RiskScore, ResponseRecommendation, ApprovalRequest,
    AttackNode, AttackEdge, InvestigationEvidence, IncidentReport,
]
INCIDENT_CHILD = [IncidentEvent, AIAgentRun]


def _dataset_files() -> list[str]:
    return get_settings().unsw_dataset_paths


@router.get("/status")
def dataset_status(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    settings = get_settings()
    files = _dataset_files()
    rows_total = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    attacks = db.scalar(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.is_anomalous.is_(True))
    ) or 0
    unsw_events = db.scalar(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.source == "unsw-bulk")
    ) or 0
    by_category = {
        r[0]: r[1]
        for r in db.execute(
            select(SecurityEvent.event_type, func.count())
            .where(SecurityEvent.is_anomalous.is_(True))
            .group_by(SecurityEvent.event_type)
        ).all()
    }
    by_severity = {
        r[0]: r[1]
        for r in db.execute(
            select(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity)
        ).all()
    }
    alerts = db.scalar(select(func.count()).select_from(Alert)) or 0
    incidents = db.scalar(select(func.count()).select_from(Incident)) or 0

    return {
        "configured": bool(settings.unsw_dataset_dir),
        "dataset_dir": settings.unsw_dataset_dir,
        "files": [
            {"name": os.path.basename(f), "path": f, "exists": os.path.exists(f)} for f in files
        ],
        "ingest_limit": settings.unsw_ingest_limit,
        "stats": {
            "events_total": rows_total,
            "unsw_events": unsw_events,
            "attack_flows": attacks,
            "normal_flows": rows_total - attacks,
            "alerts": alerts,
            "incidents": incidents,
            "by_category": by_category,
            "by_severity": by_severity,
        },
        "progress": {
            "running": UNSW_STATE["running"],
            "total_rows": UNSW_STATE["total_rows"],
            "processed_rows": UNSW_STATE["processed_rows"],
            "inserted_rows": UNSW_STATE["inserted_rows"],
            "attack_flows": UNSW_STATE["attack_flows"],
            "alerts_created": UNSW_STATE["alerts_created"],
            "incidents_created": UNSW_STATE["incidents_created"],
            "started_at": UNSW_STATE["started_at"],
            "finished_at": UNSW_STATE["finished_at"],
            "last_error": UNSW_STATE["last_error"],
        },
    }


@router.post("/unsw/ingest")
async def ingest_unsw(
    limit: Optional[int] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    settings = get_settings()
    files = _dataset_files()
    if not files:
        raise HTTPException(
            status_code=400,
            detail=(
                "No UNSW-NB15 CSVs found. Set UNSW_DATASET_DIR in backend/.env to the "
                "folder containing UNSW_NB15_training-set.csv / testing-set.csv."
            ),
        )
    if UNSW_STATE["running"]:
        raise HTTPException(status_code=409, detail="An ingestion job is already running.")

    effective_limit = limit if limit is not None else settings.unsw_ingest_limit
    started = start_ingestion(files, limit=effective_limit)
    if not started:
        raise HTTPException(status_code=409, detail="An ingestion job is already running.")

    log_action(db, actor=user.email, action="DATASET.INGEST", target_type="dataset",
               target_id="unsw-nb15", detail={"files": [os.path.basename(f) for f in files],
                                              "limit": effective_limit})
    return {
        "started": True,
        "message": "UNSW-NB15 ingestion started in the background. Poll /api/dataset/status for progress.",
        "files": [os.path.basename(f) for f in files],
        "limit": effective_limit,
    }


@router.post("/clear")
async def clear_all_data(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("ADMIN")),
):
    """Remove ALL events, alerts, incidents and pipeline artifacts (keeps reference data)."""
    if UNSW_STATE["running"]:
        raise HTTPException(status_code=409, detail="Ingestion is running — wait for it to finish.")

    incident_ids = list(db.scalars(select(Incident.id)).all())
    for model in INCIDENT_RELATED:
        db.execute(delete(model))
    for model in INCIDENT_CHILD:
        db.execute(delete(model))
    db.execute(delete(Investigation))
    db.execute(delete(Incident))
    db.execute(delete(Alert))
    db.execute(delete(SecurityEvent))
    db.execute(delete(Notification))
    db.execute(delete(AIAgentRun))
    db.commit()

    log_action(db, actor=user.email, action="DATASET.CLEAR", target_type="dataset",
               target_id="all", detail={"incidents": len(incident_ids)})
    return {
        "cleared": True,
        "message": "All events, alerts, incidents and pipeline artifacts removed. Reference data (users, assets, MITRE, intel, knowledge) kept.",
        "events_removed": True,
        "incidents_removed": len(incident_ids),
    }


# ---------------------------------------------------------------------------
# Automatic detection loop: correlates freshly-ingested anomalous events into
# alerts/incidents without any manual trigger.
# ---------------------------------------------------------------------------

_processed_ids: set[str] = set()
_pipelined_incident_ids: set[str] = set()
_AUTO_LOOP_INTERVAL = 20  # seconds


async def auto_detection_loop() -> None:
    """Periodically run the Detection Agent over new anomalous events."""
    global _processed_ids
    logger.info("auto-detection loop started (every %ss)", _AUTO_LOOP_INTERVAL)
    while True:
        try:
            await asyncio.sleep(_AUTO_LOOP_INTERVAL)
            await _run_auto_detection_pass()
        except asyncio.CancelledError:
            logger.info("auto-detection loop stopped")
            return
        except Exception as exc:  # pragma: no cover
            logger.error("auto-detection pass failed: %s", exc)


async def _run_auto_detection_pass() -> None:
    global _processed_ids, _pipelined_incident_ids
    from app.agents.detection_agent import DetectionAgent
    from app.agents.orchestrator import Orchestrator
    from app.core.websocket_manager import ws_manager

    db = None
    try:
        db = SessionLocal()
        from app.models.security import Incident, SecurityEvent
        from sqlalchemy import exists, select

        # Deep-dive already-correlated incidents that never completed a
        # pipeline (e.g. UNSW-NB15 campaigns): run investigation -> risk ->
        # response -> report automatically, one incident per pass. An
        # incident counts as "pending" until it has response recommendations,
        # so partially-failed runs self-heal on the next pass.
        pending = list(db.scalars(
            select(Incident)
            .where(
                Incident.created_by == "unsw-detection-agent",
                Incident.status.in_(["OPEN", "INVESTIGATING"]),
                ~exists().where(ResponseRecommendation.incident_id == Incident.id),
            )
            .order_by(Incident.severity.desc(), Incident.created_at.desc())
            .limit(1)
        ).all())
        for inc in pending:
            inc_id = str(inc.id)
            if inc_id in _pipelined_incident_ids:
                continue
            _pipelined_incident_ids.add(inc_id)
            asyncio.create_task(Orchestrator().run_pipeline(inc_id))
            await ws_manager.broadcast("incident_updated", {
                "incident_id": inc_id, "reason": "auto-pipeline-started",
            })
            logger.info("auto-detection: launched full pipeline for incident %s (%s)",
                        inc.incident_id, inc.title[:60])
        if len(_pipelined_incident_ids) > 500:
            _pipelined_incident_ids = set(list(_pipelined_incident_ids)[-400:])

        # Events from live ingestion only — simulator + bulk-UNSW flows are
        # correlated by their own pipeline.
        candidates = list(db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.is_anomalous.is_(True),
                SecurityEvent.source.notin_(["simulator", "unsw-bulk"]),
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(400)
        ).all())
        fresh = [e for e in candidates if e.event_id not in _processed_ids]
        if not fresh:
            return

        # Avoid correlating events that already belong to an open alert.
        existing_ids: set[str] = set()
        recent_alerts = list(db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(50)).all())
        for a in recent_alerts:
            existing_ids.update(a.source_event_ids or [])
        fresh = [e for e in fresh if e.event_id not in existing_ids]
        if not fresh:
            return

        _processed_ids.update(e.event_id for e in fresh)

        detection = DetectionAgent(db)
        result = detection.evaluate_batch(fresh, actor="auto-detection-agent")
        if len(_processed_ids) > 20000:
            _processed_ids = set(list(_processed_ids)[-15000:])

        if result.get("incident"):
            await ws_manager.broadcast("new_alert", {
                "alert_id": result["alert_id"], "severity": result["severity"],
                "title": "Automatic detection: " + (result.get("summary") or "incident opened"),
                "confidence": result["confidence"],
            })
            await ws_manager.broadcast("new_incident", {
                "incident_id": result["incident_id"], "severity": result["severity"],
            })
            asyncio.create_task(Orchestrator().run_pipeline(result["incident"]))
            logger.info("auto-detection: correlated %d events -> incident %s",
                        result["suspicious_count"], result["incident_id"])
    except Exception as exc:  # pragma: no cover
        logger.error("auto-detection pass failed: %s", exc)
    finally:
        if db is not None:
            db.close()
