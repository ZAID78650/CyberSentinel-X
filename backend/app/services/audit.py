"""Audit logging helper — records every meaningful action to action_logs."""
import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.investigation import ActionLog

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    actor: str,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None,
) -> ActionLog:
    """Persist an audit record. Never includes secrets in `detail`."""
    record = ActionLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id else None,
        detail=detail,
        ip_address=ip_address,
        request_id=request_id,
    )
    db.add(record)
    db.commit()
    logger.info("audit actor=%s action=%s target=%s/%s", actor, action, target_type, target_id)
    return record
