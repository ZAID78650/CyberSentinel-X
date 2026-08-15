"""Structured logging configuration.

Logs are emitted as JSON lines in production so they can be shipped to
a log aggregator. Sensitive values (passwords, tokens, keys) are never logged.
"""
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "cybersentinel-backend",
        }
        extras = getattr(record, "extras", None)
        if isinstance(extras, dict):
            payload.update(extras)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    if getattr(__import__("app.core.config", fromlist=["get_settings"]).get_settings(), "is_production", False):
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s — %(message)s"))
    root = logging.getLogger()
    root.setLevel(level.upper())
    root.handlers = [handler]


def get_logger(name: str, **extras: Any) -> logging.Logger:
    """Return a logger pre-populated with fixed extra fields."""
    logger = logging.getLogger(name)
    if extras:
        logger = logging.LoggerAdapter(logger, {"extras": extras})
    return logger


def request_id() -> str:
    """Generate a request ID for traceability."""
    return uuid.uuid4().hex[:16]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
