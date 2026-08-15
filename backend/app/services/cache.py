"""Small process-local TTL cache for expensive aggregates.

The heavy reads (campaign computation, judge-mode aggregate) are recomputed
per request today; on a 175k+ event corpus that is tens of N+1 queries per
page load. Caching them for a few seconds keeps the demo responsive without
adding Redis. The cache is disabled in the test environment so tests always
observe fresh writes.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, Tuple

from app.core.config import get_settings

_lock = threading.Lock()
_store: Dict[str, Tuple[float, Any]] = {}


def get_or_build(key: str, ttl: float, builder: Callable[[], Any]) -> Any:
    """Return a cached value or build + store it (TTL in seconds)."""
    if get_settings().environment == "test":
        return builder()
    now = time.monotonic()
    with _lock:
        hit = _store.get(key)
        if hit is not None and hit[0] > now:
            return hit[1]
    value = builder()
    with _lock:
        _store[key] = (time.monotonic() + ttl, value)
    return value


def clear() -> None:
    with _lock:
        _store.clear()
