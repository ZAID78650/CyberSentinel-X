"""In-memory sliding-window rate limiter.

A lightweight per-key limiter used to protect authentication endpoints.
A Redis-backed limiter can be swapped in for multi-instance deployments.
"""
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple


class RateLimiter:
    def __init__(self, max_requests: int = 20, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> Tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry = int(self.window_seconds - (now - bucket[0])) + 1
                return False, max(retry, 1)
            bucket.append(now)
            return True, 0
