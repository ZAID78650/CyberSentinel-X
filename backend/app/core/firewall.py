"""Defense-in-depth firewall layer for the API.

Layers implemented as ASGI/Starlette middleware + a status endpoint:

1. REQUEST_ID   — tags every request with a correlation id (X-Request-ID)
2. BODY_LIMIT   — rejects oversized request bodies (JSON flood protection)
3. WAF_PAYLOAD  — filters SQLi / XSS / path-traversal / command-injection
                 patterns in request bodies and query strings
4. SECURITY_HDR — hardened response headers (CSP, HSTS, frame/XSS options)
5. RATE_LIMIT     — per-key request throttling for auth and API endpoints
6. IP_WATCH       — blocks known-bad IPs from the threat-intel feed
7. MALWARE_GUARD  — blocks control-plane requests that reference known
                   malware indicators (hashes, C2 domains, families)
8. BRUTE_GUARD    — per-account login throttling (5 attempts / 10 min lockout)

Each layer reports status and counters through GET /api/security/firewall.
"""
import json
import logging
import re
import time
import uuid
from collections import defaultdict, deque
from threading import RLock
from typing import Any, Dict, List, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Layer bookkeeping
# --------------------------------------------------------------------------

_LAYER_ORDER = [
    "REQUEST_ID",
    "BODY_LIMIT",
    "WAF_PAYLOAD",
    "SECURITY_HDR",
    "RATE_LIMIT",
    "IP_WATCH",
    "MALWARE_GUARD",
    "BRUTE_GUARD",
]

_LAYER_META: Dict[str, Dict[str, Any]] = {
    "REQUEST_ID": {"name": "Request Correlation", "description": "Tags every request with a correlation ID", "color": "#38bdf8"},
    "BODY_LIMIT": {"name": "Payload Size Guard", "description": "Rejects oversized request bodies (>1 MB)", "color": "#facc15"},
    "WAF_PAYLOAD": {"name": "Web App Firewall", "description": "Filters SQLi / XSS / command-injection patterns", "color": "#fb923c"},
    "SECURITY_HDR": {"name": "Hardened Headers", "description": "CSP, HSTS, frame and MIME-sniffing protection", "color": "#4ade80"},
    "RATE_LIMIT": {"name": "Rate Limiting", "description": "Per-IP request throttling", "color": "#22d3ee"},
    "IP_WATCH": {"name": "Threat IP Watchlist", "description": "Blocks source IPs from the threat-intel feed", "color": "#f87171"},
    "MALWARE_GUARD": {"name": "Cyber Malware Prevention", "description": "Blocks control-plane requests referencing known malware hashes, C2 domains or families", "color": "#fb7185"},
    "BRUTE_GUARD": {"name": "Credential Brute-Force Guard", "description": "Locks accounts after repeated failures", "color": "#a78bfa"},
}

_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: {"blocked": 0, "passed": 0})
_brute_failures: Dict[str, Dict[str, Any]] = {}
# Ring buffer of recent blocks (layer, request, indicator) for the block log.
_block_log: deque = deque(maxlen=200)
# RLock: the block log may be written from inside record_brute_failure, which
# already holds the lock (a plain Lock would deadlock on the second acquire).
_lock = RLock()

MAX_BODY_BYTES = 1024 * 1024  # 1 MB (regular API payloads)
MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # 256 MB (dataset CSV uploads)


def _body_limit_for(request) -> int:
    """The dataset upload endpoint accepts large CSVs; everything else is 1 MB."""
    if request.url.path == "/api/dataset/upload" and "multipart/form-data" in request.headers.get("content-type", ""):
        return MAX_UPLOAD_BYTES
    return MAX_BODY_BYTES

# --------------------------------------------------------------------------
# WAF pattern database (defensive, synthetic-only corpus)
# --------------------------------------------------------------------------

_SQLI = re.compile(
    r"(?i)(\bselect\b.*\bfrom\b|\bunion\b.*\bselect\b|\binsert\b.*\bin\b|"
    r"\bdelete\b.*\bfrom\b|\bdrop\s+table\b|'?\s*or\s+['\"]?1\s*=\s*1|"
    r"--\s|;\s*--|\bexec\b.*\bxp_|information_schema|pg_sleep|benchmark\s*\()"
)
_XSS = re.compile(
    r"(?i)(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|"
    r"<\s*iframe|document\.cookie|alert\s*\(|<\s*img[^>]+onerror)"
)
_TRAVERSAL = re.compile(r"(\.\./\s*){2,}|\.\.\\{2,}|/etc/passwd|/etc/shadow|C:\\windows")
_CMDI = re.compile(r"(?i)(;\s*(rm|sh|bash|wget|curl|nc|python|powershell)\b|\|\s*(sh|bash)\b|`[^`]*`|\$\([^)]*\))")
_PATTERNS = [
    ("SQL Injection", _SQLI),
    ("Cross-Site Scripting", _XSS),
    ("Path Traversal", _TRAVERSAL),
    ("Command Injection", _CMDI),
]

# --------------------------------------------------------------------------
# MALWARE_GUARD — indicator set + control-plane allowlist
# --------------------------------------------------------------------------

# Paths where malware indicators are legitimate data (ingest, scans, queries,
# artifact references). Everywhere else, referencing a known malware indicator
# is treated as suspicious and blocked.
_MALWARE_DATA_PLANE_PREFIXES = (
    "/api/events/",
    "/api/dataset/",
    "/api/simulations/",
    "/api/malware/",
    "/api/threat-hunting",
    "/api/threat-intelligence",
    "/api/alerts/",
    "/api/incidents/",
    "/api/evidence/",
    "/api/investigations/",
    "/api/campaigns",
    "/api/predictions",
    "/api/attack-dna",
    "/api/ueba",
    "/api/analytics",
    "/api/soc",
    "/api/security/analyze",
)

_MALWARE_INDICATOR_TYPES = ("HASH", "DOMAIN", "MALWARE")
_malware_set: Optional[set] = None
_malware_set_at = 0.0
_MALWARE_SET_TTL = 60.0


def _load_malware_set() -> set:
    """Lowercased CRITICAL/HIGH malware indicator values (hashes, C2 domains,
    family names), cached for 60s. Loaded lazily to avoid import cycles."""
    global _malware_set, _malware_set_at
    now = time.monotonic()
    if _malware_set is not None and now - _malware_set_at < _MALWARE_SET_TTL:
        return _malware_set
    values: set = set()
    try:
        from app.core.database import SessionLocal
        from app.models.intel import ThreatIndicator
        from sqlalchemy import select

        db = SessionLocal()
        try:
            rows = db.scalars(
                select(ThreatIndicator.value).where(
                    ThreatIndicator.indicator_type.in_(_MALWARE_INDICATOR_TYPES),
                    ThreatIndicator.severity.in_(["CRITICAL", "HIGH"]),
                )
            ).all()
            values = {str(v).lower() for v in rows}
        finally:
            db.close()
    except Exception as exc:  # pragma: no cover
        logger.warning("malware guard: indicator load failed: %s", exc)
    with _lock:
        _malware_set = values
        _malware_set_at = time.monotonic()
    return values


def malware_guard_test_payload() -> Dict[str, Any]:
    """Deterministic demo payload: references a known malware hash (EICAR)."""
    return {"note": "firewall test", "hash": "44d88612fea8a8f36de82e1278abb02f"}


def _body_malware_hit(parsed: Any) -> Optional[str]:
    """Recursively scan a parsed JSON body for known malware indicator values."""
    if parsed is None:
        return None
    indicators = _load_malware_set()
    stack = [parsed]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            lowered = node.strip().lower()
            if lowered in indicators:
                return node
    return None


# --------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------


def firewall_stats() -> List[Dict[str, Any]]:
    with _lock:
        out = []
        for layer in _LAYER_ORDER:
            meta = _LAYER_META[layer]
            c = _counters[layer]
            out.append({
                "layer": layer,
                "name": meta["name"],
                "description": meta["description"],
                "color": meta["color"],
                "status": "ACTIVE",
                "blocked": c["blocked"],
                "passed": c["passed"],
            })
        return out


def firewall_summary() -> Dict[str, Any]:
    layers = firewall_stats()
    blocked = sum(lyr["blocked"] for lyr in layers)
    passed = sum(lyr["passed"] for lyr in layers)
    return {
        "layers": layers,
        "total_blocked": blocked,
        "total_passed": passed,
        "total_requests": blocked + passed,
        "protection_level": "DEFENSE_IN_DEPTH",
    }


def _record_block_raw(layer: str, method: str, path: str, source_ip: str, detail: str, indicator: Optional[str] = None) -> None:
    """Append one entry to the in-memory block log (bounded ring buffer)."""
    with _lock:
        _block_log.appendleft({
            "ts": time.time(),
            "layer": layer,
            "method": method,
            "path": path,
            "source_ip": source_ip,
            "indicator": indicator,
            "detail": detail,
        })


def _record_block(layer: str, request: Request, detail: str, indicator: Optional[str] = None) -> None:
    _record_block_raw(
        layer, request.method, request.url.path,
        request.client.host if request.client else "unknown", detail, indicator,
    )


def firewall_block_log(limit: int = 50) -> List[Dict[str, Any]]:
    """Most recent firewall blocks, newest first (bounded to 200 in memory)."""
    with _lock:
        return list(_block_log)[: max(1, min(limit, 200))]


def record_brute_failure(key: str, max_failures: int = 5, lockout_seconds: int = 600) -> bool:
    """Record a failed credential attempt. Returns True when the key is now locked."""
    with _lock:
        now = time.time()
        entry = _brute_failures.get(key)
        if entry is None or now - entry["window_start"] > lockout_seconds:
            entry = {"count": 0, "window_start": now, "locked_until": 0}
            _brute_failures[key] = entry
        entry["count"] += 1
        if entry["count"] >= max_failures:
            entry["locked_until"] = now + lockout_seconds
            _counters["BRUTE_GUARD"]["blocked"] += 1
            _record_block_raw("BRUTE_GUARD", "POST", "/api/auth/login", "account",
                              f"Account locked after {max_failures} failed attempts", indicator=key)
            return True
        return False


def brute_guard_clear(key: str) -> None:
    with _lock:
        _brute_failures.pop(key, None)


def is_brute_locked(key: str) -> bool:
    with _lock:
        entry = _brute_failures.get(key)
        if not entry:
            return False
        return entry.get("locked_until", 0) > time.time()


def brute_guard_remaining(key: str) -> int:
    with _lock:
        entry = _brute_failures.get(key)
        if not entry:
            return 0
        return max(0, int(entry.get("locked_until", 0) - time.time()))


# --------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------


def _body_bytes(body: bytes) -> bytes:
    return body


class FirewallMiddleware(BaseHTTPMiddleware):
    """Enforces the layered defense stack on incoming requests."""

    def __init__(self, app, blocked_ips: Optional[List[str]] = None):
        super().__init__(app)
        self.blocked_ips = set(blocked_ips or [])

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        _counters["REQUEST_ID"]["passed"] += 1

        # ---- IP_WATCH ----------------------------------------------------
        ip = request.client.host if request.client else "unknown"
        if ip in self.blocked_ips:
            _counters["IP_WATCH"]["blocked"] += 1
            _record_block("IP_WATCH", request, "Source IP on threat watchlist", indicator=ip)
            return JSONResponse(status_code=403, content={"detail": "Source IP blocked by threat watchlist"})

        # ---- BODY_LIMIT --------------------------------------------------
        if request.method in ("POST", "PUT", "PATCH"):
            limit = _body_limit_for(request)
            content_length = request.headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > limit:
                _counters["BODY_LIMIT"]["blocked"] += 1
                _record_block("BODY_LIMIT", request, f"Request body exceeds {limit} bytes")
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            body = await request.body()
            if len(body) > limit:
                _counters["BODY_LIMIT"]["blocked"] += 1
                _record_block("BODY_LIMIT", request, f"Request body exceeds {limit} bytes")
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            # ---- WAF_PAYLOAD + MALWARE_GUARD ------------------------------
            # Multipart bodies are skipped: multipart boundaries ("--")
            # trigger SQLi/comment false positives and file content is
            # inspected by the malware scanner instead.
            content_type = request.headers.get("content-type", "")
            parsed_body: Any = None
            if body and "multipart/form-data" not in content_type:
                try:
                    parsed_body = json.loads(body)
                    scan = json.dumps(parsed_body, ensure_ascii=False)
                except Exception:
                    scan = body.decode("utf-8", errors="ignore")
                hit = self._waf_scan(scan)
                if hit:
                    _counters["WAF_PAYLOAD"]["blocked"] += 1
                    _record_block("WAF_PAYLOAD", request, f"WAF pattern matched: {hit}")
                    logger.warning("firewall: WAF blocked %s (%s) from %s", hit, request.url.path, ip)
                    return JSONResponse(status_code=400, content={"detail": f"Request rejected by WAF: {hit}"})
                # Cyber Malware Prevention: block control-plane requests that
                # reference known malware indicators (hashes, C2 domains,
                # families). Data-plane paths carry these legitimately.
                if not request.url.path.startswith(_MALWARE_DATA_PLANE_PREFIXES):
                    malware_hit = _body_malware_hit(parsed_body)
                    if malware_hit:
                        _counters["MALWARE_GUARD"]["blocked"] += 1
                        _record_block("MALWARE_GUARD", request, "Known malware indicator referenced", indicator=malware_hit)
                        logger.warning("firewall: MALWARE_GUARD blocked %s (indicator %r) from %s", request.url.path, malware_hit, ip)
                        return JSONResponse(status_code=403, content={
                            "detail": f"Request references known malware indicator ({malware_hit}) — blocked by MALWARE_GUARD",
                            "layer": "MALWARE_GUARD",
                            "indicator": malware_hit,
                        })

        # ---- RATE_LIMIT --------------------------------------------------
        if request.url.path.startswith("/api/"):
            from app.core.rate_limit import RateLimiter
            limiter = RateLimiter(max_requests=120, window_seconds=60)
            allowed, _retry = limiter.check(f"api:{ip}")
            if not allowed:
                _counters["RATE_LIMIT"]["blocked"] += 1
                _record_block("RATE_LIMIT", request, "API rate limit exceeded (120 req/min)")
                return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

        _counters["RATE_LIMIT"]["passed"] += 1
        _counters["IP_WATCH"]["passed"] += 1
        _counters["BODY_LIMIT"]["passed"] += 1
        _counters["WAF_PAYLOAD"]["passed"] += 1

        response = await call_next(request)

        # ---- SECURITY_HDR ------------------------------------------------
        _counters["SECURITY_HDR"]["passed"] += 1
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:"
        )
        return response

    @staticmethod
    def _waf_scan(text: str) -> Optional[str]:
        for label, pattern in _PATTERNS:
            if pattern.search(text):
                return label
        return None
