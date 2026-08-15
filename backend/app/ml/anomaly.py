"""Hybrid anomaly detection: Isolation Forest over engineered features.

The detector is fitted on the stored event corpus and scores individual
events. It is deliberately small and deterministic so tests are stable.
"""
import logging
import threading
from collections import Counter
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SENSITIVE_TYPES = {
    "DATA_EXFILTRATION",
    "MALWARE_DETECTED",
    "PRIVILEGE_ESCALATION",
    "DATABASE_ACCESS",
    "DATA_DOWNLOAD",
}


class AnomalyDetector:
    """Lazy-fitted IsolationForest anomaly scorer."""

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, random_state: int = 42) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._model: Optional[IsolationForest] = None
        self._type_freq: Counter = Counter()
        self._ip_freq: Counter = Counter()
        self._user_freq: Counter = Counter()
        self._user_fail_ratio: Dict[str, float] = {}
        self._n_fit = 0
        self._lock = threading.Lock()

    # --- feature engineering -------------------------------------------
    def _features(self, event: Dict[str, Any]) -> np.ndarray:
        etype = event.get("event_type", "UNKNOWN")
        severity = event.get("severity", "LOW")
        src_ip = event.get("source_ip") or "unknown"
        user = event.get("user_id") or "anonymous"

        total = max(self._n_fit, 1)
        type_freq = self._type_freq.get(etype, 0) / total
        ip_freq = self._ip_freq.get(src_ip, 0) / total
        user_freq = self._user_freq.get(user, 0) / total

        ts = event.get("timestamp")
        hour = 0.0
        dow = 0.0
        if ts is not None:
            try:
                hour = ts.hour / 24.0
                dow = ts.weekday() / 7.0
            except (AttributeError, ValueError):
                pass

        return np.array(
            [
                hour,
                dow,
                (SEVERITY_RANK.get(severity, 2) - 1) / 3.0,      # 0..1
                1.0 - type_freq,                                  # rare type -> high
                1.0 - ip_freq,                                    # rare IP -> high
                1.0 - user_freq,                                  # rare user -> high
                self._user_fail_ratio.get(user, 0.0),             # failure ratio
                1.0 if etype in SENSITIVE_TYPES else 0.0,         # sensitive activity
            ],
            dtype=float,
        )

    def fit(self, events: List[Dict[str, Any]]) -> None:
        if len(events) < 12:
            logger.info("anomaly detector: skipping fit with %d events", len(events))
            return
        with self._lock:
            self._type_freq = Counter(e.get("event_type", "UNKNOWN") for e in events)
            self._ip_freq = Counter(e.get("source_ip") or "unknown" for e in events)
            self._user_freq = Counter(e.get("user_id") or "anonymous" for e in events)
            per_user: Dict[str, List[bool]] = {}
            for e in events:
                user = e.get("user_id") or "anonymous"
                per_user.setdefault(user, []).append(e.get("event_type") == "LOGIN_FAILURE")
            self._user_fail_ratio = {u: (sum(v) / len(v)) for u, v in per_user.items()}
            self._n_fit = len(events)

            X = np.array([self._features(e) for e in events])
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
            ).fit(X)
            logger.info("anomaly detector fitted on %d events", len(events))

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    def score(self, event: Dict[str, Any]) -> float:
        """Return a 0..1 anomaly score for a single event.

        Uses the ML model when fitted; otherwise falls back to a pure
        rule-based score so detection works with an empty corpus.
        """
        features = self._features(event).reshape(1, -1)
        ml_score = 0.5
        if self._model is not None:
            try:
                raw = self._model.score_samples(features)[0]
                ml_score = float(1.0 / (1.0 + np.exp(-raw)))  # sigmoid → 0..1
            except Exception as exc:  # pragma: no cover
                logger.warning("anomaly scoring failed: %s", exc)

        rule_score = self._rule_score(event)
        return round(0.5 * ml_score + 0.5 * rule_score, 4)

    def _rule_score(self, event: Dict[str, Any]) -> float:
        etype = event.get("event_type", "")
        severity = SEVERITY_RANK.get(event.get("severity", "LOW"), 2)
        score = severity / 8.0  # base from severity
        if etype in ("DATA_EXFILTRATION", "MALWARE_DETECTED"):
            score += 0.25
        elif etype in ("PRIVILEGE_ESCALATION", "BRUTE_FORCE"):
            score += 0.2
        elif etype == "UNUSUAL_LOCATION":
            score += 0.15
        elif etype == "NEW_DEVICE":
            score += 0.1
        elif etype == "LOGIN_FAILURE":
            score += 0.08
        return float(min(score, 1.0))
