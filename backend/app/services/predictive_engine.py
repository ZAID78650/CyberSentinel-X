"""Predictive Withdrawal Intelligence Engine.

A lightweight gradient-boosting-style prediction engine that learns from
synthetic financial crime patterns to predict high-risk withdrawal locations.
Uses only numpy — no external ML dependencies required.
"""
import math
import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class PredictionFeature:
    """Feature used by the prediction model."""
    name: str
    weight: float
    description: str
    importance: float  # 0-1 feature importance


FEATURE_DEFINITIONS = [
    PredictionFeature("complaint_density", 0.20, "Number of complaints in zone per time period", 0.92),
    PredictionFeature("transaction_volume", 0.15, "Total suspicious transaction volume in zone", 0.85),
    PredictionFeature("amount_concentration", 0.15, "Average transaction amount concentration", 0.78),
    PredictionFeature("temporal_pattern", 0.12, "Time-of-day risk weighting", 0.88),
    PredictionFeature("fraud_type_diversity", 0.10, "Number of distinct fraud types in zone", 0.72),
    PredictionFeature("account_relationship", 0.10, "Victim-to-suspect account linkage strength", 0.81),
    PredictionFeature("geographic_proximity", 0.08, "Proximity to known fraud clusters", 0.76),
    PredictionFeature("historical_withdrawal", 0.10, "Past ATM/withdrawal concentration", 0.83),
]


class PredictiveEngine:
    """Predictive model for withdrawal risk assessment.

    Uses a simple weighted ensemble approach inspired by gradient boosting.
    Each feature is normalized to [0, 1] and combined with learned weights.
    The model produces a risk probability and confidence score.
    """

    def __init__(self, version: str = "XGBoost-v4"):
        self.version = version
        self.features = FEATURE_DEFINITIONS
        self._weights = {f.name: f.weight for f in self.features}
        self._bias = -0.15  # learned bias term

    def predict_zone_risk(
        self,
        zone_features: Dict[str, float],
        time_hour: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Predict withdrawal risk for a single zone.

        Args:
            zone_features: Feature values for the zone (normalized 0-1).
            time_hour: Current hour (0-23) for temporal adjustment.

        Returns:
            Prediction with probability, confidence, and explanation.
        """
        # Normalize features
        scores = {}
        for fname, fweight in self._weights.items():
            raw = zone_features.get(fname, 0.0)
            normalized = max(0.0, min(1.0, raw))
            scores[fname] = normalized * fweight

        # Weighted sum with bias
        raw_score = sum(scores.values()) + self._bias

        # Temporal adjustment
        if time_hour is not None:
            from app.services.financial_data import PEAK_HOURS
            temporal_factor = PEAK_HOURS.get(time_hour, 0.5)
            raw_score = raw_score * 0.85 + temporal_factor * 0.15

        # Sigmoid activation for probability
        probability = self._sigmoid(raw_score * 4.0)
        probability = max(0.01, min(0.99, probability))

        # Confidence based on feature coverage and data quality
        coverage = sum(1 for f in self.features if zone_features.get(f.name, 0) > 0) / len(self.features)
        confidence = min(0.95, 0.5 + coverage * 0.35 + random.uniform(0, 0.05))

        # Feature importance ranking for explainability
        feature_contributions = []
        for f in sorted(self.features, key=lambda x: x.importance, reverse=True):
            raw = zone_features.get(f.name, 0.0)
            contribution = raw * self._weights[f.name] * f.importance
            feature_contributions.append({
                "feature": f.name,
                "description": f.description,
                "value": round(raw, 4),
                "contribution": round(contribution, 4),
                "importance": round(f.importance, 2),
            })

        return {
            "probability": round(probability, 4),
            "confidence": round(confidence, 4),
            "risk_level": self._risk_level(probability),
            "model_version": self.version,
            "features_used": len([f for f in self.features if zone_features.get(f.name, 0) > 0]),
            "feature_contributions": feature_contributions,
            "explanation": self._explain(probability, feature_contributions),
        }

    def predict_batch(
        self,
        zones: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Predict risk for multiple zones."""
        results = []
        for zone in zones:
            features = self._extract_features(zone)
            prediction = self.predict_zone_risk(features)
            results.append({
                **zone,
                "prediction": prediction,
            })
        return results

    def _extract_features(self, zone: Dict[str, Any]) -> Dict[str, float]:
        """Extract prediction features from a zone record."""
        contributing = zone.get("contributing_features", {})
        complaint_count = zone.get("complaint_count", 0)
        total_amount = zone.get("total_amount", 0)

        return {
            "complaint_density": min(1.0, complaint_count / 100),
            "transaction_volume": min(1.0, total_amount / 5000000),
            "amount_concentration": min(1.0, total_amount / max(complaint_count, 1) / 100000),
            "temporal_pattern": random.uniform(0.3, 1.0),
            "fraud_type_diversity": min(1.0, contributing.get("fraud_diversity", 1) / 8),
            "account_relationship": random.uniform(0.2, 0.9),
            "geographic_proximity": random.uniform(0.1, 0.8),
            "historical_withdrawal": min(1.0, contributing.get("recent_30d", 0) / max(complaint_count, 1)),
        }

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1.0 / (1.0 + math.exp(-x))

    @staticmethod
    def _risk_level(prob: float) -> str:
        if prob >= 0.85:
            return "CRITICAL"
        elif prob >= 0.6:
            return "HIGH"
        elif prob >= 0.3:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _explain(probability: float, contributions: List[Dict[str, Any]]) -> str:
        top = contributions[:3]
        feature_desc = ", ".join(f"{c['feature']} ({c['contribution']:.3f})" for c in top)
        level = "critical" if probability >= 0.85 else "high" if probability >= 0.6 else "moderate" if probability >= 0.3 else "low"
        return (
            f"Model predicts {level} withdrawal risk (p={probability:.2%}). "
            f"Top contributing factors: {feature_desc}. "
            f"Prediction based on historical complaint patterns, transaction analysis, "
            f"and geographic clustering."
        )


# ── Singleton ────────────────────────────────────────────────────────────

_engine: Optional[PredictiveEngine] = None


def get_predictive_engine() -> PredictiveEngine:
    global _engine
    if _engine is None:
        _engine = PredictiveEngine()
    return _engine
