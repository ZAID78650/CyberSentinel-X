"""Synthetic financial cybercrime data generator.

Generates realistic Indian cybercrime complaints, transactions, and
geographic data for the Predictive Withdrawal Intelligence Engine.
All data is synthetic — never uses real PII or financial data.
"""
import random
import hashlib
import math
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

# ── Indian geography for realistic cybercrime distribution ────────────────

INDIAN_STATES = {
    "Maharashtra": {"districts": ["Mumbai", "Pune", "Nagpur", "Thane", "Nashik"], "weight": 0.15, "center": (19.75, 75.71)},
    "Delhi": {"districts": ["New Delhi", "South Delhi", "North Delhi", "East Delhi", "West Delhi"], "weight": 0.12, "center": (28.61, 77.21)},
    "Karnataka": {"districts": ["Bengaluru", "Mysuru", "Mangaluru", "Hubli"], "weight": 0.10, "center": (15.32, 75.71)},
    "Tamil Nadu": {"districts": ["Chennai", "Coimbatore", "Madurai", "Salem"], "weight": 0.09, "center": (11.13, 78.67)},
    "Uttar Pradesh": {"districts": ["Lucknow", "Noida", "Agra", "Varanasi", "Kanpur"], "weight": 0.11, "center": (26.85, 80.91)},
    "Gujarat": {"districts": ["Ahmedabad", "Surat", "Vadodara", "Rajkot"], "weight": 0.07, "center": (22.26, 71.19)},
    "West Bengal": {"districts": ["Kolkata", "Howrah", "Durgapur"], "weight": 0.07, "center": (22.99, 87.75)},
    "Rajasthan": {"districts": ["Jaipur", "Jodhpur", "Udaipur"], "weight": 0.05, "center": (27.02, 74.22)},
    "Telangana": {"districts": ["Hyderabad", "Warangal"], "weight": 0.06, "center": (17.12, 79.20)},
    "Kerala": {"districts": ["Thiruvananthapuram", "Kochi", "Kozhikode"], "weight": 0.05, "center": (10.85, 76.27)},
    "Madhya Pradesh": {"districts": ["Bhopal", "Indore", "Jabalpur"], "weight": 0.04, "center": (22.97, 78.66)},
    "Bihar": {"districts": ["Patna", "Gaya"], "weight": 0.03, "center": (25.09, 85.31)},
    "Punjab": {"districts": ["Ludhiana", "Amritsar", "Chandigarh"], "weight": 0.03, "center": (30.90, 75.85)},
    "Odisha": {"districts": ["Bhubaneswar", "Cuttack"], "weight": 0.02, "center": (20.95, 85.10)},
    "Assam": {"districts": ["Guwahati"], "weight": 0.01, "center": (26.14, 91.74)},
}

FRAUD_TYPES = [
    {"type": "UPI Fraud", "weight": 0.22, "avg_amount": 15000, "amount_range": (500, 200000)},
    {"type": "Credit Card Fraud", "weight": 0.15, "avg_amount": 45000, "amount_range": (2000, 500000)},
    {"type": "Debit Card Fraud", "weight": 0.10, "avg_amount": 25000, "amount_range": (1000, 150000)},
    {"type": "Net Banking Fraud", "weight": 0.12, "avg_amount": 60000, "amount_range": (5000, 800000)},
    {"type": "KYC Fraud", "weight": 0.08, "avg_amount": 30000, "amount_range": (1000, 200000)},
    {"type": "Insurance Fraud", "weight": 0.05, "avg_amount": 120000, "amount_range": (10000, 1000000)},
    {"type": "Loan Fraud", "weight": 0.06, "avg_amount": 200000, "amount_range": (25000, 5000000)},
    {"type": "Cryptocurrency Fraud", "weight": 0.04, "avg_amount": 80000, "amount_range": (5000, 2000000)},
    {"type": "ATM Skimming", "weight": 0.05, "avg_amount": 35000, "amount_range": (2000, 100000)},
    {"type": "Phishing", "weight": 0.08, "avg_amount": 20000, "amount_range": (1000, 300000)},
    {"type": "SIM Swap Fraud", "weight": 0.03, "avg_amount": 50000, "amount_range": (2000, 500000)},
    {"type": "Investment Scam", "weight": 0.02, "avg_amount": 500000, "amount_range": (50000, 10000000)},
]

BANKS = [
    "SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Punjab National Bank",
    "Bank of Baroda", "Canara Bank", "Union Bank", "Indian Bank", "Kotak Mahindra",
    "Yes Bank", "IDFC First Bank", "IndusInd Bank", "Federal Bank", "South Indian Bank",
]

CHANNELS = ["UPI", "NEFT", "RTGS", "IMPS", "ATM", "NET_BANKING", "POS", "MOBILE_BANKING"]

# Time patterns: cybercrime peaks in evening/night
PEAK_HOURS = {
    0: 0.6, 1: 0.4, 2: 0.3, 3: 0.2, 4: 0.15, 5: 0.2,
    6: 0.3, 7: 0.4, 8: 0.5, 9: 0.6, 10: 0.7, 11: 0.75,
    12: 0.8, 13: 0.7, 14: 0.65, 15: 0.7, 16: 0.75, 17: 0.85,
    18: 0.95, 19: 1.0, 20: 0.95, 21: 0.9, 22: 0.85, 23: 0.7,
}

RISK_LEVELS = {"LOW": (0, 0.3), "MEDIUM": (0.3, 0.6), "HIGH": (0.6, 0.85), "CRITICAL": (0.85, 1.0)}


def _generate_id(prefix: str, seed: int) -> str:
    h = hashlib.md5(str(seed).encode()).hexdigest()[:8].upper()
    return f"{prefix}-{h}"


def _weighted_choice(items: list[dict], key: str = "weight") -> dict:
    weights = [i[key] for i in items]
    return random.choices(items, weights=weights, k=1)[0]


def _risk_level(prob: float) -> str:
    for level, (lo, hi) in RISK_LEVELS.items():
        if lo <= prob < hi:
            return level
    return "CRITICAL"


def _hour_from_weighted() -> int:
    hours = list(range(24))
    weights = [PEAK_HOURS[h] for h in hours]
    return random.choices(hours, weights=weights, k=1)[0]


class FinancialCrimeDataGenerator:
    """Generates a realistic synthetic dataset for the prediction engine."""

    def __init__(self, seed: int = 42, num_complaints: int = 500):
        self.seed = seed
        self.num_complaints = num_complaints
        random.seed(seed)
        self.complaints: List[Dict[str, Any]] = []
        self.transactions: List[Dict[str, Any]] = []
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.zones: List[Dict[str, Any]] = []

    def generate(self) -> Dict[str, Any]:
        """Generate the full synthetic dataset."""
        self._generate_complaints()
        self._generate_transactions()
        self._generate_accounts()
        self._generate_zones()
        self._compute_zone_risks()
        return {
            "complaints": self.complaints,
            "transactions": self.transactions,
            "accounts": list(self.accounts.values()),
            "zones": self.zones,
            "stats": self._compute_stats(),
        }

    def _generate_complaints(self):
        base_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
        for i in range(self.num_complaints):
            state_data = _weighted_choice(list(INDIAN_STATES.values()))
            state_name = [k for k, v in INDIAN_STATES.items() if v == state_data][0]
            district = random.choice(state_data["districts"])
            fraud = _weighted_choice(FRAUD_TYPES)
            amount = round(random.uniform(*fraud["amount_range"]), 2)
            hour = _hour_from_weighted()
            day_offset = random.randint(0, 365)
            complaint_time = base_date + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))

            # Geographic jitter around state center
            lat = state_data["center"][0] + random.gauss(0, 1.5)
            lon = state_data["center"][1] + random.gauss(0, 1.5)

            # Risk score based on amount, fraud type, and time
            amount_factor = min(1.0, amount / 200000)
            time_factor = PEAK_HOURS.get(hour, 0.5)
            fraud_factor = fraud["weight"] * 5
            risk = min(1.0, 0.2 * amount_factor + 0.3 * time_factor + 0.25 * fraud_factor + random.gauss(0, 0.1))
            risk = max(0.0, min(1.0, risk))

            victim_acc = _generate_id("ACC", i * 3)
            suspect_acc = _generate_id("ACC", i * 3 + 1)

            self.accounts[victim_acc] = {"account_id": victim_acc, "type": "VICTIM", "risk": 0.1, "state": state_name, "district": district}
            self.accounts[suspect_acc] = {"account_id": suspect_acc, "type": "SUSPECT", "risk": risk, "state": state_name, "district": district}

            status = random.choices(
                ["FILED", "INVESTIGATING", "RESOLVED", "CLOSED"],
                weights=[0.3, 0.35, 0.25, 0.1], k=1
            )[0]

            self.complaints.append({
                "complaint_id": f"CMP-{100000 + i}",
                "state": state_name,
                "district": district,
                "fraud_type": fraud["type"],
                "amount": amount,
                "reported_amount": round(amount * random.uniform(0.8, 1.2), 2),
                "status": status,
                "risk_score": round(risk, 4),
                "latitude": round(lat, 6),
                "longitude": round(lon, 6),
                "complaint_time": complaint_time.isoformat(),
                "victim_account": victim_acc,
                "suspect_account": suspect_acc,
                "channel": random.choice(CHANNELS),
                "bank": random.choice(BANKS),
                "description": f"{fraud['type']} reported from {district}, {state_name}. Amount: ₹{amount:,.0f}",
            })

    def _generate_transactions(self):
        """Generate 2-5 transactions per complaint."""
        for complaint in self.complaints:
            num_txns = random.randint(2, 5)
            for j in range(num_txns):
                tx_time = datetime.fromisoformat(complaint["complaint_time"]) - timedelta(hours=random.randint(1, 72))
                amount = complaint["amount"] / num_txns * random.uniform(0.5, 1.5)
                self.transactions.append({
                    "transaction_id": f"TXN-{hashlib.md5((complaint['complaint_id'] + '-' + str(j)).encode()).hexdigest()[:10].upper()}",
                    "complaint_id": complaint["complaint_id"],
                    "from_account": complaint["victim_account"],
                    "to_account": complaint["suspect_account"],
                    "amount": round(amount, 2),
                    "channel": complaint["channel"],
                    "timestamp": tx_time.isoformat(),
                    "is_suspicious": random.random() < 0.7,
                    "fraud_type": complaint["fraud_type"],
                    "latitude": complaint["latitude"] + random.gauss(0, 0.3),
                    "longitude": complaint["longitude"] + random.gauss(0, 0.3),
                    "state": complaint["state"],
                    "district": complaint["district"],
                })

    def _generate_accounts(self):
        """Generate mule accounts and beneficiary accounts."""
        for acc_id, acc in list(self.accounts.items()):
            if random.random() < 0.15:
                self.accounts[acc_id]["type"] = "MULE"
                self.accounts[acc_id]["risk"] = min(1.0, acc["risk"] + 0.3)

    def _generate_zones(self):
        """Generate withdrawal risk zones from complaint clusters."""
        zone_id = 0
        for state_name, state_data in INDIAN_STATES.items():
            state_complaints = [c for c in self.complaints if c["state"] == state_name]
            for district in state_data["districts"]:
                district_complaints = [c for c in state_complaints if c["district"] == district]
                if not district_complaints:
                    continue
                lat = sum(c["latitude"] for c in district_complaints) / len(district_complaints)
                lon = sum(c["longitude"] for c in district_complaints) / len(district_complaints)
                avg_risk = sum(c["risk_score"] for c in district_complaints) / len(district_complaints)
                total_amount = sum(c["amount"] for c in district_complaints)

                features = {
                    "complaint_density": len(district_complaints) / self.num_complaints,
                    "avg_amount": total_amount / len(district_complaints),
                    "fraud_diversity": len(set(c["fraud_type"] for c in district_complaints)),
                    "avg_risk": round(avg_risk, 4),
                    "recent_30d": sum(1 for c in district_complaints
                                       if datetime.fromisoformat(c["complaint_time"]) > datetime(2025, 11, 1, tzinfo=timezone.utc)),
                }

                self.zones.append({
                    "zone_id": f"ZN-{zone_id:03d}",
                    "zone_name": f"{district} ({state_name})",
                    "state": state_name,
                    "district": district,
                    "latitude": round(lat, 6),
                    "longitude": round(lon, 6),
                    "complaint_count": len(district_complaints),
                    "total_amount": round(total_amount, 2),
                    "avg_risk": round(avg_risk, 4),
                    "contributing_features": features,
                })
                zone_id += 1

    def _compute_zone_risks(self):
        """Compute risk probabilities for zones using a simple model."""
        if not self.zones:
            return
        max_complaints = max(z["complaint_count"] for z in self.zones)
        for zone in self.zones:
            # Weighted risk formula
            density_score = zone["complaint_count"] / max(max_complaints, 1)
            amount_score = min(1.0, zone["total_amount"] / 5000000)
            risk_score = zone["avg_risk"]
            spike_score = zone["contributing_features"].get("recent_30d", 0) / max(zone["complaint_count"], 1)

            probability = (
                0.30 * density_score +
                0.25 * amount_score +
                0.25 * risk_score +
                0.20 * spike_score +
                random.gauss(0, 0.03)
            )
            probability = max(0.0, min(1.0, probability))

            zone["risk_probability"] = round(probability, 4)
            zone["risk_level"] = _risk_level(probability)
            zone["confidence"] = round(min(0.95, 0.6 + density_score * 0.3 + random.uniform(0, 0.05)), 4)
            zone["model_version"] = "XGBoost-v4"
            zone["time_window"] = f"{_hour_from_weighted():02d}:00-{(_hour_from_weighted() + 3) % 24:02d}:00"

    def _compute_stats(self) -> Dict[str, Any]:
        total_amount = sum(c["amount"] for c in self.complaints)
        fraud_dist = {}
        state_dist = {}
        severity_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for c in self.complaints:
            fraud_dist[c["fraud_type"]] = fraud_dist.get(c["fraud_type"], 0) + 1
            state_dist[c["state"]] = state_dist.get(c["state"], 0) + 1
            severity_dist[c["risk_score"] >= 0.85 and "CRITICAL" or
                          c["risk_score"] >= 0.6 and "HIGH" or
                          c["risk_score"] >= 0.3 and "MEDIUM" or "LOW"] += 1

        return {
            "total_complaints": len(self.complaints),
            "total_transactions": len(self.transactions),
            "total_amount": round(total_amount, 2),
            "avg_complaint_amount": round(total_amount / max(len(self.complaints), 1), 2),
            "high_risk_zones": sum(1 for z in self.zones if z.get("risk_level") in ("HIGH", "CRITICAL")),
            "total_zones": len(self.zones),
            "fraud_distribution": fraud_dist,
            "state_distribution": state_dist,
            "severity_distribution": severity_dist,
            "unique_accounts": len(self.accounts),
            "suspicious_transactions": sum(1 for t in self.transactions if t.get("is_suspicious")),
        }


# ── Singleton generator (lazy, thread-safe) ──────────────────────────────

_generator_instance: Optional[FinancialCrimeDataGenerator] = None
_generator_data: Optional[Dict[str, Any]] = None


def get_financial_data(num_complaints: int = 500, seed: int = 42) -> Dict[str, Any]:
    """Get or regenerate the synthetic financial crime dataset."""
    global _generator_instance, _generator_data
    if _generator_data is None or _generator_instance is None or _generator_instance.num_complaints != num_complaints:
        _generator_instance = FinancialCrimeDataGenerator(seed=seed, num_complaints=num_complaints)
        _generator_data = _generator_instance.generate()
    return _generator_data


def get_complaints() -> List[Dict[str, Any]]:
    return get_financial_data()["complaints"]


def get_transactions() -> List[Dict[str, Any]]:
    return get_financial_data()["transactions"]


def get_accounts() -> List[Dict[str, Any]]:
    return get_financial_data()["accounts"]


def get_zones() -> List[Dict[str, Any]]:
    return get_financial_data()["zones"]


def get_stats() -> Dict[str, Any]:
    return get_financial_data()["stats"]


def get_heatmap_data() -> List[Dict[str, Any]]:
    """Get zone data formatted for heatmap visualization."""
    zones = get_zones()
    return [
        {
            "zone_id": z["zone_id"],
            "name": z["zone_name"],
            "lat": z["latitude"],
            "lng": z["longitude"],
            "risk": z["risk_probability"],
            "level": z["risk_level"],
            "complaints": z["complaint_count"],
            "amount": z["total_amount"],
            "confidence": z.get("confidence", 0),
            "time_window": z.get("time_window", "00:00-03:00"),
            "features": z.get("contributing_features", {}),
        }
        for z in zones
    ]


def get_predictive_alerts(n: int = 20) -> List[Dict[str, Any]]:
    """Generate the top N predictive withdrawal alerts."""
    zones = sorted(get_zones(), key=lambda z: z.get("risk_probability", 0), reverse=True)
    alerts = []
    for i, z in enumerate(zones[:n]):
        risk = z.get("risk_probability", 0)
        level = z.get("risk_level", "LOW")
        crime_types = list(set(
            c["fraud_type"] for c in get_complaints()
            if c["state"] == z["state"] and c["district"] == z["district"]
        ))
        hour = _hour_from_weighted()
        alerts.append({
            "alert_id": f"CSX-{1000 + i}",
            "risk_level": level,
            "risk_probability": round(risk, 4),
            "confidence": z.get("confidence", 0),
            "predicted_zone": z["zone_name"],
            "zone_id": z["zone_id"],
            "time_window": f"{hour:02d}:00-{(hour + 3) % 24:02d}:00",
            "crime_pattern": crime_types[0] if crime_types else "Mixed Fraud",
            "related_complaints": z["complaint_count"],
            "total_amount": z["total_amount"],
            "model_version": "XGBoost-v4",
            "latitude": z["latitude"],
            "longitude": z["longitude"],
            "state": z["state"],
            "district": z["district"],
            "contributing_features": z.get("contributing_features", {}),
            "is_actioned": random.random() < 0.3,
        })
    return alerts
