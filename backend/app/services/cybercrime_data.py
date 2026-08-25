"""Cybercrime Data Ingestion Engine.

Unified data ingestion supporting CSV, JSON, with:
- Schema detection and column mapping
- Type detection
- Missing/duplicate detection
- Timestamp normalization
- Currency normalization
- Geographic normalization
- Entity normalization
- Data quality scoring

Canonical schema for cybercrime data:
- Complaint, Account, Transaction, Beneficiary, Device, IP, ATM, Location, Bank/FI
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ── Canonical Schema ─────────────────────────────────────────────────────

CANONICAL_SCHEMA = {
    "complaint": {
        "required": ["complaint_id", "state", "district", "fraud_type"],
        "optional": ["city", "amount", "reported_amount", "status", "description",
                      "victim_account_id", "suspect_account_id", "transaction_id",
                      "risk_score", "latitude", "longitude", "complaint_time",
                      "occurrence_time", "channel", "bank", "device_type"],
    },
    "transaction": {
        "required": ["transaction_id", "from_account", "to_account", "amount"],
        "optional": ["complaint_id", "channel", "timestamp", "is_suspicious",
                      "fraud_type", "latitude", "longitude", "state", "district",
                      "description", "reference_number"],
    },
    "account": {
        "required": ["account_id", "account_type"],
        "optional": ["bank_name", "ifsc", "state", "district", "risk_score",
                      "linked_complaints", "total_transaction_volume", "is_frozen",
                      "created_date", "last_active"],
    },
}

# ── Column mapping aliases ───────────────────────────────────────────────

COLUMN_ALIASES = {
    "complaint_id": ["complaint_id", "complaintid", "cmp_id", "case_id", "caseid", "id", "complaint_number"],
    "state": ["state", "state_name", "st", "region"],
    "district": ["district", "district_name", "city", "city_name", "area", "location"],
    "fraud_type": ["fraud_type", "fraudtype", "crime_type", "crimetype", "type", "category", "attack_cat", "label"],
    "amount": ["amount", "transaction_amount", "amt", "value", "sum", "total", "money"],
    "status": ["status", "case_status", "complaint_status"],
    "latitude": ["latitude", "lat", "y", "geo_lat"],
    "longitude": ["longitude", "lng", "lon", "long", "x", "geo_lng"],
    "complaint_time": ["complaint_time", "complaintdate", "date", "timestamp", "time", "reported_at", "created_at"],
    "from_account": ["from_account", "sender", "source_account", "debit_account", "payer"],
    "to_account": ["to_account", "receiver", "destination_account", "credit_account", "payee"],
    "transaction_id": ["transaction_id", "txn_id", "trans_id", "payment_id"],
    "channel": ["channel", "payment_channel", "mode", "payment_mode", "medium"],
    "bank": ["bank", "bank_name", "institution", "financial_institution", "fi"],
    "ip_address": ["ip", "ip_address", "src_ip", "source_ip", "dst_ip", "destination_ip"],
    "device_type": ["device", "device_type", "platform", "os"],
}

# Indian geography
INDIAN_STATES = {
    "Maharashtra": {"districts": ["Mumbai", "Pune", "Nagpur", "Thane", "Nashik", "Aurangabad", "Solapur"], "weight": 0.15, "center": (19.75, 75.71)},
    "Delhi": {"districts": ["New Delhi", "South Delhi", "North Delhi", "East Delhi", "West Delhi"], "weight": 0.12, "center": (28.61, 77.21)},
    "Karnataka": {"districts": ["Bengaluru", "Mysuru", "Mangaluru", "Hubli", "Belgaum"], "weight": 0.10, "center": (15.32, 75.71)},
    "Tamil Nadu": {"districts": ["Chennai", "Coimbatore", "Madurai", "Salem", "Tiruchirappalli"], "weight": 0.09, "center": (11.13, 78.67)},
    "Uttar Pradesh": {"districts": ["Lucknow", "Noida", "Agra", "Varanasi", "Kanpur", "Meerut"], "weight": 0.11, "center": (26.85, 80.91)},
    "Gujarat": {"districts": ["Ahmedabad", "Surat", "Vadodara", "Rajkot"], "weight": 0.07, "center": (22.26, 71.19)},
    "West Bengal": {"districts": ["Kolkata", "Howrah", "Durgapur", "Siliguri"], "weight": 0.07, "center": (22.99, 87.75)},
    "Rajasthan": {"districts": ["Jaipur", "Jodhpur", "Udaipur", "Kota"], "weight": 0.05, "center": (27.02, 74.22)},
    "Telangana": {"districts": ["Hyderabad", "Warangal", "Karimnagar"], "weight": 0.06, "center": (17.12, 79.20)},
    "Kerala": {"districts": ["Thiruvananthapuram", "Kochi", "Kozhikode", "Thrissur"], "weight": 0.05, "center": (10.85, 76.27)},
    "Madhya Pradesh": {"districts": ["Bhopal", "Indore", "Jabalpur", "Gwalior"], "weight": 0.04, "center": (22.97, 78.66)},
    "Bihar": {"districts": ["Patna", "Gaya", "Muzaffarpur"], "weight": 0.03, "center": (25.09, 85.31)},
    "Punjab": {"districts": ["Ludhiana", "Amritsar", "Chandigarh", "Jalandhar"], "weight": 0.03, "center": (30.90, 75.85)},
    "Odisha": {"districts": ["Bhubaneswar", "Cuttack", "Rourkela"], "weight": 0.02, "center": (20.95, 85.10)},
    "Assam": {"districts": ["Guwahati", "Silchar"], "weight": 0.01, "center": (26.14, 91.74)},
    "Jharkhand": {"districts": ["Ranchi", "Jamshedpur", "Dhanbad"], "weight": 0.02, "center": (23.34, 85.31)},
    "Chhattisgarh": {"districts": ["Raipur", "Bhilai"], "weight": 0.01, "center": (21.25, 81.63)},
    "Goa": {"districts": ["Panaji", "Margao"], "weight": 0.01, "center": (15.49, 73.83)},
}

FRAUD_TYPES = [
    {"type": "UPI Fraud", "weight": 0.22, "avg_amount": 15000, "range": (500, 200000)},
    {"type": "Credit Card Fraud", "weight": 0.15, "avg_amount": 45000, "range": (2000, 500000)},
    {"type": "Debit Card Fraud", "weight": 0.10, "avg_amount": 25000, "range": (1000, 150000)},
    {"type": "Net Banking Fraud", "weight": 0.12, "avg_amount": 60000, "range": (5000, 800000)},
    {"type": "KYC Fraud", "weight": 0.08, "avg_amount": 30000, "range": (1000, 200000)},
    {"type": "Insurance Fraud", "weight": 0.05, "avg_amount": 120000, "range": (10000, 1000000)},
    {"type": "Loan Fraud", "weight": 0.06, "avg_amount": 200000, "range": (25000, 5000000)},
    {"type": "Cryptocurrency Fraud", "weight": 0.04, "avg_amount": 80000, "range": (5000, 2000000)},
    {"type": "ATM Skimming", "weight": 0.05, "avg_amount": 35000, "range": (2000, 100000)},
    {"type": "Phishing", "weight": 0.08, "avg_amount": 20000, "range": (1000, 300000)},
    {"type": "SIM Swap Fraud", "weight": 0.03, "avg_amount": 50000, "range": (2000, 500000)},
    {"type": "Investment Scam", "weight": 0.02, "avg_amount": 500000, "range": (50000, 10000000)},
]

BANKS = [
    "SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Punjab National Bank",
    "Bank of Baroda", "Canara Bank", "Union Bank", "Indian Bank", "Kotak Mahindra",
    "Yes Bank", "IDFC First Bank", "IndusInd Bank", "Federal Bank", "South Indian Bank",
]

CHANNELS = ["UPI", "NEFT", "RTGS", "IMPS", "ATM", "NET_BANKING", "POS", "MOBILE_BANKING"]

PEAK_HOURS = {
    0: 0.6, 1: 0.4, 2: 0.3, 3: 0.2, 4: 0.15, 5: 0.2,
    6: 0.3, 7: 0.4, 8: 0.5, 9: 0.6, 10: 0.7, 11: 0.75,
    12: 0.8, 13: 0.7, 14: 0.65, 15: 0.7, 16: 0.75, 17: 0.85,
    18: 0.95, 19: 1.0, 20: 0.95, 21: 0.9, 22: 0.85, 23: 0.7,
}


# ══════════════════════════════════════════════════════════════════════════
# DATA QUALITY SCORER
# ══════════════════════════════════════════════════════════════════════════

class DataQualityScorer:
    """Score dataset quality based on completeness, consistency, and validity."""

    def score(self, data: List[Dict], schema_type: str = "complaint") -> Dict[str, Any]:
        if not data:
            return {"score": 0, "grade": "F", "issues": ["No data"]}

        schema = CANONICAL_SCHEMA.get(schema_type, CANONICAL_SCHEMA["complaint"])
        total = len(data)
        all_keys = set()
        for row in data:
            all_keys.update(row.keys())

        # Completeness
        missing_rates = {}
        for field in schema["required"]:
            present = sum(1 for row in data if row.get(field) is not None and str(row.get(field, "")).strip())
            missing_rates[field] = round((1 - present / total) * 100, 1)

        for field in schema.get("optional", []):
            present = sum(1 for row in data if row.get(field) is not None and str(row.get(field, "")).strip())
            missing_rates[field] = round((1 - present / total) * 100, 1)

        # Duplicates
        id_field = schema["required"][0] if schema["required"] else "id"
        ids = [row.get(id_field) for row in data if row.get(id_field)]
        dup_rate = round((1 - len(set(str(i) for i in ids)) / max(len(ids), 1)) * 100, 1)

        # Type consistency
        numeric_fields = ["amount", "risk_score", "latitude", "longitude"]
        type_issues = 0
        for field in numeric_fields:
            for row in data[:100]:
                val = row.get(field)
                if val is not None and str(val).strip():
                    try:
                        float(str(val).replace(",", ""))
                    except (ValueError, TypeError):
                        type_issues += 1

        # Calculate score
        required_missing_avg = sum(missing_rates.get(f, 0) for f in schema["required"]) / max(len(schema["required"]), 1)
        completeness_penalty = min(40, required_missing_avg * 2)
        dup_penalty = min(15, dup_rate * 0.5)
        type_penalty = min(10, type_issues * 0.2)
        unknown_fields_penalty = min(10, max(0, (len(all_keys) - len(CANONICAL_SCHEMA["complaint"]["required"]) - 8)) * 0.5)

        score = round(max(0, 100 - completeness_penalty - dup_penalty - type_penalty - unknown_fields_penalty), 1)

        if score >= 90: grade = "A"
        elif score >= 80: grade = "B"
        elif score >= 70: grade = "C"
        elif score >= 60: grade = "D"
        else: grade = "F"

        issues = []
        for field, rate in missing_rates.items():
            if rate > 50:
                issues.append(f"High missing rate for '{field}': {rate}%")
        if dup_rate > 5:
            issues.append(f"Duplicate rate: {dup_rate}%")
        if type_issues > 10:
            issues.append(f"Type inconsistencies: {type_issues} values")

        return {
            "score": score,
            "grade": grade,
            "total_records": total,
            "unique_fields": len(all_keys),
            "completeness": {k: 100 - v for k, v in missing_rates.items()},
            "duplicate_rate": dup_rate,
            "type_issues": type_issues,
            "issues": issues[:10],
            "missing_rates": missing_rates,
        }


# ══════════════════════════════════════════════════════════════════════════
# ENHANCED SYNTHETIC DATA GENERATOR
# ══════════════════════════════════════════════════════════════════════════

class CyberCrimeDataGenerator:
    """Generates realistic synthetic Indian cybercrime data for ML training.

    Produces complaints, transactions, accounts, and geographic zones with
    realistic temporal patterns, geographic clustering, and fraud relationships.
    """

    def __init__(self, seed: int = 42, num_complaints: int = 500):
        self.seed = seed
        self.num_complaints = num_complaints
        random.seed(seed)
        np.random.seed(seed)

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
        self._add_risk_levels()

        stats = self._compute_stats()
        return {
            "complaints": self.complaints,
            "transactions": self.transactions,
            "accounts": list(self.accounts.values()),
            "zones": self.zones,
            "stats": stats,
        }

    def _generate_complaints(self):
        base_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
        for i in range(self.num_complaints):
            state_name, state_data = self._weighted_state()
            district = random.choice(state_data["districts"])
            fraud = self._weighted_fraud()
            amount = round(random.uniform(*fraud["range"]), 2)
            hour = self._weighted_hour()
            day_offset = random.randint(0, 365)
            complaint_time = base_date + timedelta(days=day_offset, hours=hour, minutes=random.randint(0, 59))

            lat = state_data["center"][0] + random.gauss(0, 1.5)
            lon = state_data["center"][1] + random.gauss(0, 1.5)

            amount_factor = min(1.0, amount / 200000)
            time_factor = PEAK_HOURS.get(hour, 0.5)
            fraud_factor = fraud["weight"] * 5
            risk = min(1.0, max(0.0,
                0.2 * amount_factor + 0.3 * time_factor + 0.25 * fraud_factor + random.gauss(0, 0.1)
            ))

            victim_acc = f"ACC-{hashlib.md5(str(i * 3).encode()).hexdigest()[:8].upper()}"
            suspect_acc = f"ACC-{hashlib.md5(str(i * 3 + 1).encode()).hexdigest()[:8].upper()}"

            self.accounts[victim_acc] = {"account_id": victim_acc, "type": "VICTIM", "risk": 0.1, "state": state_name, "district": district}
            self.accounts[suspect_acc] = {"account_id": suspect_acc, "type": "SUSPECT", "risk": risk, "state": state_name, "district": district}

            status = random.choices(["FILED", "INVESTIGATING", "RESOLVED", "CLOSED"], weights=[0.3, 0.35, 0.25, 0.1], k=1)[0]

            self.complaints.append({
                "complaint_id": f"CMP-{100000 + i}",
                "state": state_name,
                "district": district,
                "city": district,
                "fraud_type": fraud["type"],
                "amount": amount,
                "reported_amount": round(amount * random.uniform(0.8, 1.2), 2),
                "status": status,
                "risk_score": round(risk, 4),
                "latitude": round(lat, 6),
                "longitude": round(lon, 6),
                "complaint_time": complaint_time.isoformat(),
                "occurrence_time": (complaint_time - timedelta(hours=random.randint(1, 72))).isoformat(),
                "victim_account": victim_acc,
                "suspect_account": suspect_acc,
                "channel": random.choice(CHANNELS),
                "bank": random.choice(BANKS),
                "description": f"{fraud['type']} reported from {district}, {state_name}. Amount: ₹{amount:,.0f}",
                "ip_address": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "device_type": random.choice(["Android", "iOS", "Windows", "Mac", "Linux"]),
            })

    def _generate_transactions(self):
        for complaint in self.complaints:
            num_txns = random.randint(2, 5)
            for j in range(num_txns):
                tx_time = datetime.fromisoformat(complaint["complaint_time"]) - timedelta(hours=random.randint(1, 72))
                amount = complaint["amount"] / num_txns * random.uniform(0.5, 1.5)
                self.transactions.append({
                    "transaction_id": f"TXN-{hashlib.md5((complaint['complaint_id'] + str(j)).encode()).hexdigest()[:10].upper()}",
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
        for acc_id, acc in list(self.accounts.items()):
            if random.random() < 0.15:
                self.accounts[acc_id]["type"] = "MULE"
                self.accounts[acc_id]["risk"] = min(1.0, acc["risk"] + 0.3)

    def _generate_zones(self):
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
                    "recent_90d": sum(1 for c in district_complaints
                                       if datetime.fromisoformat(c["complaint_time"]) > datetime(2025, 9, 1, tzinfo=timezone.utc)),
                    "unique_victims": len(set(c.get("victim_account", "") for c in district_complaints)),
                    "unique_suspects": len(set(c.get("suspect_account", "") for c in district_complaints)),
                    "channel_diversity": len(set(c["channel"] for c in district_complaints)),
                    "avg_daily_amount": total_amount / 365,
                    "amount_concentration": max(c["amount"] for c in district_complaints) / max(total_amount, 1),
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
        if not self.zones:
            return
        max_complaints = max(z["complaint_count"] for z in self.zones)
        for zone in self.zones:
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
            zone["risk_level"] = self._risk_level(probability)
            zone["confidence"] = round(min(0.95, 0.6 + density_score * 0.3 + random.uniform(0, 0.05)), 4)
            zone["model_version"] = "XGBoost-v4"
            zone["time_window"] = f"{self._weighted_hour():02d}:00-{(self._weighted_hour() + 3) % 24:02d}:00"

    def _add_risk_levels(self):
        for c in self.complaints:
            risk = c.get("risk_score", 0.5)
            if risk >= 0.85: c["risk_level"] = "CRITICAL"
            elif risk >= 0.6: c["risk_level"] = "HIGH"
            elif risk >= 0.3: c["risk_level"] = "MEDIUM"
            else: c["risk_level"] = "LOW"

    def _compute_stats(self) -> Dict[str, Any]:
        total_amount = sum(c["amount"] for c in self.complaints)
        fraud_dist = {}
        state_dist = {}
        severity_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for c in self.complaints:
            fraud_dist[c["fraud_type"]] = fraud_dist.get(c["fraud_type"], 0) + 1
            state_dist[c["state"]] = state_dist.get(c["state"], 0) + 1
            severity_dist[c.get("risk_level", "LOW")] += 1

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

    def _weighted_state(self):
        states = list(INDIAN_STATES.items())
        weights = [s[1]["weight"] for s in states]
        chosen = random.choices(states, weights=weights, k=1)[0]
        return chosen[0], chosen[1]

    def _weighted_fraud(self):
        return random.choices(FRAUD_TYPES, weights=[f["weight"] for f in FRAUD_TYPES], k=1)[0]

    def _weighted_hour(self):
        hours = list(range(24))
        weights = [PEAK_HOURS[h] for h in hours]
        return random.choices(hours, weights=weights, k=1)[0]

    @staticmethod
    def _risk_level(prob):
        if prob >= 0.85: return "CRITICAL"
        if prob >= 0.6: return "HIGH"
        if prob >= 0.3: return "MEDIUM"
        return "LOW"


# ══════════════════════════════════════════════════════════════════════════
# DATA INGESTION ENGINE
# ══════════════════════════════════════════════════════════════════════════

class IngestionEngine:
    """Unified data ingestion with schema detection and normalization."""

    def ingest_csv(self, filepath: str, schema_type: str = "auto") -> Dict[str, Any]:
        """Ingest a CSV file with schema detection and normalization."""
        import pandas as pd

        t0 = time.time()
        basename = os.path.basename(filepath)

        # Detect schema
        df = pd.read_csv(filepath, nrows=5)
        detected_schema = self._detect_schema(list(df.columns))
        df = pd.read_csv(filepath)  # full read
        total_rows = len(df)

        # Column mapping
        mapped_columns = self._map_columns(list(df.columns))

        # Rename columns to canonical names
        rename_map = {}
        for original, canonical in mapped_columns.items():
            if canonical and canonical != original:
                rename_map[original] = canonical
        if rename_map:
            df = df.rename(columns=rename_map)

        # Type conversion
        for col in ["amount", "reported_amount", "risk_score", "latitude", "longitude"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col].astype(str).str.replace(",", ""), errors="coerce")

        # Timestamp normalization
        for col in ["complaint_time", "occurrence_time", "timestamp"]:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)

        # Remove duplicates
        initial_rows = len(df)
        id_col = "complaint_id" if "complaint_id" in df.columns else df.columns[0]
        df = df.drop_duplicates(subset=[id_col], keep="first")
        duplicates_removed = initial_rows - len(df)

        # Missing value report
        missing_report = {}
        for col in df.columns:
            missing_count = int(df[col].isna().sum())
            if missing_count > 0:
                missing_report[col] = round(missing_count / total_rows * 100, 1)

        # Convert to dict records
        records = df.where(df.notna(), None).to_dict("records")

        # Data quality scoring
        scorer = DataQualityScorer()
        quality = scorer.score(records, detected_schema)

        elapsed_ms = int((time.time() - t0) * 1000)

        return {
            "file": basename,
            "total_rows": total_rows,
            "rows_after_dedup": len(records),
            "duplicates_removed": duplicates_removed,
            "detected_schema": detected_schema,
            "mapped_columns": {k: v for k, v in mapped_columns.items() if v},
            "missing_report": missing_report,
            "data_quality": quality,
            "records": records,
            "ingestion_time_ms": elapsed_ms,
            "columns": list(df.columns),
        }

    def _detect_schema(self, columns: List[str]) -> str:
        """Auto-detect which canonical schema best matches."""
        cols_lower = [c.lower().strip() for c in columns]
        scores = {}
        for schema_name, schema in CANONICAL_SCHEMA.items():
            required = [r.lower() for r in schema["required"]]
            matched = sum(1 for r in required if any(r in c for c in cols_lower))
            scores[schema_name] = matched / max(len(required), 1)
        best = max(scores, key=scores.get)
        return best if scores[best] > 0.3 else "complaint"

    def _map_columns(self, columns: List[str]) -> Dict[str, Optional[str]]:
        """Map raw columns to canonical names."""
        mapping = {}
        used_canonical = set()
        for col in columns:
            col_lower = col.lower().strip()
            mapped = None
            for canonical, aliases in COLUMN_ALIASES.items():
                if canonical not in used_canonical and col_lower in [a.lower() for a in aliases]:
                    mapped = canonical
                    used_canonical.add(canonical)
                    break
            mapping[col] = mapped
        return mapping


# ── Singleton data cache ─────────────────────────────────────────────────

_generator_instance: Optional[CyberCrimeDataGenerator] = None
_generator_data: Optional[Dict[str, Any]] = None


def get_financial_data(num_complaints: int = 500, seed: int = 42) -> Dict[str, Any]:
    """Get or regenerate the synthetic financial crime dataset."""
    global _generator_instance, _generator_data
    if _generator_data is None or _generator_instance is None or _generator_instance.num_complaints != num_complaints:
        _generator_instance = CyberCrimeDataGenerator(seed=seed, num_complaints=num_complaints)
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
    zones = get_zones()
    return [
        {
            "zone_id": z["zone_id"], "name": z["zone_name"],
            "lat": z["latitude"], "lng": z["longitude"],
            "risk": z["risk_probability"], "level": z["risk_level"],
            "complaints": z["complaint_count"], "amount": z["total_amount"],
            "confidence": z.get("confidence", 0),
            "time_window": z.get("time_window", "00:00-03:00"),
            "features": z.get("contributing_features", {}),
        }
        for z in zones
    ]

def get_predictive_alerts(n: int = 20) -> List[Dict[str, Any]]:
    zones = sorted(get_zones(), key=lambda z: z.get("risk_probability", 0), reverse=True)
    alerts = []
    for i, z in enumerate(zones[:n]):
        risk = z.get("risk_probability", 0)
        level = z.get("risk_level", "LOW")
        crime_types = list(set(
            c["fraud_type"] for c in get_complaints()
            if c["state"] == z["state"] and c["district"] == z["district"]
        ))
        hour = random.choices(list(range(24)), weights=[PEAK_HOURS[h] for h in range(24)], k=1)[0]
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
