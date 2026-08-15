"""Synthetic attack simulator.

Generates SAFE, fully synthetic attack scenarios for the demo. No real
systems are ever touched. Each scenario produces a correlated event stream
that flows through detection -> alert -> incident -> pipeline.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


from app.schemas.event import EventIngest

logger = logging.getLogger(__name__)

BAD_IPS = {
    "account-takeover": ["45.155.205.233", "185.220.101.34"],
    "brute-force": ["103.75.190.12", "91.240.118.17"],
    "malware": ["45.155.205.233", "194.26.135.90"],
    "data-exfiltration": ["5.188.206.44", "45.155.205.233"],
    "privilege-escalation": ["103.75.190.12", "192.99.14.201"],
}

# (asset_id, label, criticality) — must exist in seed assets
ASSETS = {
    "account-takeover": ("ast-payroll-db", "payroll-db-01", 9),
    "brute-force": ("ast-app-server", "app-server-01", 6),
    "malware": ("ast-finance-ws", "finance-ws-07", 8),
    "data-exfiltration": ("ast-customer-db", "customer-db-02", 10),
    "privilege-escalation": ("ast-admin-srv", "admin-srv-03", 9),
}

USERS = {
    "account-takeover": "aisha.khan",
    "brute-force": "ravi.patel",
    "malware": "maria.fernandez",
    "data-exfiltration": "john.carter",
    "privilege-escalation": "sara.ahmed",
}

DEVICES = {
    "account-takeover": "MacBook-Pro-A7F3",
    "brute-force": "Windows-10-LT-4B21",
    "malware": "Windows-11-FIN-9C1D",
    "data-exfiltration": "MacBook-Air-8E2A",
    "privilege-escalation": "Ubuntu-WS-5F77",
}

METADATA: Dict[str, Dict[str, Any]] = {
    "account-takeover": {"location": "Mumbai, IN", "ip_asn": "AS174", "browser": "Chrome 125"},
    "brute-force": {"attempt_count": 26, "technique": "password-guessing"},
    "malware": {"file_hash": "b1946ac92492d2347c6235b4d2611184", "malware": "RedLine Stealer",
                "c2_domain": "update-secure-check.xyz", "cve": "CVE-2021-44228"},
    "data-exfiltration": {"bytes": 482_000_000, "method": "https-post", "data_classification": "RESTRICTED"},
    "privilege-escalation": {"privilege_from": "standard", "privilege_to": "domain-admin",
                             "technique": "uac-bypass", "cve": "CVE-2021-34527"},
}


def _minutes_ago(minutes: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def build_scenario_events(scenario: str) -> List[EventIngest]:
    """Build the event stream for a scenario, oldest first."""
    ip = BAD_IPS[scenario][0]
    ip2 = BAD_IPS[scenario][1]
    user = USERS[scenario]
    device = DEVICES[scenario]
    asset_id, asset_label, _crit = ASSETS[scenario]
    meta = dict(METADATA[scenario])

    def ev(event_type: str, minutes: float, severity: str = "MEDIUM", **extra) -> EventIngest:
        m = dict(meta)
        m.update(extra)
        return EventIngest(
            event_type=event_type,
            severity=severity,
            source_ip=ip if event_type != "DATA_EXFILTRATION" else ip2,
            destination_ip=None,
            user_id=user,
            device_id=device,
            asset_id=asset_id,
            source="simulator",
            timestamp=_minutes_ago(minutes),
            metadata=m,
        )

    if scenario == "account-takeover":
        return [
            ev("LOGIN_FAILURE", 45, "LOW", attempt=1),
            ev("LOGIN_FAILURE", 44, "LOW", attempt=2),
            ev("LOGIN_FAILURE", 43, "LOW", attempt=3),
            ev("LOGIN_FAILURE", 42, "LOW", attempt=4),
            ev("LOGIN_FAILURE", 41, "LOW", attempt=5),
            ev("LOGIN_FAILURE", 40, "LOW", attempt=6),
            ev("LOGIN_SUCCESS", 39, "HIGH", is_new_device=True),
            ev("NEW_DEVICE", 39, "MEDIUM"),
            ev("UNUSUAL_LOCATION", 38, "MEDIUM"),
            ev("PRIVILEGE_ESCALATION", 30, "HIGH"),
            ev("SUSPICIOUS_PROCESS", 25, "MEDIUM", process="powershell.exe -enc ..."),
            ev("DATABASE_ACCESS", 18, "HIGH", resource="payroll-db-01.employees"),
            ev("DATA_DOWNLOAD", 12, "HIGH", resource="payroll-db-01.employees", rows=12480),
            ev("SUSPICIOUS_NETWORK_CONNECTION", 5, "MEDIUM", destination=ip2),
        ]
    if scenario == "brute-force":
        events = [ev("LOGIN_FAILURE", 30 - i * 1.1, "LOW", attempt=i + 1) for i in range(22)]
        events += [
            ev("LOGIN_FAILURE", 5, "LOW", attempt=23),
            ev("LOGIN_FAILURE", 4, "LOW", attempt=24),
            ev("LOGIN_FAILURE", 3, "LOW", attempt=25),
            ev("LOGIN_SUCCESS", 2, "HIGH"),
            ev("NEW_DEVICE", 2, "MEDIUM"),
            ev("PRIVILEGE_ESCALATION", 1, "HIGH"),
        ]
        return events
    if scenario == "malware":
        return [
            ev("LOGIN_SUCCESS", 60, "MEDIUM"),
            ev("FILE_ACCESS", 50, "LOW", resource="Downloads/invoice-2026.exe"),
            ev("SUSPICIOUS_PROCESS", 45, "MEDIUM", process="setup_4891.exe"),
            ev("MALWARE_DETECTED", 40, "CRITICAL", signature="redline/stealer"),
            ev("SUSPICIOUS_NETWORK_CONNECTION", 35, "HIGH", destination=ip2),
            ev("SUSPICIOUS_PROCESS", 20, "MEDIUM", process="rundll32.exe"),
            ev("DATA_DOWNLOAD", 10, "HIGH", resource="Documents/credentials.txt"),
        ]
    if scenario == "data-exfiltration":
        return [
            ev("LOGIN_SUCCESS", 90, "MEDIUM"),
            ev("DATABASE_ACCESS", 60, "MEDIUM", resource="customer-db-02.customers"),
            ev("FILE_ACCESS", 45, "LOW", resource="//fileshare/confidential/"),
            ev("DATA_DOWNLOAD", 30, "HIGH", resource="customer-db-02.customers", rows=98200),
            ev("DATA_EXFILTRATION", 10, "CRITICAL", destination=ip2),
            ev("SUSPICIOUS_NETWORK_CONNECTION", 5, "MEDIUM", destination=ip2),
        ]
    if scenario == "privilege-escalation":
        return [
            ev("LOGIN_SUCCESS", 70, "MEDIUM"),
            ev("SUSPICIOUS_PROCESS", 50, "MEDIUM", process="sdclt.exe"),
            ev("PRIVILEGE_ESCALATION", 40, "HIGH"),
            ev("DATABASE_ACCESS", 25, "HIGH", resource="admin-srv-03.config"),
            ev("FILE_ACCESS", 15, "MEDIUM", resource="/etc/shadow"),
            ev("SUSPICIOUS_NETWORK_CONNECTION", 5, "MEDIUM", destination=ip2),
        ]
    raise ValueError(f"Unknown scenario: {scenario}")


SCENARIOS = {
    "account-takeover": "Account Takeover",
    "brute-force": "Brute Force Attack",
    "malware": "Malware Infection",
    "data-exfiltration": "Data Exfiltration",
    "privilege-escalation": "Privilege Escalation",
}
