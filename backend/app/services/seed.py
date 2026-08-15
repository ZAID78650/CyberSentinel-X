"""Idempotent database seeding.

Populates reference data only: roles, demo users, assets, MITRE techniques,
threat indicators and knowledge documents (RAG). No synthetic events are
seeded — event data comes from real datasets (UNSW-NB15) or live ingestion.
Safe to run repeatedly.
"""
import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.intel import KnowledgeDocument, MitreTechnique
from app.models.security import Asset
from app.models.user import User
from app.services.auth_service import ensure_default_roles, get_or_create_role
from app.threat_intel.adapter import seed_local_indicators
from app.threat_intel.mitre_data import MITRE_TECHNIQUES

logger = logging.getLogger(__name__)

DEMO_USERS = [
    {"email": "admin@cybersentinel.io", "full_name": "System Administrator", "org": "CyberSentinel SOC",
     "password": "Admin@2026", "role": "ADMIN"},
    {"email": "analyst@cybersentinel.io", "full_name": "Ava Security Analyst", "org": "CyberSentinel SOC",
     "password": "Analyst@2026", "role": "SECURITY_ANALYST"},
    {"email": "viewer@cybersentinel.io", "full_name": "Vikram Viewer", "org": "CyberSentinel SOC",
     "password": "Viewer@2026", "role": "VIEWER"},
]

ASSETS = [
    ("ast-payroll-db", "payroll-db-01", "database", "10.0.1.21", "payroll-db-01.corp.local", 9, "Finance"),
    ("ast-customer-db", "customer-db-02", "database", "10.0.1.22", "customer-db-02.corp.local", 10, "Customer Success"),
    ("ast-app-server", "app-server-01", "server", "10.0.2.11", "app-server-01.corp.local", 6, "Engineering"),
    ("ast-admin-srv", "admin-srv-03", "server", "10.0.2.15", "admin-srv-03.corp.local", 9, "IT Operations"),
    ("ast-finance-ws", "finance-ws-07", "workstation", "10.0.3.31", "finance-ws-07.corp.local", 8, "Finance"),
    ("ast-email-gw", "email-gw-01", "server", "10.0.2.9", "email-gw-01.corp.local", 7, "IT Operations"),
    ("ast-file-share", "fileshare-01", "server", "10.0.2.12", "fileshare-01.corp.local", 8, "All"),
    ("ast-prod-api", "prod-api-01", "server", "10.0.2.13", "prod-api-01.corp.local", 6, "Engineering"),
]

def seed_mitre(db: Session) -> int:
    count = db.scalar(select(func.count()).select_from(MitreTechnique)) or 0
    if count > 0:
        return count
    for t in MITRE_TECHNIQUES:
        db.add(MitreTechnique(
            technique_id=t["technique_id"], name=t["name"], tactic=t["tactic"],
            description=t["description"], detection=t["detection"],
            severity_hint=t["severity_hint"], platforms=t["platforms"], url=t["url"],
        ))
    db.commit()
    return len(MITRE_TECHNIQUES)


def seed_assets(db: Session) -> int:
    count = db.scalar(select(func.count()).select_from(Asset)) or 0
    if count > 0:
        return count
    for asset_id, name, atype, ip, host, crit, owner in ASSETS:
        # name stores the stable key referenced by events (e.g. ast-payroll-db)
        db.add(Asset(name=asset_id, asset_type=atype, ip_address=ip, hostname=host,
                     criticality=crit, owner=owner, description=f"{atype} {name} ({asset_id})"))
    db.commit()
    return len(ASSETS)


def seed_users(db: Session) -> int:
    ensure_default_roles(db)
    created = 0
    for u in DEMO_USERS:
        if db.scalar(select(User).where(User.email == u["email"])):
            continue
        from app.core.security import hash_password
        user = User(email=u["email"], full_name=u["full_name"], organization=u["org"],
                    password_hash=hash_password(u["password"]), is_verified=True)
        role = get_or_create_role(db, u["role"])
        user.roles.append(role)
        db.add(user)
        created += 1
    db.commit()
    return created


def run_seed(db: Session) -> None:
    seed_users(db)
    seed_mitre(db)
    seed_assets(db)
    seed_local_indicators(db)
    _seed_knowledge(db)


def _seed_knowledge(db: Session) -> None:
    count = db.scalar(select(func.count()).select_from(KnowledgeDocument)) or 0
    if count > 0:
        return
    try:
        from app.rag.rag_service import index_documents
        index_documents(db)
    except Exception as exc:
        logger.warning("knowledge indexing skipped: %s", exc)
