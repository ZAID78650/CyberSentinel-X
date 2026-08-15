"""Pytest fixtures.

A fresh SQLite database per test session is used, seeded once, so the
suite is fast and deterministic. The DATABASE_URL env var is set BEFORE
any application import so settings resolve to the test database.
"""
import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/test.db"
os.environ["ENVIRONMENT"] = "test"
os.environ["LLM_PROVIDER"] = "local"
os.environ["VECTOR_DB_BACKEND"] = "local"
os.environ["VECTOR_DB_PATH"] = f"{tempfile.mkdtemp()}/vector_store"
os.environ["DATASET_UPLOAD_DIR"] = f"{tempfile.mkdtemp()}/uploads"
os.environ["JWT_SECRET"] = "test-secret"
os.environ["JWT_REFRESH_SECRET"] = "test-refresh-secret"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.seed import run_seed  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def seeded_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    run_seed(db)
    # Test corpus: a small real event workload so API tests exercise
    # populated lists. Production DBs get their events from UNSW-NB15
    # ingestion / live streams instead of the seed.
    try:
        from app.agents.detection_agent import DetectionAgent
        from app.services.event_service import ingest_batch
        from app.services.simulator import build_scenario_events

        payloads = build_scenario_events("brute-force") + build_scenario_events("malware")
        events = ingest_batch(db, payloads, source="test-seed")
        DetectionAgent(db).evaluate_batch(events, actor="test-seed")
    except Exception as exc:  # pragma: no cover
        print(f"[conftest] warning: test corpus seeding failed: {exc}")
    db.close()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="session")
def db_session():
    """A shared DB session bound to the seeded test database."""
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_headers(client):
    r = client.post("/api/auth/login", json={"email": "admin@cybersentinel.io", "password": "Admin@2026"})
    assert r.status_code == 200, r.text
    token = r.json()["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def analyst_headers(client):
    r = client.post("/api/auth/login", json={"email": "analyst@cybersentinel.io", "password": "Analyst@2026"})
    token = r.json()["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def viewer_headers(client):
    r = client.post("/api/auth/login", json={"email": "viewer@cybersentinel.io", "password": "Viewer@2026"})
    token = r.json()["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}
