"""CyberSentinel X — FastAPI application entry point."""
import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import (
    alerts,
    analytics,
    analytics_ext,
    attack_dna,
    auth,
    campaign_intel,
    dashboard,
    dataset,
    evidence,
    events,
    financial,
    health,
    incidents,
    investigations,
    malware,
    oauth,
    pipeline,
    predictions,
    reports,
    sbom,
    response,
    security,
    simulations,
    threat_intel,
    soc_tools,
    ueba,
    websocket,
)
from app.core.config import get_settings
from app.core.database import Base, SessionLocal, engine
from app.core.logging import setup_logging
from app.services.auth_service import ensure_default_roles
from app.services.seed import run_seed

logger = logging.getLogger(__name__)
settings = get_settings()
setup_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """On startup: create tables if missing, seed reference data, start auto-detection."""
    logger.info("starting %s (%s)", settings.app_name, settings.environment)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ensure_default_roles(db)
        run_seed(db)
    finally:
        db.close()
    from app.api.routes.dataset import restore_bundled_sample

    restore_bundled_sample()
    from app.api.routes.dataset import auto_detection_loop

    auto_detection_task = asyncio.create_task(auto_detection_loop())
    yield
    auto_detection_task.cancel()
    logger.info("shutting down %s", settings.app_name)


app = FastAPI(
    title="CyberSentinel X API",
    description="Agentic AI-Powered Autonomous Cyber Threat Detection, Investigation & Response Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.core.firewall import FirewallMiddleware  # noqa: E402
app.add_middleware(FirewallMiddleware)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    if not settings.is_production:
        response.headers["X-Debug-Time-MS"] = f"{int((time.perf_counter() - start) * 1000)}"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# --- Routers -------------------------------------------------------------
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(security.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(investigations.router)
app.include_router(threat_intel.router)
app.include_router(attack_dna.router)
app.include_router(evidence.router)
app.include_router(predictions.router)
app.include_router(sbom.router)
app.include_router(pipeline.router)
app.include_router(malware.router)
app.include_router(soc_tools.router)
app.include_router(dashboard.router)
app.include_router(dataset.router)
app.include_router(response.router)
app.include_router(reports.router)
app.include_router(analytics.router)
app.include_router(analytics_ext.router)
app.include_router(campaign_intel.router)
app.include_router(ueba.router)
app.include_router(simulations.router)
app.include_router(websocket.router)
app.include_router(financial.router)


@app.get("/", include_in_schema=False)
def root():
    return {"name": settings.app_name, "docs": "/docs", "health": "/health", "ready": "/ready"}
