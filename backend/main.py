"""
main.py — FastAPI application entry point.
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.models.database import engine
from backend.routers import events, alerts, hosts, ws, exceptions, simulate

logger = logging.getLogger(__name__)


def _run_migrations() -> None:
    """Run Alembic upgrade head (sync — called from asyncio.to_thread).

    Resolve alembic.ini and script_location against the project root rather than
    the process CWD. A bare ``Config("alembic.ini")`` is CWD-relative, so when
    uvicorn is launched from anywhere other than the repo root alembic silently
    reads an empty config and fails with "No 'script_location' key found".
    """
    project_root = Path(__file__).resolve().parents[1]
    cfg = Config(str(project_root / "alembic.ini"))
    # script_location in the .ini is itself CWD-relative; pin it absolute too.
    cfg.set_main_option("script_location", str(project_root / "backend" / "migrations"))
    cfg.set_main_option("prepend_sys_path", str(project_root))
    command.upgrade(cfg, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await asyncio.to_thread(_run_migrations)
    logger.info("Database migrations applied.")
    yield
    await engine.dispose()
    logger.info("Database engine disposed.")


app = FastAPI(
    title="Hybrid R-Sentry API",
    description="Ransomware detection backend — event ingestion, alert management, live WS push.",
    version="2.2.0",
    lifespan=lifespan,
)

# CORS — allow the React dev server and production build
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(hosts.router)
app.include_router(ws.router)
app.include_router(exceptions.router)
app.include_router(simulate.router)


@app.get("/health")
async def health():
    import os
    return {
        "status": "ok",
        "service": "hybrid-rsentry-backend",
        "sensor_backend": os.getenv("SENSOR_BACKEND", "ebpf"),
    }


@app.get("/")
async def root():
    return {"message": "Hybrid R-Sentry API v2.2.0 — /docs for Swagger UI"}


class HealthCheckRequest(BaseModel):
    events: list[dict] = Field(default=[], max_length=200)


@app.post("/api/ai/health")
async def ai_health_check(body: HealthCheckRequest):
    """Trigger async AI health analysis of recent events."""
    from backend.workers.tasks import analyze_health_ai
    analyze_health_ai.delay(body.events[:100])
    return {"status": "analysis_queued"}
