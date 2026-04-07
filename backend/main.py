"""
main.py — FastAPI application entry point.
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.models.database import engine, Base
from backend.routers import events, alerts, hosts, ws

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured.")
    yield
    await engine.dispose()
    logger.info("Database engine disposed.")


app = FastAPI(
    title="Hybrid R-Sentry API",
    description="Ransomware detection backend — event ingestion, alert management, live WS push.",
    version="1.0.0",
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


@app.get("/health")
async def health():
    return {"status": "ok", "service": "hybrid-rsentry-backend"}


@app.get("/")
async def root():
    return {"message": "Hybrid R-Sentry API v1.0.0 — /docs for Swagger UI"}
