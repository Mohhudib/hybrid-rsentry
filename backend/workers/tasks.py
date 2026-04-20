import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Load .env so Celery workers have access to API keys and DB URL
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

import redis as redis_lib
from celery import Celery
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from backend.models.schemas import Alert, Event, Host, Severity
from backend.services import ai_analyst

logger = logging.getLogger(__name__)

celery_app = Celery(
    "rsentry",
    broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
)
celery_app.conf.task_serializer = "json"
celery_app.conf.result_serializer = "json"
celery_app.conf.accept_content = ["json"]

_engine = None
_SessionLocal = None


def _get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_async_engine(
            os.getenv("DATABASE_URL", ""),
            poolclass=NullPool,
        )
        _SessionLocal = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine, _SessionLocal


def _run(coro):
    """Python 3.13 Celery fork safety — asyncio.run() breaks in forked workers."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _redis():
    return redis_lib.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        decode_responses=True,
    )


# ── WebSocket push tasks ──────────────────────────────────────────────────────

@celery_app.task(name="push_alert_ws")
def push_alert_ws(alert_id: str, host_id: str, severity: str, event_type: str):
    r = _redis()
    r.publish("rsentry:alerts", json.dumps({
        "type": "new_alert",
        "alert_id": alert_id,
        "host_id": host_id,
        "severity": severity,
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))


@celery_app.task(name="push_event_ws")
def push_event_ws(
    event_id: str, host_id: str, event_type: str, severity: str,
    file_path: str, entropy_delta: float, canary_hit: bool,
    process_name: str, details: dict,
):
    r = _redis()
    r.publish("rsentry:events", json.dumps({
        "type": "new_event",
        "event_id": event_id,
        "host_id": host_id,
        "event_type": event_type,
        "severity": severity,
        "file_path": file_path,
        "entropy_delta": entropy_delta,
        "canary_hit": canary_hit,
        "process_name": process_name,
        "details": details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))


# ── Host risk ─────────────────────────────────────────────────────────────────

@celery_app.task(name="update_host_risk")
def update_host_risk(host_id: str):
    async def _inner():
        _, SessionLocal = _get_engine()
        async with SessionLocal() as db:
            result = await db.execute(
                select(Alert.severity, func.count(Alert.id))
                .where(Alert.host_id == host_id, Alert.acknowledged == False)
                .group_by(Alert.severity)
            )
            rows = result.all()
            weights = {
                Severity.CRITICAL: 40,
                Severity.HIGH: 20,
                Severity.MEDIUM: 10,
                Severity.LOW: 2,
            }
            score = min(sum(weights.get(sev, 0) * count for sev, count in rows), 100.0)

            host_result = await db.execute(select(Host).where(Host.host_id == host_id))
            host = host_result.scalar_one_or_none()
            if host:
                host.risk_score = score
                await db.commit()

    _run(_inner())


# ── AI analysis tasks ─────────────────────────────────────────────────────────

@celery_app.task(name="analyze_event_ai")
def analyze_event_ai(event_id: str, event_data: dict):
    result = ai_analyst.analyze_event(event_data)
    r = _redis()
    r.publish("rsentry:ai", json.dumps({
        "type": "ai_analysis",
        "event_id": event_id,
        **result,
    }))

    if result.get("analysis_failed"):
        return

    if result.get("risk_level") == "LOW" or result.get("threat_type") == "Benign":
        auto_ack_by_event.delay(event_id)


@celery_app.task(name="analyze_alert_ai")
def analyze_alert_ai(alert_id: str, event_data: dict):
    result = ai_analyst.analyze_alert(event_data)
    r = _redis()
    r.publish("rsentry:ai", json.dumps({
        "type": "ai_analysis",
        "alert_id": alert_id,
        **result,
    }))

    if result.get("analysis_failed"):
        return

    if result.get("risk_level") == "LOW" or result.get("threat_type") == "Benign":
        _run(_ack_alert_by_id(alert_id))


async def _ack_alert_by_id(alert_id: str):
    _, SessionLocal = _get_engine()
    async with SessionLocal() as db:
        result = await db.execute(
            select(Alert).where(
                Alert.id == uuid.UUID(alert_id),
                Alert.acknowledged == False,
            )
        )
        alert = result.scalar_one_or_none()
        if alert:
            alert.acknowledged = True
            alert.resolved_at = datetime.now(timezone.utc)
            await db.commit()
            _redis().publish("rsentry:alerts", json.dumps({
                "type": "alert_acked",
                "alert_id": alert_id,
                "host_id": alert.host_id,
                "reason": "AI_BENIGN",
            }))


@celery_app.task(name="publish_markov_analysis")
def publish_markov_analysis(event_id: str):
    _redis().publish("rsentry:ai", json.dumps({
        "type": "ai_analysis",
        "event_id": event_id,
        "threat_type": "Benign",
        "technique": "Markov Chain Repositioning",
        "language_or_tool": "Python",
        "behavior_summary": "Internal Markov chain module repositioned canary files to predicted hotspot locations. This is a normal defensive operation.",
        "risk_level": "LOW",
        "recommendation": "No action required. Canary files have been repositioned automatically.",
        "confidence": "HIGH",
    }))


# ── Auto-acknowledge tasks ────────────────────────────────────────────────────

@celery_app.task(name="auto_ack_containment")
def auto_ack_containment(host_id: str):
    async def _inner():
        _, SessionLocal = _get_engine()
        async with SessionLocal() as db:
            result = await db.execute(
                select(Alert).where(
                    Alert.host_id == host_id,
                    Alert.severity == Severity.CRITICAL,
                    Alert.acknowledged == False,
                )
            )
            alerts = result.scalars().all()
            now = datetime.now(timezone.utc)
            for alert in alerts:
                alert.acknowledged = True
                alert.resolved_at = now
            await db.commit()

        _redis().publish("rsentry:alerts", json.dumps({
            "type": "alerts_acked",
            "host_id": host_id,
            "reason": "CONTAINMENT_COMPLETE",
        }))

    _run(_inner())


@celery_app.task(name="analyze_health_ai")
def analyze_health_ai(recent_events: list):
    result = ai_analyst.analyze_system_health(recent_events)
    _redis().publish("rsentry:ai", json.dumps({
        "type": "health_analysis",
        **result,
    }))


@celery_app.task(name="auto_ack_by_event")
def auto_ack_by_event(event_id: str):
    async def _inner():
        _, SessionLocal = _get_engine()
        async with SessionLocal() as db:
            result = await db.execute(
                select(Alert).where(
                    Alert.event_id == uuid.UUID(event_id),
                    Alert.acknowledged == False,
                )
            )
            alert = result.scalar_one_or_none()
            if alert:
                alert.acknowledged = True
                alert.resolved_at = datetime.now(timezone.utc)
                await db.commit()
                _redis().publish("rsentry:alerts", json.dumps({
                    "type": "alert_acked",
                    "alert_id": str(alert.id),
                    "host_id": alert.host_id,
                    "reason": "AI_BENIGN",
                }))

    _run(_inner())
