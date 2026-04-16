"""
tasks.py — Celery workers for async processing.
"""
import asyncio
import logging
import os

from celery import Celery
from sqlalchemy import select

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "rsentry",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)


@celery_app.task(name="push_alert_ws", bind=True, max_retries=3)
def push_alert_ws(self, alert_id: str, host_id: str, severity: str, event_type: str = ""):
    """Push a new alert notification to all connected WebSocket clients via Redis pub/sub."""
    try:
        from backend.routers.ws import publish_to_channel
        payload = {
            "type": "new_alert",
            "alert_id": alert_id,
            "host_id": host_id,
            "severity": severity,
            "event_type": event_type,
        }
        asyncio.run(publish_to_channel("rsentry:alerts", payload))
        logger.info("WS alert pushed: %s", alert_id)
    except Exception as exc:
        logger.error("push_alert_ws failed: %s", exc)
        raise self.retry(exc=exc, countdown=2)


@celery_app.task(name="push_event_ws", bind=True, max_retries=2)
def push_event_ws(self, event_id: str, host_id: str, event_type: str,
                  severity: str, file_path: str, entropy_delta: float,
                  canary_hit: bool, process_name: str, details: dict):
    """Push every event to WebSocket for live dashboard updates."""
    try:
        from backend.routers.ws import publish_to_channel
        payload = {
            "type": "new_event",
            "event_id": event_id,
            "host_id": host_id,
            "event_type": event_type,
            "severity": severity,
            "file_path": file_path,
            "entropy_delta": entropy_delta,
            "canary_hit": canary_hit,
            "process_name": process_name,
            "details": details or {},
        }
        asyncio.run(publish_to_channel("rsentry:events", payload))
    except Exception as exc:
        logger.error("push_event_ws failed: %s", exc)
        raise self.retry(exc=exc, countdown=1)


@celery_app.task(name="analyze_event_ai", bind=True, max_retries=2)
def analyze_event_ai(self, event_id: str, event_data: dict):
    """Send a HIGH/CRITICAL event to Gemini for AI threat analysis and store result."""
    try:
        from backend.services.ai_analyst import analyze_event
        from backend.routers.ws import publish_to_channel
        result = analyze_event(event_data)
        result["event_id"] = event_id
        result["type"] = "ai_analysis"
        asyncio.run(publish_to_channel("rsentry:ai", result))
        logger.info("AI analysis complete for event %s: %s", event_id, result.get("threat_type"))
    except Exception as exc:
        logger.error("analyze_event_ai failed: %s", exc)
        raise self.retry(exc=exc, countdown=5)


@celery_app.task(name="analyze_health_ai", bind=True, max_retries=1)
def analyze_health_ai(self, recent_events: list):
    """Analyze overall system health using Gemini."""
    try:
        from backend.services.ai_analyst import analyze_system_health
        from backend.routers.ws import publish_to_channel
        result = analyze_system_health(recent_events)
        result["type"] = "health_analysis"
        asyncio.run(publish_to_channel("rsentry:ai", result))
        logger.info("Health analysis: %s", result.get("status"))
    except Exception as exc:
        logger.error("analyze_health_ai failed: %s", exc)


@celery_app.task(name="update_host_risk", bind=True, max_retries=3)
def update_host_risk(self, host_id: str):
    """Recompute and persist the risk score for a host."""
    try:
        asyncio.run(_update_host_risk_async(host_id))
    except Exception as exc:
        logger.error("update_host_risk failed: %s", exc)
        raise self.retry(exc=exc, countdown=5)


async def _update_host_risk_async(host_id: str):
    from backend.models.database import AsyncSessionLocal
    from backend.models.schemas import Host, Alert, Severity

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 2,
    }

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Host).where(Host.host_id == host_id))
        host = result.scalar_one_or_none()
        if host is None:
            return

        alerts_result = await db.execute(
            select(Alert).where(
                Alert.host_id == host_id,
                Alert.acknowledged == False,  # noqa: E712
            )
        )
        alerts = alerts_result.scalars().all()

        score = sum(SEVERITY_WEIGHTS.get(a.severity, 0) for a in alerts)
        host.risk_score = min(float(score), 100.0)
        await db.commit()
        logger.info("Host %s risk_score updated to %.1f", host_id, host.risk_score)
