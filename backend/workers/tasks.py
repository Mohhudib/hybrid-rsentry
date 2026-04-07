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
def push_alert_ws(self, alert_id: str, host_id: str, severity: str):
    """Push a new alert notification to all connected WebSocket clients via Redis pub/sub."""
    try:
        from backend.routers.ws import publish_alert
        payload = {
            "type": "new_alert",
            "alert_id": alert_id,
            "host_id": host_id,
            "severity": severity,
        }
        asyncio.run(publish_alert(payload))
        logger.info("WS alert pushed: %s", alert_id)
    except Exception as exc:
        logger.error("push_alert_ws failed: %s", exc)
        raise self.retry(exc=exc, countdown=2)


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
