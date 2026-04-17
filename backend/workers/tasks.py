"""
tasks.py — Celery workers for async processing.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone

from celery import Celery
from dotenv import load_dotenv

load_dotenv()
from sqlalchemy import select

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://rsentry:rsentry_pass@localhost:5432/rsentry_db")

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


def _run(coro):
    """Run a coroutine in a fresh isolated event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_session():
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import NullPool
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return engine, Session


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
    """Send a HIGH/CRITICAL/MEDIUM event to AI for threat analysis."""
    try:
        from backend.services.ai_analyst import analyze_event
        from backend.routers.ws import publish_to_channel
        result = analyze_event(event_data)

        # If NVIDIA API failed, do not publish an error card — pending card will expire naturally
        if result.get("analysis_failed"):
            logger.warning("AI analysis failed for event %s: %s", event_id, result.get("reason"))
            return

        result["event_id"] = event_id
        result["type"] = "ai_analysis"
        asyncio.run(publish_to_channel("rsentry:ai", result))
        logger.info("AI analysis complete for event %s: %s", event_id, result.get("threat_type"))

        # Auto-acknowledge if AI determines this is Benign or LOW risk
        if result.get("threat_type") == "Benign" or result.get("risk_level") == "LOW":
            auto_ack_by_event.delay(event_id)
            logger.info("Auto-acknowledging alert for event %s (AI: %s)", event_id, result.get("threat_type"))

    except Exception as exc:
        logger.error("analyze_event_ai failed: %s", exc)
        raise self.retry(exc=exc, countdown=5)


@celery_app.task(name="analyze_alert_ai", bind=True, max_retries=2)
def analyze_alert_ai(self, event_id: str, event_data: dict):
    """Analyze an alert on-demand using NVIDIA_API_KEY_ALERTS — separate key and rate limit from live events."""
    try:
        from backend.services.ai_analyst import analyze_alert
        from backend.routers.ws import publish_to_channel
        result = analyze_alert(event_data)

        if result.get("analysis_failed"):
            logger.warning("Alert AI analysis failed for event %s: %s", event_id, result.get("reason"))
            return

        result["event_id"] = event_id
        result["type"] = "ai_analysis"
        asyncio.run(publish_to_channel("rsentry:ai", result))
        logger.info("Alert AI analysis complete for event %s: %s", event_id, result.get("threat_type"))

        # Auto-acknowledge the alert if AI says it is Benign or LOW risk (false positive)
        if result.get("threat_type") == "Benign" or result.get("risk_level") == "LOW":
            auto_ack_by_event.delay(event_id)
            logger.info("Auto-acknowledging false positive alert for event %s", event_id)

    except Exception as exc:
        logger.error("analyze_alert_ai failed: %s", exc)
        raise self.retry(exc=exc, countdown=5)


@celery_app.task(name="publish_markov_analysis", bind=True, max_retries=1)
def publish_markov_analysis(self, event_id: str):
    """Publish a pre-built analysis for Markov chain reposition events — no NVIDIA API call needed."""
    try:
        from backend.routers.ws import publish_to_channel
        result = {
            "type": "ai_analysis",
            "event_id": event_id,
            "threat_type": "Markov Chain — Adaptive Canary Repositioning",
            "technique": "Canary File Relocation",
            "language_or_tool": "Internal — Markov Chain Module",
            "behavior_summary": "The Markov chain adaptive repositioner moved canary files to predicted hotspot directories based on observed access patterns. This is a normal internal defensive operation, not a threat.",
            "risk_level": "LOW",
            "recommendation": "No action required. The system is proactively adapting canary positions.",
            "confidence": "HIGH",
            "markov_action": True,
        }
        asyncio.run(publish_to_channel("rsentry:ai", result))
        logger.info("Published Markov analysis for event %s", event_id)
    except Exception as exc:
        logger.error("publish_markov_analysis failed: %s", exc)
        raise self.retry(exc=exc, countdown=2)


@celery_app.task(name="analyze_health_ai", bind=True, max_retries=1)
def analyze_health_ai(self, recent_events: list):
    """Analyze overall system health using NVIDIA AI."""
    from backend.services.ai_analyst import analyze_system_health
    from backend.routers.ws import publish_to_channel
    try:
        result = analyze_system_health(recent_events)
        result["type"] = "health_analysis"
        _run(publish_to_channel("rsentry:ai", result))
        logger.info("Health analysis: %s", result.get("status"))
    except Exception as exc:
        logger.error("analyze_health_ai failed: %s", exc)
        fallback = {
            "type": "health_analysis",
            "status": "UNKNOWN",
            "threat_type": "—",
            "behavior_summary": f"Health analysis failed: {str(exc)[:100]}",
            "risk_level": "UNKNOWN",
            "recommendation": "Check NVIDIA_API_KEY and Celery logs.",
            "confidence": "LOW",
        }
        try:
            _run(publish_to_channel("rsentry:ai", fallback))
        except Exception:
            pass


@celery_app.task(name="auto_ack_by_event", bind=True, max_retries=2)
def auto_ack_by_event(self, event_id: str):
    """Auto-acknowledge the alert linked to a specific event (AI said Benign/LOW)."""
    try:
        _run(_auto_ack_by_event_async(event_id))
    except Exception as exc:
        logger.error("auto_ack_by_event failed: %s", exc)
        raise self.retry(exc=exc, countdown=3)


async def _auto_ack_by_event_async(event_id: str):
    import uuid
    from backend.models.schemas import Alert
    engine, Session = _make_session()
    try:
        async with Session() as db:
            result = await db.execute(
                select(Alert).where(
                    Alert.event_id == uuid.UUID(event_id),
                    Alert.acknowledged == False,  # noqa: E712
                )
            )
            alert = result.scalar_one_or_none()
            if alert:
                alert.acknowledged = True
                alert.resolved_at = datetime.now(timezone.utc)
                await db.commit()
                logger.info("Auto-acknowledged alert for event %s", event_id)
    finally:
        await engine.dispose()


@celery_app.task(name="auto_ack_containment", bind=True, max_retries=2)
def auto_ack_containment(self, host_id: str):
    """Auto-acknowledge all CRITICAL alerts for a host after containment is complete."""
    try:
        _run(_auto_ack_containment_async(host_id))
    except Exception as exc:
        logger.error("auto_ack_containment failed: %s", exc)
        raise self.retry(exc=exc, countdown=3)


async def _auto_ack_containment_async(host_id: str):
    from backend.models.schemas import Alert, Severity
    engine, Session = _make_session()
    try:
        async with Session() as db:
            result = await db.execute(
                select(Alert).where(
                    Alert.host_id == host_id,
                    Alert.severity == Severity.CRITICAL,
                    Alert.acknowledged == False,  # noqa: E712
                )
            )
            alerts = result.scalars().all()
            now = datetime.now(timezone.utc)
            for alert in alerts:
                alert.acknowledged = True
                alert.resolved_at = now
            await db.commit()
            logger.info("Auto-acknowledged %d CRITICAL alerts for host %s after containment", len(alerts), host_id)
    finally:
        await engine.dispose()


@celery_app.task(name="update_host_risk", bind=True, max_retries=3)
def update_host_risk(self, host_id: str):
    """Recompute and persist the risk score for a host."""
    try:
        _run(_update_host_risk_async(host_id))
    except Exception as exc:
        logger.error("update_host_risk failed: %s", exc)
        raise self.retry(exc=exc, countdown=5)


async def _update_host_risk_async(host_id: str):
    from backend.models.schemas import Host, Alert, Severity

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 2,
    }

    engine, Session = _make_session()
    try:
        async with Session() as db:
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
    finally:
        await engine.dispose()
