"""
events.py — POST /api/events (ingest agent payloads) + GET queries.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.database import get_db
from backend.models.schemas import (
    Alert, Event, Host,
    EventCreate, EventResponse, AlertResponse,
    Severity, EventType,
)
from backend.workers.tasks import push_alert_ws, push_event_ws, update_host_risk, analyze_event_ai

router = APIRouter(prefix="/api/events", tags=["events"])

ALERT_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


async def _upsert_host(db: AsyncSession, host_id: str) -> Host:
    result = await db.execute(select(Host).where(Host.host_id == host_id))
    host = result.scalar_one_or_none()
    if host is None:
        host = Host(host_id=host_id)
        db.add(host)
    host.last_seen = datetime.now(timezone.utc)
    await db.flush()
    return host


@router.post("", response_model=EventResponse, status_code=201)
async def ingest_event(payload: EventCreate, db: AsyncSession = Depends(get_db)):
    """Receive an event from the agent and persist it. Generates alerts for HIGH/CRITICAL."""

    await _upsert_host(db, payload.host_id)

    event = Event(
        host_id=payload.host_id,
        timestamp=payload.timestamp,
        event_type=payload.event_type,
        severity=payload.severity,
        pid=payload.pid,
        process_name=payload.process_name,
        file_path=payload.file_path,
        lineage_score=payload.lineage_score,
        entropy_delta=payload.entropy_delta,
        canary_hit=payload.canary_hit,
        details=payload.details,
    )
    db.add(event)
    await db.flush()

    # Auto-generate alert for HIGH/CRITICAL events
    alert: Optional[Alert] = None
    if payload.severity in ALERT_SEVERITIES:
        alert = Alert(
            event_id=event.id,
            host_id=payload.host_id,
            severity=payload.severity,
        )
        db.add(alert)
        await db.flush()

    await db.commit()
    await db.refresh(event)

    # Push every event live to dashboard
    push_event_ws.delay(
        str(event.id), payload.host_id, payload.event_type.value,
        payload.severity.value, payload.file_path, payload.entropy_delta,
        payload.canary_hit, payload.process_name, payload.details,
    )

    # Async tasks (fire-and-forget)
    if alert:
        push_alert_ws.delay(str(alert.id), payload.host_id,
                            payload.severity.value, payload.event_type.value)
        update_host_risk.delay(payload.host_id)
        # AI threat analysis for HIGH/CRITICAL events — skip internal system events
        sub_type = (payload.details or {}).get("sub_type", "")
        # Skip AI for internal system events:
        # - MARKOV_REPOSITION = Markov chain sending its heartbeat
        # - moved + pid==0 = Markov chain physically moving a canary file (watchdog on_moved)
        is_internal = (
            sub_type == "MARKOV_REPOSITION" or
            (sub_type == "moved" and payload.pid == 0)
        )
        if is_internal:
            pass  # Not a threat — Markov chain repositioning canary files
        else:
            analyze_event_ai.delay(str(event.id), {
                "event_type": payload.event_type.value,
                "severity": payload.severity.value,
                "host_id": payload.host_id,
                "file_path": payload.file_path,
                "process_name": payload.process_name,
                "pid": payload.pid,
                "entropy_delta": payload.entropy_delta,
                "lineage_score": payload.lineage_score,
                "canary_hit": payload.canary_hit,
                "details": payload.details,
            })

    return event


@router.get("", response_model=list[EventResponse])
async def list_events(
    host_id: Optional[str] = Query(None),
    severity: Optional[Severity] = Query(None),
    event_type: Optional[EventType] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    q = select(Event).order_by(desc(Event.timestamp)).offset(offset).limit(limit)
    if host_id:
        q = q.where(Event.host_id == host_id)
    if severity:
        q = q.where(Event.severity == severity)
    if event_type:
        q = q.where(Event.event_type == event_type)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(event_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if event is None:
        raise HTTPException(404, "Event not found")
    return event
