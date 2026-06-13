"""
tests/unit/backend/test_routers_alerts.py
Tests for backend/routers/alerts.py — list, counts (GROUP BY assembly), ack, get.
"""
import uuid
from datetime import datetime, timezone

import pytest

from backend.models.schemas import Host, Event, Alert, Severity, EventType


async def _seed_alert(session, host_id="HOST1", severity=Severity.CRITICAL, acknowledged=False):
    """Create a host + event + alert chain, return the alert."""
    existing = None
    from sqlalchemy import select
    existing = (await session.execute(select(Host).where(Host.host_id == host_id))).scalar_one_or_none()
    if existing is None:
        session.add(Host(host_id=host_id))
        await session.flush()
    event = Event(
        host_id=host_id, timestamp=datetime.now(timezone.utc),
        event_type=EventType.CANARY_TOUCHED, severity=severity,
    )
    session.add(event)
    await session.flush()
    alert = Alert(event_id=event.id, host_id=host_id, severity=severity, acknowledged=acknowledged)
    session.add(alert)
    await session.commit()
    return alert


@pytest.mark.asyncio
async def test_list_alerts_empty(client):
    r = await client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_list_alerts_returns_seeded(client, db_session):
    await _seed_alert(db_session, severity=Severity.HIGH)
    r = await client.get("/api/alerts")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_list_alerts_filter_by_severity(client, db_session):
    await _seed_alert(db_session, severity=Severity.CRITICAL)
    await _seed_alert(db_session, severity=Severity.LOW)
    r = await client.get("/api/alerts", params={"severity": "CRITICAL"})
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1 and body[0]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_list_alerts_limit_cap(client):
    # limit > 500 must be rejected by Query(le=500)
    r = await client.get("/api/alerts", params={"limit": 9999})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_counts_all_zero_when_empty(client):
    r = await client.get("/api/alerts/counts")
    assert r.status_code == 200
    body = r.json()
    # GROUP BY assembly must still return every severity key + TOTAL,
    # plus the 24h rollup keys the dashboard MetricsStrip consumes.
    assert body == {
        "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "TOTAL": 0,
        "CRITICAL_24H": 0, "HIGH_24H": 0, "MEDIUM_24H": 0, "TOTAL_24H": 0,
    }


@pytest.mark.asyncio
async def test_counts_group_by_assembly(client, db_session):
    await _seed_alert(db_session, severity=Severity.CRITICAL)
    await _seed_alert(db_session, severity=Severity.CRITICAL)
    await _seed_alert(db_session, severity=Severity.HIGH)
    r = await client.get("/api/alerts/counts")
    body = r.json()
    assert body["CRITICAL"] == 2
    assert body["HIGH"] == 1
    assert body["MEDIUM"] == 0
    assert body["TOTAL"] == 3  # sum across severities, not a separate query


@pytest.mark.asyncio
async def test_counts_excludes_acknowledged(client, db_session):
    await _seed_alert(db_session, severity=Severity.CRITICAL, acknowledged=True)
    await _seed_alert(db_session, severity=Severity.HIGH, acknowledged=False)
    r = await client.get("/api/alerts/counts")
    body = r.json()
    assert body["CRITICAL"] == 0  # acknowledged excluded
    assert body["HIGH"] == 1
    assert body["TOTAL"] == 1


@pytest.mark.asyncio
async def test_acknowledge_alert(client, db_session):
    alert = await _seed_alert(db_session)
    aid = str(alert.id)
    r = await client.patch(f"/api/alerts/{aid}/acknowledge")
    assert r.status_code == 200
    # counts should now drop it
    counts = (await client.get("/api/alerts/counts")).json()
    assert counts["TOTAL"] == 0


@pytest.mark.asyncio
async def test_get_alert_404(client):
    r = await client.get(f"/api/alerts/{uuid.uuid4()}")
    assert r.status_code == 404
