"""
hosts.py — Host inventory and risk endpoints.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.database import get_db
from backend.models.schemas import Host, Event, Alert, HostResponse, Severity

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("", response_model=list[HostResponse])
async def list_hosts(
    contained: Optional[bool] = Query(None),
    limit: int = Query(50, le=500),
    db: AsyncSession = Depends(get_db),
):
    q = select(Host).order_by(desc(Host.last_seen)).limit(limit)
    if contained is not None:
        q = q.where(Host.is_contained == contained)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{host_id}", response_model=HostResponse)
async def get_host(host_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Host).where(Host.host_id == host_id))
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(404, "Host not found")
    return host


@router.get("/{host_id}/risk")
async def host_risk_summary(host_id: str, db: AsyncSession = Depends(get_db)):
    """Aggregate risk metrics for a host."""
    host_result = await db.execute(select(Host).where(Host.host_id == host_id))
    host = host_result.scalar_one_or_none()
    if host is None:
        raise HTTPException(404, "Host not found")

    # Count alerts by severity
    alert_counts = {}
    for sev in Severity:
        count_result = await db.execute(
            select(func.count()).select_from(Alert).where(
                Alert.host_id == host_id,
                Alert.severity == sev,
                Alert.acknowledged == False,  # noqa: E712
            )
        )
        alert_counts[sev.value] = count_result.scalar_one()

    # Recent critical events
    recent_result = await db.execute(
        select(Event)
        .where(Event.host_id == host_id, Event.severity == Severity.CRITICAL)
        .order_by(desc(Event.timestamp))
        .limit(5)
    )
    recent_critical = recent_result.scalars().all()

    return {
        "host_id": host_id,
        "risk_score": host.risk_score,
        "is_contained": host.is_contained,
        "last_seen": host.last_seen.isoformat(),
        "open_alerts": alert_counts,
        "recent_critical_events": [
            {
                "id": str(e.id),
                "event_type": e.event_type.value,
                "timestamp": e.timestamp.isoformat(),
                "file_path": e.file_path,
                "process_name": e.process_name,
            }
            for e in recent_critical
        ],
    }


@router.post("/{host_id}/contain")
async def contain_host(host_id: str, db: AsyncSession = Depends(get_db)):
    """Mark a host as contained (dashboard manual override)."""
    result = await db.execute(select(Host).where(Host.host_id == host_id))
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(404, "Host not found")
    host.is_contained = True
    await db.commit()
    return {"status": "contained", "host_id": host_id}


@router.delete("/{host_id}/contain")
async def release_host(host_id: str, db: AsyncSession = Depends(get_db)):
    """Release a host from containment."""
    result = await db.execute(select(Host).where(Host.host_id == host_id))
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(404, "Host not found")
    host.is_contained = False
    await db.commit()
    return {"status": "released", "host_id": host_id}
