"""
alerts.py — Alert management endpoints + evidence retrieval.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.database import get_db
from backend.models.schemas import (
    Alert, Evidence, EvidenceCreate, EvidenceResponse,
    AlertResponse, Severity,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    host_id: Optional[str] = Query(None),
    severity: Optional[Severity] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    q = select(Alert).order_by(desc(Alert.created_at)).offset(offset).limit(limit)
    if host_id:
        q = q.where(Alert.host_id == host_id)
    if severity:
        q = q.where(Alert.severity == severity)
    if acknowledged is not None:
        q = q.where(Alert.acknowledged == acknowledged)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(404, "Alert not found")
    alert.acknowledged = True
    alert.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/{alert_id}/evidence", response_model=list[EvidenceResponse])
async def get_alert_evidence(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Evidence).where(Evidence.alert_id == alert_id)
    )
    return result.scalars().all()


@router.post("/{alert_id}/evidence", response_model=EvidenceResponse, status_code=201)
async def attach_evidence(
    alert_id: uuid.UUID,
    payload: EvidenceCreate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(404, "Alert not found")

    evidence = Evidence(
        alert_id=alert_id,
        pid=payload.pid,
        evidence_dir=payload.evidence_dir,
        files=payload.files,
        iptables_rule=payload.iptables_rule,
        raw_data=payload.raw_data,
    )
    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)
    return evidence


@router.get("/{alert_id}/forensic-export")
async def forensic_export(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Export full alert + evidence as JSON for incident response."""
    alert_result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = alert_result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(404, "Alert not found")

    evidence_result = await db.execute(
        select(Evidence).where(Evidence.alert_id == alert_id)
    )
    evidence_list = evidence_result.scalars().all()

    return {
        "alert": {
            "id": str(alert.id),
            "event_id": str(alert.event_id),
            "host_id": alert.host_id,
            "severity": alert.severity.value,
            "acknowledged": alert.acknowledged,
            "created_at": alert.created_at.isoformat(),
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        },
        "evidence": [
            {
                "id": str(e.id),
                "pid": e.pid,
                "evidence_dir": e.evidence_dir,
                "files": e.files,
                "iptables_rule": e.iptables_rule,
                "raw_data": e.raw_data,
                "captured_at": e.captured_at.isoformat(),
            }
            for e in evidence_list
        ],
    }
