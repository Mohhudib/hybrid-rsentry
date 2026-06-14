"""
alerts.py — Alert management endpoints + evidence retrieval.
"""
import asyncio
import csv
import io
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.database import get_db
from backend.models.schemas import (
    Alert, Event, Evidence, EvidenceCreate, EvidenceResponse,
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


@router.get("/counts")
async def alert_counts(db: AsyncSession = Depends(get_db)):
    """Return active (unacknowledged) counts and 24h total counts by severity."""
    # Active (unacknowledged) counts
    sev_rows = (await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.acknowledged == False)  # noqa: E712
        .group_by(Alert.severity)
    )).all()
    counts = {sev.value: 0 for sev in Severity}
    for sev, count in sev_rows:
        counts[sev.value] = count
    counts["TOTAL"] = sum(counts[sev.value] for sev in Severity)

    # 24h total counts (all alerts regardless of ack status)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    sev_24h_rows = (await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.created_at >= cutoff)
        .group_by(Alert.severity)
    )).all()
    counts_24h: dict = {sev.value: 0 for sev in Severity}
    for sev, cnt in sev_24h_rows:
        counts_24h[sev.value] = cnt
    counts["CRITICAL_24H"] = counts_24h.get("CRITICAL", 0)
    counts["HIGH_24H"]     = counts_24h.get("HIGH", 0)
    counts["MEDIUM_24H"]   = counts_24h.get("MEDIUM", 0)
    counts["TOTAL_24H"]    = sum(counts_24h.values())
    return counts



@router.get("/with-events")
async def list_alerts_with_events(
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    limit: int = Query(500),
    db: AsyncSession = Depends(get_db),
):
    """Return alerts joined with their event data for PDF report generation."""
    stmt = (
        select(Alert, Event)
        .join(Event, Alert.event_id == Event.id)
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    if severity and severity != "ALL":
        stmt = stmt.where(Alert.severity == severity)
    if acknowledged is not None:
        stmt = stmt.where(Alert.acknowledged == acknowledged)
    if date_from:
        try:
            stmt = stmt.where(Alert.created_at >= datetime.fromisoformat(date_from))
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid date_from format, expected ISO 8601")
    if date_to:
        try:
            stmt = stmt.where(Alert.created_at <= datetime.fromisoformat(date_to))
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid date_to format, expected ISO 8601")

    rows = (await db.execute(stmt)).all()
    result = []
    for alert, event in rows:
        result.append({
            "id":           str(alert.id),
            "event_id":     str(alert.event_id),
            "host_id":      alert.host_id,
            "severity":     alert.severity.value,
            "acknowledged": alert.acknowledged,
            "created_at":   alert.created_at.isoformat() if alert.created_at else None,
            "resolved_at":  alert.resolved_at.isoformat() if alert.resolved_at else None,
            "event_type":   event.event_type.value,
            "pid":          event.pid,
            "process_name": event.process_name,
            "file_path":    event.file_path,
            "lineage_score":event.lineage_score,
            "entropy_delta":event.entropy_delta,
            "canary_hit":   event.canary_hit,
            "timestamp":    event.timestamp.isoformat() if event.timestamp else None,
            "details":      event.details or {},
        })
    return result

@router.post("/clear-all")
async def clear_all_alerts(db: AsyncSession = Depends(get_db)):
    """Acknowledge all open alerts and set resolved_at — equivalent to the manual SQL clear command."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(Alert)
        .where(Alert.acknowledged == False)  # noqa: E712
        .values(acknowledged=True, resolved_at=now)
        .returning(Alert.host_id)
    )
    host_ids = list({row[0] for row in result.fetchall()})
    await db.commit()
    from backend.workers.tasks import update_host_risk
    for host_id in host_ids:
        update_host_risk.delay(host_id)
    return {"cleared": len(host_ids) > 0, "hosts_updated": len(host_ids)}


@router.post("/acknowledge-all")
async def acknowledge_all_alerts(db: AsyncSession = Depends(get_db)):
    """Bulk-acknowledge every open alert and trigger risk recalculation for all affected hosts."""
    host_rows = (await db.execute(
        select(Alert.host_id).where(Alert.acknowledged == False).distinct()  # noqa: E712
    )).scalars().all()
    now = datetime.now(timezone.utc)
    await db.execute(
        update(Alert)
        .where(Alert.acknowledged == False)  # noqa: E712
        .values(acknowledged=True, resolved_at=now)
    )
    await db.commit()
    from backend.workers.tasks import update_host_risk
    for host_id in host_rows:
        update_host_risk.delay(host_id)
    return {"acknowledged": len(host_rows) > 0, "hosts_updated": len(host_rows)}


_EXPORT_HEADERS = [
    "Alert ID", "Host", "Severity", "Status",
    "Detected At", "Resolved At",
    "Event Type", "Event Time", "PID", "Process",
    "File Path", "Entropy Delta", "Lineage Score", "Canary Hit",
]


def _fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""


def _yn(val):
    return "Yes" if val else "No"


async def _fetch_export_rows(db, severity, acknowledged, limit):
    stmt = (
        select(Alert, Event)
        .join(Event, Alert.event_id == Event.id)
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    if severity and severity != "ALL":
        stmt = stmt.where(Alert.severity == severity)
    if acknowledged is not None:
        stmt = stmt.where(Alert.acknowledged == acknowledged)
    rows = (await db.execute(stmt)).all()
    data = []
    for alert, event in rows:
        data.append([
            str(alert.id)[:8],
            alert.host_id,
            alert.severity.value,
            "Acknowledged" if alert.acknowledged else "Open",
            _fmt_dt(alert.created_at),
            _fmt_dt(alert.resolved_at),
            event.event_type.value if event else "",
            _fmt_dt(event.timestamp) if event else "",
            str(event.pid) if event else "",
            event.process_name if event else "",
            event.file_path if event else "",
            f"{event.entropy_delta:.2f}" if event and event.entropy_delta is not None else "",
            f"{event.lineage_score:.2f}" if event and event.lineage_score is not None else "",
            _yn(event.canary_hit) if event else "",
        ])
    return data


@router.get("/export/csv")
async def export_alerts_csv(
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(1000, le=5000),
    db: AsyncSession = Depends(get_db),
):
    """Export alerts as a standard CSV file (opens in Excel / Google Sheets)."""
    data_rows = await _fetch_export_rows(db, severity, acknowledged, limit)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_EXPORT_HEADERS)
    writer.writerows(data_rows)
    buf.seek(0)
    filename = f"rsentry-alerts-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/txt")
async def export_alerts_txt(
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(1000, le=5000),
    db: AsyncSession = Depends(get_db),
):
    """Export alerts as a human-readable aligned text table."""
    data_rows = await _fetch_export_rows(db, severity, acknowledged, limit)
    col_widths = [len(h) for h in _EXPORT_HEADERS]
    for row in data_rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    def _pad_row(cells):
        return "  |  ".join(str(c).ljust(col_widths[i]) for i, c in enumerate(cells))

    separator = "-+-".join("-" * (w + 2) for w in col_widths)
    buf = io.StringIO()
    buf.write(_pad_row(_EXPORT_HEADERS) + "\n")
    buf.write(separator + "\n")
    for row in data_rows:
        buf.write(_pad_row(row) + "\n")
    buf.seek(0)
    filename = f"rsentry-alerts-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.txt"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


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
    from backend.workers.tasks import update_host_risk
    update_host_risk.delay(alert.host_id)
    return alert


@router.post("/{alert_id}/analyze")
async def analyze_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Trigger on-demand AI analysis for an alert. Auto-acknowledges if AI says Benign/LOW."""
    alert_result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = alert_result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(404, "Alert not found")

    event_data: dict = {
        "event_type": "UNKNOWN",
        "severity": alert.severity.value,
        "host_id": alert.host_id,
        "file_path": None,
        "process_name": None,
        "pid": 0,
        "entropy_delta": 0,
        "lineage_score": 0,
        "canary_hit": False,
        "details": {},
    }
    if alert.event_id:
        ev_result = await db.execute(select(Event).where(Event.id == alert.event_id))
        ev = ev_result.scalar_one_or_none()
        if ev:
            event_data = {
                "event_type": ev.event_type.value,
                "severity": ev.severity.value,
                "host_id": ev.host_id,
                "file_path": ev.file_path,
                "process_name": ev.process_name,
                "pid": ev.pid,
                "entropy_delta": ev.entropy_delta or 0,
                "lineage_score": ev.lineage_score or 0,
                "canary_hit": ev.canary_hit or False,
                "details": ev.details or {},
            }

    # Pass event_id so the AI Analyst panel can match the result to the pending event
    if alert.event_id:
        event_data["event_id"] = str(alert.event_id)

    from backend.workers.tasks import analyze_alert_ai
    analyze_alert_ai.delay(str(alert_id), event_data)
    return {"queued": True, "alert_id": str(alert_id)}


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

    # جيب الـ AI analysis من Redis لو موجود
    from backend.services.ai_analyst import _get_redis
    ai_analysis = None
    try:
        r = _get_redis()
        ai_data = await asyncio.to_thread(r.get, f"rsentry:ai_analysis:{alert.event_id}")
        if ai_data:
            import json as _json
            ai_analysis = _json.loads(ai_data)
    except Exception:
        pass

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
        "ai_analysis": ai_analysis,
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
