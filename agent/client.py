"""
client.py — REST client that sends agent events to the Hybrid R-Sentry backend.
"""
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
HOST_ID = os.getenv("HOST_ID", socket.gethostname())
RETRY_COUNT = 3
RETRY_DELAY = 1.5  # seconds


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity(
    canary_hit: bool,
    combined_score: float,
    entropy_delta: float,
) -> str:
    if canary_hit:
        return "CRITICAL"
    if combined_score >= 70:
        return "CRITICAL"
    if combined_score >= 40:
        return "HIGH"
    if entropy_delta > 3.5:
        return "MEDIUM"
    return "LOW"


def build_payload(
    event_type: str,
    pid: int,
    process_name: str,
    file_path: str,
    lineage_score: float,
    entropy_delta: float,
    canary_hit: bool,
    details: Optional[dict] = None,
    severity: Optional[str] = None,
) -> dict:
    """
    Construct the canonical event payload.
    Severity is auto-computed if not provided.
    """
    combined_score = lineage_score * 0.5 + (entropy_delta / 8.0) * 100 * 0.5
    auto_severity = _severity(canary_hit, combined_score, entropy_delta)

    return {
        "host_id": HOST_ID,
        "timestamp": _now_iso(),
        "event_type": event_type,
        "severity": severity or auto_severity,
        "pid": pid,
        "process_name": process_name,
        "file_path": file_path,
        "lineage_score": round(lineage_score, 2),
        "entropy_delta": round(entropy_delta, 4),
        "canary_hit": canary_hit,
        "details": details or {},
    }


class AgentClient:
    """Synchronous HTTP client (uses httpx for simplicity in watchdog threads)."""

    def __init__(self, backend_url: str = BACKEND_URL, host_id: str = HOST_ID):
        self.backend_url = backend_url.rstrip("/")
        self.host_id = host_id
        self._client = httpx.Client(
            timeout=httpx.Timeout(10.0, connect=3.0),
            headers={"Content-Type": "application/json", "X-Agent-Host": host_id},
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post_with_retry(self, endpoint: str, payload: dict) -> Optional[dict]:
        url = f"{self.backend_url}{endpoint}"
        for attempt in range(1, RETRY_COUNT + 1):
            try:
                resp = self._client.post(url, json=payload)
                resp.raise_for_status()
                logger.debug("Event posted OK [%d] attempt=%d", resp.status_code, attempt)
                return resp.json()
            except httpx.HTTPStatusError as exc:
                logger.warning("HTTP %d posting event: %s", exc.response.status_code, exc)
                break
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                logger.warning("Attempt %d/%d failed: %s", attempt, RETRY_COUNT, exc)
                if attempt < RETRY_COUNT:
                    time.sleep(RETRY_DELAY * attempt)
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_event(
        self,
        event_type: str,
        pid: int,
        process_name: str,
        file_path: str,
        lineage_score: float,
        entropy_delta: float,
        canary_hit: bool,
        details: Optional[dict] = None,
        severity: Optional[str] = None,
    ) -> Optional[dict]:
        payload = build_payload(
            event_type=event_type,
            pid=pid,
            process_name=process_name,
            file_path=file_path,
            lineage_score=lineage_score,
            entropy_delta=entropy_delta,
            canary_hit=canary_hit,
            details=details,
            severity=severity,
        )
        logger.info(
            "→ %s | sev=%s | pid=%d | canary=%s | lineage=%.1f | entropy_delta=%.3f",
            event_type, payload["severity"], pid, canary_hit, lineage_score, entropy_delta,
        )
        return self._post_with_retry("/api/events", payload)

    def send_heartbeat(self) -> Optional[dict]:
        payload = build_payload(
            event_type="HEARTBEAT",
            pid=os.getpid(),
            process_name="rsentry-agent",
            file_path="",
            lineage_score=0.0,
            entropy_delta=0.0,
            canary_hit=False,
            details={"version": "1.0.0"},
            severity="LOW",
        )
        return self._post_with_retry("/api/events", payload)

    def send_containment_triggered(self, pid: int, process_name: str, file_path: str,
                                    lineage_score: float, entropy_delta: float) -> Optional[dict]:
        return self.send_event(
            event_type="CONTAINMENT_TRIGGERED",
            pid=pid,
            process_name=process_name,
            file_path=file_path,
            lineage_score=lineage_score,
            entropy_delta=entropy_delta,
            canary_hit=True,
            severity="CRITICAL",
        )

    def send_containment_complete(self, pid: int, result_dict: dict) -> Optional[dict]:
        return self.send_event(
            event_type="CONTAINMENT_COMPLETE",
            pid=pid,
            process_name=result_dict.get("name", ""),
            file_path="",
            lineage_score=0.0,
            entropy_delta=0.0,
            canary_hit=False,
            details=result_dict,
            severity="CRITICAL",
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
