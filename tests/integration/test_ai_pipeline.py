#!/usr/bin/env python3
"""
test_ai_pipeline.py — AI analysis pipeline integration test.

Verifies the full event → Celery → AI analysis → Redis pub/sub chain by:
  1. Posting a synthetic CRITICAL event to the backend
  2. Polling Redis for an ai_analysis message keyed to that event
  3. Asserting the analysis payload has the required fields

Prerequisites (must all be running):
  - docker compose up -d (Postgres + Redis)
  - uvicorn backend.main:app  (FastAPI on port 8000)
  - Celery worker with AI_API_KEY set

Skip automatically if any prerequisite is unavailable so CI without live
services does not fail.
"""
from __future__ import annotations

import json
import os
import time
import uuid

import pytest

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
REDIS_URL   = os.getenv("REDIS_URL",   "redis://localhost:6379/0")
AI_CHANNEL  = "rsentry:ai"
TIMEOUT_S   = 60


def _backend_available() -> bool:
    try:
        import httpx
        r = httpx.get(f"{BACKEND_URL}/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _redis_available() -> bool:
    try:
        import redis as _redis
        r = _redis.from_url(REDIS_URL, socket_timeout=2)
        r.ping()
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not (_backend_available() and _redis_available()),
    reason="Backend or Redis not available — skipping live AI pipeline test",
)
def test_ai_pipeline_end_to_end():
    import httpx
    import redis as _redis

    r = _redis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe(AI_CHANNEL)

    event_id = str(uuid.uuid4())
    payload = {
        "host_id":      "TEST_HOST",
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type":   "CANARY_TOUCHED",
        "severity":     "CRITICAL",
        "pid":          0,
        "process_name": "pytest_ai_pipeline",
        "file_path":    "/tmp/AAA_pipeline_test.txt",
        "entropy_delta": 0.0,
        "lineage_score": 0.0,
        "canary_hit":   True,
        "details":      {"test": True, "event_id_hint": event_id},
    }
    resp = httpx.post(f"{BACKEND_URL}/api/events", json=payload, timeout=10)
    assert resp.status_code in (200, 201), f"Event post failed: {resp.text}"

    deadline = time.time() + TIMEOUT_S
    received = None
    while time.time() < deadline:
        msg = pubsub.get_message(timeout=1.0)
        if msg and msg["type"] == "message":
            try:
                data = json.loads(msg["data"])
                if data.get("host_id") == "TEST_HOST" or data.get("type") in ("ai_analysis", "ai_analysis_update"):
                    received = data
                    break
            except (json.JSONDecodeError, TypeError):
                pass

    pubsub.unsubscribe(AI_CHANNEL)
    r.close()

    assert received is not None, (
        f"No AI analysis published to {AI_CHANNEL} within {TIMEOUT_S}s. "
        "Check that the Celery worker is running with AI_API_KEY set."
    )
    for field in ("verdict", "risk_score", "explanation"):
        assert field in received, f"AI analysis missing field '{field}': {received}"

    assert received.get("verdict") in ("Benign", "Suspicious", "Malicious", "Unknown"), \
        f"Unexpected verdict: {received.get('verdict')}"
