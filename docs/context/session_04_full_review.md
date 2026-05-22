# Session 04 — Full Code Review

**Date:** 2026-05-22  
**Goal:** Review every file in the project — logic, purpose, correctness — and fix all bugs found.  
**Commit:** `7421190`

---

## Scope of review

Every backend file (`main.py`, `database.py`, `schemas.py`, all routers, workers, services), every agent file (`monitor.py`, `containment.py`, `adaptive.py`, `lineage.py`, `entropy.py`, `graph.py`, `client.py`, `exceptions.py`), every frontend file (all pages and components), `docker-compose.yml`, `setup.sh`, and `CLAUDE.md`.

---

## Bugs found and fixed

### Bug 1 — alerts.py: wrong UUID passed to AI task (auto-acknowledge never worked)

**File:** `backend/routers/alerts.py:123`

**Problem:** The on-demand "AI Analyze" button (Alerts page) calls `POST /api/alerts/{id}/analyze`. This endpoint fetched the alert, built event data, then called:
```python
analyze_alert_ai.delay(str(alert.event_id or alert_id), event_data)
```
`alert.event_id` is the foreign key to the events table — the event's UUID, not the alert's UUID. Since `event_id` is always set (NOT NULL), this always passed the wrong ID to the task. The `_ack_alert_by_id` function inside the task then queried `Alert.id == event_id`, which found nothing, so **on-demand AI auto-acknowledge was completely broken**.

**Fix:**
```python
# Pass event_id in event_data so the AI Analyst page can display the card
if alert.event_id:
    event_data["event_id"] = str(alert.event_id)

analyze_alert_ai.delay(str(alert_id), event_data)  # correct alert_id
```

---

### Bug 2 — tasks.py: AI Analyst page never showed on-demand results

**File:** `backend/workers/tasks.py`

**Problem:** `analyze_alert_ai` published its result to Redis as:
```python
{"type": "ai_analysis", "alert_id": alert_id, ...result}
```
`App.jsx` only handles `ai_analysis` messages that have `event_id` set:
```javascript
if (msg.type === 'ai_analysis' && msg.event_id) { ... }
```
Since there was no `event_id` in the message, every on-demand analysis result was silently ignored by the frontend. The AI Analyst page would never show these cards.

**Fix:** Read `event_id` from `event_data` (put there by the fix above) and include it in the publish:
```python
payload = {"type": "ai_analysis", "alert_id": alert_id, **result}
if event_data.get("event_id"):
    payload["event_id"] = event_data["event_id"]
r.publish("rsentry:ai", json.dumps(payload))
```

---

### Bug 3 — hosts.py: Events and Alerts columns always showed `—`

**File:** `backend/routers/hosts.py`

**Problem:** `HostsPage.jsx` and `HostRiskPanel.jsx` both read `risk?.alert_count` and `risk?.event_count` from the host risk API response. But `/api/hosts/{id}/risk` only returned `open_alerts` (a dict keyed by severity) and `recent_critical_events` (a list). Neither `alert_count` nor `event_count` existed in the response, so both values were always `undefined`, rendering as `—`.

**Fix:** Added two extra DB queries and included the results:
```python
total_alerts = ...  # sum of unacknowledged alerts for this host
total_events = ...  # total event count for this host

return {
    ...existing fields...,
    "alert_count": total_alerts,
    "event_count": total_events,
}
```

---

### Bug 4 — docker-compose.yml: AI analysis silently failed in Docker

**File:** `docker-compose.yml`

**Problem:** The `celery_worker` service had `DATABASE_URL` and `REDIS_URL` in its environment but was missing `NVIDIA_API_KEY` and `NVIDIA_API_KEY_ALERTS`. `ai_analyst.py` uses `os.getenv()` to read these — so in Docker, every AI analysis call raised `RuntimeError: NVIDIA_API_KEY not set` inside the Celery task, and the task returned `{"analysis_failed": True}` silently.

**Fix:**
```yaml
celery_worker:
  environment:
    DATABASE_URL: ...
    REDIS_URL: ...
    NVIDIA_API_KEY: ${NVIDIA_API_KEY:-}
    NVIDIA_API_KEY_ALERTS: ${NVIDIA_API_KEY_ALERTS:-}
```

---

### Bug 5 — CLAUDE.md + setup.sh: startup commands missing .env sourcing

**Files:** `CLAUDE.md`, `setup.sh`

**Problem:** The documented startup for Terminal 2 (uvicorn) and Terminal 3 (Celery) did not include sourcing `.env`:
```bash
# OLD (broken)
cd ~/hybrid-rsentry && source venv/bin/activate && uvicorn backend.main:app --reload
cd ~/hybrid-rsentry && PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info
```
`database.py` checks `DATABASE_URL = os.getenv("DATABASE_URL")` at **module import time** and raises `RuntimeError` immediately if it's missing. `ai_analyst.py` uses `os.getenv("NVIDIA_API_KEY")` at client construction time. Neither uses `_env()` (the file reader in tasks.py). So if the shell doesn't have these vars, both processes crash.

**Fix:**
```bash
# CORRECT
cd ~/hybrid-rsentry && set -a && source .env && set +a && source venv/bin/activate && uvicorn backend.main:app --reload
cd ~/hybrid-rsentry && set -a && source .env && set +a && PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info
```

---

### Bug 6 — client.py: wrong key in send_containment_complete

**File:** `agent/client.py:170`

**Problem:** `send_containment_complete` tried to get the process name from the result dict:
```python
process_name=result_dict.get("name", ""),
```
But `ContainmentResult.to_dict()` returns:
```python
{"pid": ..., "stopped": ..., "evidence_dir": ..., "evidence_files": ..., "iptables_rule": ..., "killed": ..., "error": ..., "timestamp": ...}
```
There is no `"name"` key. So `process_name` in every `CONTAINMENT_COMPLETE` event was always an empty string.

**Fix:**
```python
process_name="",  # ContainmentResult.to_dict() has no name field
```

---

## Architecture review — what was verified correct

| Component | Status |
|---|---|
| `database.py` — raises RuntimeError if DATABASE_URL missing | Intentional, correct |
| `events.py` — is_internal check for Markov canary moves (pid==0, sub_type==moved) | Correct |
| `events.py` — publish_markov_analysis fires when repositioner moves canaries (CRITICAL+is_internal) | Correct |
| `tasks.py` — _run() new event loop per task for Python 3.13 Celery fork safety | Correct |
| `tasks.py` — auto_ack_by_event for live AI analysis, _ack_alert_by_id for on-demand | Correct (after Fix 1) |
| `adaptive.py` — Markov stationary distribution via numpy eig on T^T | Correct |
| `containment.py` — SIGSTOP → evidence → iptables → SIGKILL pipeline | Correct |
| `lineage.py` — BENIGN_PARENTS reduces score, SUSPICIOUS_PARENT_NAMES triggers it | Correct |
| `exceptions.py` — whitelist applied only when not a canary hit | Correct |
| WebSocket — Redis pub/sub on 3 channels, ping/pong keepalive | Correct |
| `App.jsx` — AI state lifted to root, persists 4min across navigation | Correct |
| `AlertsPage.jsx` — refreshes on new_alert AND liveAiResult (catches auto-acks) | Correct |
| `StatsBar.jsx` — /api/alerts/counts + /api/hosts, refreshes on live events | Correct |
| `ReportsPage.jsx` — forensic JSON export per alert and bulk | Correct |
| `FileSystemTree.jsx` — builds tree from events, flash on new event, search filter | Correct |

---

## What is still pending (not bugs, just unfinished features)

- Alembic migrations (currently using `create_all` on startup — works but not production-grade)
- Unit tests
- CI/CD GitHub Actions
- Graph view (React Flow) to replace FileSystemTree was discussed, never started
- 35 GitHub Dependabot npm alerts — all in react-scripts build toolchain, accepted risk
