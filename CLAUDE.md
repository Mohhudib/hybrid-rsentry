# Hybrid R-Sentry — Claude Context

You are helping debug or develop **Hybrid R-Sentry**, a ransomware detection system running on Kali Linux.
Read this entire file before doing anything.

---

## What the system is

A multi-process Python + React application with five processes that must all be running simultaneously:

| Process | What it does |
|---|---|
| Docker (Postgres + Redis) | Database and message broker |
| FastAPI backend (`uvicorn`) | REST API + WebSocket server on port 8000 |
| Celery worker | Async tasks: AI analysis, WebSocket push, risk scoring |
| Agent (`agent.monitor`) | Watchdog that monitors files, detects threats, fires containment |
| React frontend (`npm start`) | Dashboard on port 3000 |

---

## Startup sequence

```bash
# Terminal 1
cd ~/hybrid-rsentry && docker compose up -d

# Terminal 2 — source .env first so DATABASE_URL and NVIDIA keys reach uvicorn
cd ~/hybrid-rsentry && set -a && source .env && set +a && source venv/bin/activate && uvicorn backend.main:app --reload

# Terminal 3 — source .env first so DATABASE_URL and NVIDIA keys reach Celery
cd ~/hybrid-rsentry && set -a && source .env && set +a && PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info

# Terminal 4 — sudo -E is mandatory to preserve WATCH_PATH and other env vars
cd ~/hybrid-rsentry && set -a && source .env && set +a && sudo -E ~/hybrid-rsentry/venv/bin/python -m agent.monitor

# Terminal 5
cd ~/hybrid-rsentry/frontend && npm start
```

---

## Key files

```
backend/main.py                  — FastAPI app, CORS config, lifespan (DB table creation)
backend/models/database.py       — SQLAlchemy async engine; reads DATABASE_URL (required, no default)
backend/models/schemas.py        — All ORM models + Pydantic schemas
backend/routers/events.py        — POST /api/events (agent posts here), alert creation logic
backend/routers/alerts.py        — Alert CRUD, /api/alerts/counts, ACK endpoint
backend/routers/hosts.py         — Host inventory, contain/release endpoints
backend/routers/ws.py            — WebSocket; subscribes to 3 Redis channels
backend/workers/tasks.py         — All Celery tasks; reads .env directly via _env() — no dotenv
backend/services/ai_analyst.py   — NVIDIA LLM calls (OpenAI-compatible API)
agent/monitor.py                 — Main watchdog; orchestrates entropy, lineage, containment
agent/containment.py             — SIGSTOP → evidence capture → iptables DROP → SIGKILL
agent/adaptive.py                — Markov chain canary repositioner
agent/lineage.py                 — Process ancestry scorer
agent/exceptions.py              — Whitelist: browsers, package managers, system paths
agent/client.py                  — HTTP client that posts events to /api/events
frontend/src/App.jsx             — Root app; WebSocket state and AI state live here
frontend/src/pages/AIAnalystPage.jsx
frontend/src/pages/AlertsPage.jsx
frontend/src/pages/HostsPage.jsx
```

---

## Required .env variables

File lives at `~/hybrid-rsentry/.env` (gitignored — never committed).

```
POSTGRES_PASSWORD=...
DATABASE_URL=postgresql+asyncpg://rsentry:<POSTGRES_PASSWORD>@localhost:5432/rsentry_db
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=...
HOST_ID=ATOMIC
BACKEND_URL=http://localhost:8000
WATCH_PATH=/home/mohammad/Documents
CANARY_COUNT=15
NVIDIA_API_KEY=...
NVIDIA_API_KEY_ALERTS=...
```

---

## Hard rules — never violate these

1. **WATCH_PATH must be outside ~/hybrid-rsentry.** Canary files (AAA_*.txt) corrupt git refs if placed inside the project directory.
2. **Never run `docker compose down -v`.** The `-v` flag deletes the Postgres data volume. Use `docker compose down` only.
3. **Never edit `.env.example` thinking it is `.env`.** Real secrets are in `.env` (gitignored).
4. **Always start the agent with `sudo -E`** after sourcing `.env`. Without `-E`, sudo strips env vars and the agent watches the wrong path.
5. **Always activate the venv before pip commands:** `source venv/bin/activate`
6. **Never run `npm audit fix --force`.** It installs `react-scripts@0.0.0` and breaks the frontend build.
7. **Do not suggest adding authentication middleware** without understanding the full async SQLAlchemy dependency chain — this has broken the app before.

---

## Known issues and fixes

**Agent floods alerts from Firefox cache / wrong path**
Cause: WATCH_PATH not passed through sudo.
Fix: start agent with `sudo -E` after sourcing `.env` (see startup above).

**Canary files appear in `.git/refs/heads/`**
Symptom: git commands error; files named `AAA_*.txt` inside `.git/refs/`.
Fix: `find .git/refs -name "AAA_*" -delete`

**Backend crashes immediately on startup with RuntimeError**
Cause: `DATABASE_URL` is not set — the backend has no fallback default. `database.py` checks it at module import time.
Fix: always use `set -a && source .env && set +a` before starting uvicorn (see startup sequence above).

**Celery crashes on startup or AI analysis fails silently**
Cause: `DATABASE_URL` (needed at import time) and `NVIDIA_API_KEY`/`NVIDIA_API_KEY_ALERTS` are not in the shell environment.
Note: `_env()` in tasks.py reads the .env file for database/redis/celery config, but `database.py` and `ai_analyst.py` use `os.getenv()` directly.
Fix: always use `set -a && source .env && set +a` before starting Celery (see startup sequence above).

**NVIDIA API returns 429**
Cause: rate limit hit. The AI analyst has built-in retry logic.
Fix: if persistent, rotate `NVIDIA_API_KEY` and `NVIDIA_API_KEY_ALERTS` in `.env` and restart Celery.

**Alert counts wrong or stale in dashboard**
StatsBar uses `/api/alerts/counts` endpoint. Risk score updates and WebSocket pushes go through Celery.
Fix: confirm the Celery worker is running.

**Risk score stuck at 0 after clearing alerts**
This is correct behaviour. The score recalculates via Celery on the next incoming event.

---

## Alert severity logic

| Severity | Trigger | Auto-action |
|---|---|---|
| CRITICAL | Any canary file (AAA_*.txt) touched | Immediate: SIGSTOP → iptables DROP → SIGKILL |
| HIGH | Entropy spike + lineage score ≥ 40 | AI analysis queued, alert record created |
| MEDIUM | Entropy spike alone | AI analysis queued, alert record created |
| LOW | Heartbeat / system events | Logged only, no alert record |

AI auto-acknowledges alerts it classifies as Benign or LOW risk.
CRITICAL alerts are auto-acknowledged when CONTAINMENT_COMPLETE fires.

---

## Safe diagnostic commands

```bash
# Confirm all 5 processes are running
docker compose ps
ps aux | grep uvicorn
ps aux | grep celery
ps aux | grep agent.monitor

# Backend health check
curl http://localhost:8000/health

# Recent events in DB
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "SELECT event_type, severity, file_path, timestamp FROM events ORDER BY timestamp DESC LIMIT 20;"

# Unacknowledged alert counts
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "SELECT severity, COUNT(*) FROM alerts WHERE acknowledged=false GROUP BY severity;"

# Clear accumulated test/false-positive alerts (marks resolved, does not delete records)
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "UPDATE alerts SET acknowledged=true, resolved_at=NOW() WHERE acknowledged=false;"

# Watch Redis for live traffic
redis-cli subscribe rsentry:alerts

# Swagger UI (while uvicorn is running)
# http://localhost:8000/docs
```

---

## Debugging approach

Always ask which terminal the error appeared in before suggesting a fix.
The five processes are independent — an error in Celery does not mean the backend is broken.
