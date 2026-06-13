# Project Architecture Reference

**Last updated:** 2026-06-13

---

## What Hybrid R-Sentry is

A ransomware detection system for Linux endpoints combining multiple detection layers:

- **Canary files** (`AAA_`/`aaa_`/`ZZZ_`/`zzz_` prefixes, `.txt`) — bait files that trigger CRITICAL alert if touched or deleted
- **Shannon entropy delta** — detects file encryption activity via rolling window
- **Markov chain repositioning** — moves canary files to predicted access hotspots
- **Process lineage scoring** — scores suspicious process ancestry
- **Auto-containment pipeline** — SIGSTOP → evidence capture → iptables DROP → SIGKILL

---

## Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI + SQLAlchemy async + PostgreSQL |
| Async tasks | Celery + Redis as broker/backend |
| Real-time push | WebSocket (FastAPI) + Redis pub/sub |
| Agent | Python watchdog + eBPF/BCC sensor + psutil + scipy/numpy (entropy) + networkx (Markov) |
| AI analysis | Cerebras → NVIDIA → Groq fallback chain (OpenAI-compatible) |
| Frontend | React 19 + Vite 5 + Recharts + Tailwind CSS |
| Infrastructure | Docker Compose (Postgres + Redis) + Python 3.13 venv on Kali |

---

## Five-process architecture

```
┌─────────────────┐     HTTP POST /api/events      ┌──────────────────────┐
│  Agent          │ ─────────────────────────────► │  FastAPI Backend     │
│  (monitor.py)   │                                │  (port 8000)         │
│                 │                                │                      │
│  - watchdog     │                                │  - event ingestion   │
│  - entropy      │                                │  - alert creation    │
│  - lineage      │                                │  - host tracking     │
│  - Markov       │                                │  - WebSocket server  │
│  - containment  │                                └──────────┬───────────┘
└─────────────────┘                                           │
                                                    Celery task dispatch
                                                              │
                                                    ┌─────────▼───────────┐
                                                    │  Celery Worker      │
                                                    │                     │
                                                    │  - AI analysis      │
                                                    │  - WS push          │
                                                    │  - risk scoring     │
                                                    │  - auto-ack         │
                                                    └─────────┬───────────┘
                                                              │
                                                    Redis pub/sub publish
                                                              │
                                                    ┌─────────▼───────────┐
┌─────────────────┐     WebSocket ws://...          │  FastAPI WS         │
│  React Frontend │ ◄──────────────────────────────│  (rsentry:alerts    │
│  (port 3000)    │                                │   rsentry:events    │
│                 │                                │   rsentry:ai)       │
│  - Dashboard    │                                └─────────────────────┘
│  - Alerts       │
│  - Hosts        │     REST API (axios)           ┌──────────────────────┐
│  - Filesystem   │ ◄─────────────────────────────│  PostgreSQL          │
│  - AI Analyst   │                                │  (port 5432)         │
│  - Reports      │                                └──────────────────────┘
└─────────────────┘
```

---

## Redis pub/sub channels

| Channel | Published by | Consumed by |
|---|---|---|
| `rsentry:alerts` | `push_alert_ws`, `_ack_alert_by_id`, `auto_ack_containment`, `auto_ack_by_event` | FastAPI WS → frontend |
| `rsentry:events` | `push_event_ws` | FastAPI WS → frontend |
| `rsentry:ai` | `analyze_event_ai`, `analyze_alert_ai`, `publish_markov_analysis`, `analyze_health_ai` | FastAPI WS → frontend AI Analyst page |

---

## Database tables

| Table | Purpose |
|---|---|
| `hosts` | One row per monitored endpoint. `risk_score` updated by Celery. |
| `events` | Every detection event from the agent. |
| `alerts` | Created for CRITICAL/HIGH/MEDIUM events. Has `acknowledged` flag. |
| `evidence` | Forensic data captured during containment (proc artifacts, psutil info). |

---

## Alert severity logic

| Severity | Trigger | Auto-action |
|---|---|---|
| CRITICAL | Canary file touched/deleted/moved OR combined score ≥ 70 | SIGSTOP → evidence → iptables DROP → SIGKILL |
| HIGH | Entropy spike + lineage score ≥ 40, combined score < 70 | Alert record created, AI analysis queued |
| MEDIUM | Entropy spike alone (delta ≥ 3.5 bits) | Alert record created, AI analysis queued |
| LOW | Heartbeat, system events | Event recorded, no alert record |

AI auto-acknowledges alerts it classifies as Benign or LOW risk.  
CRITICAL alerts are auto-acknowledged when CONTAINMENT_COMPLETE fires.

---

## Markov chain repositioning

The Markov repositioner (`agent/adaptive.py`) tracks which directories are accessed most frequently and builds a transition probability matrix. When any state probability reaches ≥ 0.70 and at least 10 observations have been recorded, it:

1. Computes the stationary distribution (left eigenvector for eigenvalue 1)
2. Ranks directories by stationary probability (predicted hotspots)
3. Moves canary files to those directories using `shutil.move`

When watchdog detects the file moves (pid=0, sub_type="moved"), `events.py` recognises them as internal Markov operations (`is_internal=True`) and publishes a pre-built "Benign / LOW risk" AI analysis instead of creating an alert.

---

## AI analysis paths

Two separate NVIDIA API keys to avoid rate limit cross-blocking:

| Path | Key | Task | When triggered |
|---|---|---|---|
| Live event analysis | `NVIDIA_API_KEY` | `analyze_event_ai` | Every CRITICAL/HIGH/MEDIUM event |
| On-demand analysis | `NVIDIA_API_KEY_ALERTS` | `analyze_alert_ai` | User clicks "AI Analyze" on Alerts page |
| Health check | `NVIDIA_API_KEY` | `analyze_health_ai` | User clicks "Run System Health Check" |

---

## Key file map

```
backend/main.py                  — FastAPI app, CORS, lifespan (DB create_all)
backend/models/database.py       — Async engine; raises RuntimeError if DATABASE_URL missing
backend/models/schemas.py        — All ORM models + Pydantic schemas (4 tables)
backend/routers/events.py        — POST /api/events (agent posts here), alert creation
backend/routers/alerts.py        — Alert CRUD, /counts, ACK, analyze, evidence, forensic-export
backend/routers/hosts.py         — Host list, risk summary (alert_count + event_count), contain/release
backend/routers/ws.py            — WebSocket, subscribes to 3 Redis channels, ping/pong
backend/workers/tasks.py         — All Celery tasks; reads .env via _env() for broker/db config
backend/services/ai_analyst.py   — Multi-provider AI: Cerebras → NVIDIA → Groq fallback; dual-key (_events / _alerts)

agent/monitor.py                 — Main watchdog; coordinates all modules, heartbeat, reposition loop
agent/containment.py             — SIGSTOP → /proc evidence → iptables → SIGKILL pipeline
agent/adaptive.py                — Markov chain canary repositioner (numpy eigenvector)
agent/lineage.py                 — psutil process ancestry scorer (0–100)
agent/entropy.py                 — Rolling Shannon entropy delta engine (scipy)
agent/graph.py                   — Filesystem graph, canary placement via BFS
agent/client.py                  — Synchronous HTTP client (httpx), retry on connect error
agent/exceptions.py              — Whitelist: paths, extensions, process names for false positive suppression

frontend/src/App.jsx             — Root; WebSocket + AI state lifted here, persists across navigation
frontend/src/hooks/useWebSocket.js — WS connect, auto-reconnect, 25s ping keepalive
frontend/src/api/client.js       — Axios base client, all REST endpoints
frontend/src/pages/Overview.jsx  — Dashboard with StatsBar, EventChart, AlertFeed, HostRiskPanel, TacticalResponseLog
frontend/src/pages/AlertsPage.jsx — Alert list, ACK, AI Analyze button, active/all filter
frontend/src/pages/HostsPage.jsx  — Host cards with radial risk gauge, contain/release button
frontend/src/pages/AIAnalystPage.jsx — AI analysis cards, pending spinners, system health tab
frontend/src/pages/ReportsPage.jsx   — Forensic export table, filter by severity/ack, bulk export
frontend/src/pages/FilesystemPage.jsx — Filesystem tree with canary highlighting, entropy pills
```

---

## Required .env variables

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

`DATABASE_URL` is required with no fallback — backend raises RuntimeError at startup if missing.  
`WATCH_PATH` must be outside `~/hybrid-rsentry` — canary files corrupt git refs if inside the project.
