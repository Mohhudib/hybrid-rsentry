# Hybrid R-Sentry — Project Context & Session Resume File

> When returning to Claude Code, say:
> **"I'm continuing Hybrid R-Sentry, read CONTEXT.md"**

---

## What This Project Is

A ransomware detection system that extends the academic paper **R-Sentry** by adding 4 new detection layers. Runs on **Kali Linux inside VirtualBox**. Built as a monorepo on Windows, deployed on Kali.

---

## Developer Setup

- **Code is written on:** Windows (CMD + Claude Code CLI)
- **Project runs on:** Kali Linux VirtualBox
- **Repo location (Windows):** `C:\Users\Mohammad Hudib\Documents\GitHub\Hybrid-Rsentry`
- **GitHub:** needs to be pushed (see TODO list below)
- **Kali workflow:** `git pull` → `source venv/bin/activate` → run services

---

## Tech Stack

| Layer | Tech |
|---|---|
| Agent | Python 3.11, watchdog, networkx, scipy, numpy, pandas, psutil |
| Backend | FastAPI, SQLAlchemy (async), asyncpg, PostgreSQL, Redis, Celery |
| Frontend | React 18, Recharts, Axios, Tailwind CSS |
| Infra | Docker Compose, nginx, iptables, auditd |

---

## Git Branch Structure

```
main
└── develop  ← all work merged here
    ├── feat/agent       ✅ merged
    ├── feat/backend     ✅ merged
    ├── feat/detection   ✅ merged
    └── feat/evp         ✅ merged (frontend)
```

---

## Every File Built So Far

### Agent (`agent/`)
| File | What it does |
|---|---|
| `monitor.py` | Main orchestrator — watchdog inotify watcher, heartbeat loop, Markov reposition loop |
| `graph.py` | NetworkX filesystem graph, DFS/BFS hotspot detection, places 15 `AAA_` canary files |
| `entropy.py` | Rolling Shannon entropy delta engine (scipy/numpy/pandas), fires `ENTROPY_SPIKE` |
| `lineage.py` | psutil process ancestry scorer, suspicion score 0–100 |
| `adaptive.py` | Markov chain canary repositioner using numpy + shutil.move() |
| `containment.py` | SIGSTOP → /proc evidence capture → iptables DROP → SIGKILL pipeline |
| `client.py` | REST client, sends events to backend, auto-computes severity |

### Backend (`backend/`)
| File | What it does |
|---|---|
| `main.py` | FastAPI app entry point, CORS, lifespan (creates DB tables on startup) |
| `models/database.py` | SQLAlchemy async engine + session factory |
| `models/schemas.py` | 4 ORM tables (hosts, events, alerts, evidence) + Pydantic schemas |
| `routers/events.py` | POST /api/events — ingest agent payloads, auto-generate alerts |
| `routers/alerts.py` | GET/PATCH /api/alerts, acknowledge, forensic JSON export |
| `routers/hosts.py` | GET /api/hosts, risk summary, contain/release controls |
| `routers/ws.py` | WebSocket /ws/alerts — Redis pub/sub live push to dashboard |
| `workers/tasks.py` | Celery tasks: push_alert_ws, update_host_risk |

### Frontend (`frontend/src/`)
| File | What it does |
|---|---|
| `App.jsx` | 3-panel layout, WS live alert injection |
| `components/AlertFeed.jsx` | Real-time alert list, severity filter, ACK button |
| `components/HostRiskPanel.jsx` | Radial risk gauge (Recharts), contain/release per host |
| `components/EventChart.jsx` | 30-min area chart bucketed by severity (Recharts) |
| `components/ForensicExport.jsx` | One-click JSON download of alert + evidence |
| `components/StatusBar.jsx` | Live WebSocket connection indicator |
| `hooks/useWebSocket.js` | Auto-reconnect WebSocket hook |
| `api/client.js` | Axios API client for all backend endpoints |

### Simulations (`simulations/`)
| File | What it does |
|---|---|
| `sim_dfs.py` | Safe simulator: DFS file access pattern |
| `sim_random.py` | Safe simulator: random access order |
| `sim_depth.py` | Safe simulator: deepest directories first |

### Infrastructure
| File | What it does |
|---|---|
| `docker-compose.yml` | Postgres, Redis, Backend, Celery worker, Frontend (nginx) |
| `Dockerfile.backend` | Python 3.11 slim + iptables/procps |
| `frontend/Dockerfile.frontend` | Node build → nginx serve |
| `frontend/nginx.conf` | SPA fallback + API/WS proxy to backend |
| `setup.sh` | Full bootstrap script for Kali Linux (venv + pip + npm) |
| `requirements.txt` | All Python dependencies |
| `frontend/package.json` | All Node dependencies |
| `.env.example` | Template for environment variables |
| `.gitignore` | Excludes venv/, node_modules/, .env, evidence dirs |

---

## API Event Payload (every agent POST)

```json
{
  "host_id": "kali-endpoint-01",
  "timestamp": "2026-04-08T12:00:00Z",
  "event_type": "CANARY_TOUCHED | ENTROPY_SPIKE | PROCESS_ANOMALY | COMBINED_ALERT | CONTAINMENT_TRIGGERED | CONTAINMENT_COMPLETE | HEARTBEAT",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "pid": 1234,
  "process_name": "python3",
  "file_path": "/home/user/AAA_canary_01.txt",
  "lineage_score": 75.5,
  "entropy_delta": 4.2,
  "canary_hit": true,
  "details": {}
}
```

### Severity Rules
- `canary_hit = true` → always **CRITICAL**
- `combined_score >= 70` → **CRITICAL**
- `combined_score 40–69` → **HIGH**
- `entropy_delta > 3.5` (single file) → **MEDIUM**
- `score < 40` → **LOW**

---

## Environment Variables (`.env`)

```
DATABASE_URL=postgresql+asyncpg://rsentry:rsentry_pass@localhost:5432/rsentry_db
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=change-me-in-production
HOST_ID=kali-endpoint-01
BACKEND_URL=http://localhost:8000
WATCH_PATH=/home
CANARY_COUNT=15
```

---

## TODO — What's NOT done yet (next steps)

- [ ] **Push to GitHub** — remote not added yet (user needs to create GitHub repo first)
- [ ] **Alembic migrations** — DB schema version control
- [ ] **Tailwind PostCSS config** — needed to compile frontend CSS (`postcss.config.js`)
- [ ] **Frontend `.env.local`** — set REACT_APP_API_URL and REACT_APP_WS_URL
- [ ] **Test on Kali** — clone repo, run setup.sh, docker compose up, run agent
- [ ] **Makefile** — shortcut commands (make run, make agent, make sim-dfs)
- [ ] **Unit tests** — pytest for entropy.py, lineage.py, graph.py

---

## How to Push to GitHub (not done yet)

```bash
# In Windows CMD, inside the repo:
git remote add origin https://github.com/YOUR-USERNAME/Hybrid-Rsentry.git
git push -u origin main
git push -u origin develop
git push origin feat/agent feat/backend feat/detection feat/evp
```

## How to Run on Kali (after cloning)

```bash
git clone https://github.com/YOUR-USERNAME/Hybrid-Rsentry.git
cd Hybrid-Rsentry
git checkout develop
chmod +x setup.sh && ./setup.sh

# Start infra
sudo docker compose up -d postgres redis

# Backend (terminal 1)
source venv/bin/activate
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Agent (terminal 2)
sudo venv/bin/python -m agent.monitor

# Frontend (terminal 3)
cd frontend && npm start
# Open http://localhost:3000
```

---

## Key Decisions Made

- **venv** used instead of system pip (Kali PEP 668 blocks system-wide installs)
- **Monorepo** with 4 feature branches all merging into `develop`
- **Celery + Redis** for async alert push (not blocking the FastAPI event loop)
- **Canary prefix `AAA_`** so they sort to the top of any directory listing
- **DRY_RUN=true** env var disables actual SIGKILL/iptables for safe testing
- **sim_*.py** simulators write random bytes only — no real encryption

---

*Last updated: 2026-04-08 | Claude Sonnet 4.6*
