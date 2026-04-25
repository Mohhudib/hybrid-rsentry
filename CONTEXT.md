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
- **GitHub repo:** https://github.com/Mohhudib/hybrid-rsentry (Private)
- **GitHub username:** Mohhudib
- **Kali username:** mohammad
- **Kali repo location:** `~/hybrid-rsentry`

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

## Every File Built

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

## API Event Payload

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
- `entropy_delta > 3.5` → **MEDIUM**
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

## Problems Solved & Fixes Applied

### Problem 1 — PEP 668 externally-managed-environment
**What happened:** `pip install -r requirements.txt` blocked by Kali system Python protection
**Fix:** Created `setup.sh` with `python3 -m venv venv` + `source venv/bin/activate`

### Problem 2 — scipy compile error (OpenBLAS not found)
**What happened:** scipy 1.13.1 has no pre-built wheel for Python 3.13 on Kali, tries to compile from source and fails
**Fix applied:**
- Updated `requirements.txt` to `scipy>=1.14.0` and `numpy>=2.0.0`
- Install scipy from system apt then copy into venv:
```bash
sudo apt install -y python3-scipy python3-numpy python3-pandas
cp -r /usr/lib/python3/dist-packages/scipy ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
cp -r /usr/lib/python3/dist-packages/numpy ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
cp -r /usr/lib/python3/dist-packages/pandas ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
```

### Problem 3 — asyncpg ModuleNotFoundError
**What happened:** venv was using system SQLAlchemy which couldn't see venv's asyncpg
**Fix:** Recreate venv without `--system-site-packages`, use `venv/bin/uvicorn` explicitly

### Problem 4 — libopenblas-dev / libatlas-base-dev not found
**What happened:** These packages don't exist on this Kali version
**Fix:** Use system apt scipy instead (see Problem 2 fix)

---

## Current Status (as of 2026-04-08)

| Component | Status |
|---|---|
| All code written | ✅ Done |
| Pushed to GitHub | ✅ Done |
| Cloned on Kali | ✅ Done |
| venv created | ✅ Done |
| scipy/numpy/pandas | ⚠️ In progress — fixing compile issue |
| pip install complete | ⏳ Not done yet |
| Docker + PostgreSQL + Redis | ⏳ Not done yet |
| Backend running | ⏳ Not done yet |
| Agent running | ⏳ Not done yet |
| Frontend running | ⏳ Not done yet |

---

## Next Steps (do these on Kali in order)

```bash
# 1. Install system scipy
sudo apt install -y python3-scipy python3-numpy python3-pandas

# 2. Copy into venv
cp -r /usr/lib/python3/dist-packages/scipy ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
cp -r /usr/lib/python3/dist-packages/numpy ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
cp -r /usr/lib/python3/dist-packages/pandas ~/hybrid-rsentry/venv/lib/python3.13/site-packages/

# 3. Pull latest code
cd ~/hybrid-rsentry
git pull origin develop

# 4. Install remaining Python deps
source venv/bin/activate
pip install -r requirements.txt

# 5. Start Docker services
sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo docker compose up -d postgres redis

# 6. Run backend (terminal 1)
venv/bin/uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 7. Run agent (terminal 2)
sudo ~/hybrid-rsentry/venv/bin/python -m agent.monitor

# 8. Run frontend (terminal 3)
cd ~/hybrid-rsentry/frontend
npm start

# 9. Open dashboard
# Browser → http://localhost:3000
```

---

## TODO — Remaining Features

- [ ] Alembic migrations — DB schema version control
- [ ] Tailwind PostCSS config (`postcss.config.js`)
- [ ] Frontend `.env.local`
- [ ] Makefile — shortcut commands
- [ ] Unit tests — pytest for entropy, lineage, graph modules

---

## Key Decisions

- **venv** used instead of system pip (Kali PEP 668)
- **Monorepo** with 4 feature branches all merging into `develop`
- **Celery + Redis** for async alert push
- **Canary prefix `AAA_`** sorts to top of directory listings
- **DRY_RUN=true** disables actual SIGKILL/iptables for safe testing
- **sim_*.py** write random bytes only — no real encryption

---

*Last updated: 2026-04-08 | Claude Sonnet 4.6*
