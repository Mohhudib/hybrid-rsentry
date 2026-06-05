# 🛡️ Hybrid R-Sentry

<div align="center">

**A real-time ransomware detection and auto-containment system for Linux endpoints**

[![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)](https://python.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react)](https://reactjs.org)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF?style=flat-square&logo=vite)](https://vitejs.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Celery](https://img.shields.io/badge/Celery-5.x-37814A?style=flat-square)](https://docs.celeryq.dev)
[![Redis](https://img.shields.io/badge/Redis-7.x-DC382D?style=flat-square&logo=redis)](https://redis.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat-square&logo=postgresql)](https://postgresql.org)
[![Tests](https://img.shields.io/badge/tests-71%20passing-brightgreen?style=flat-square)](#testing)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

**[Landing Page](https://mohhudib.github.io/hybrid-rsentry/)**

</div>

---

## Overview

Hybrid R-Sentry is a **hybrid ransomware detection system** that combines multiple detection layers with an AI-powered analyst to identify, classify, and automatically contain ransomware threats on Linux endpoints — in real time.

Unlike signature-based solutions, Hybrid R-Sentry uses **behavioral analysis** to catch unknown and zero-day ransomware variants before they can cause significant damage.

---

## Features

### Detection Engine
- **Canary Files** — Strategically placed bait files (`AAA_*.txt`) that trigger an immediate CRITICAL alert if touched or deleted by any process
- **Shannon Entropy Analysis** — Monitors file entropy deltas to detect encryption activity in progress; memory-capped at 5 000 files with LRU eviction and 65 KB partial reads to prevent OOM on large watch paths
- **Process Lineage Scoring** — Scores suspicious process ancestry chains including parent names, spawn location, and binary SHA-256 verified against 416 K dpkg hashes (MATCH / MISMATCH / UNKNOWN verdicts)
- **Ransomware Extension Detection** — Renames to `.enc`, `.locked`, `.wcry`, `.crypted` etc. trigger CRITICAL (if the source was a document) or HIGH alert
- **Markov Chain Repositioning** — Adaptively moves canary files to predicted high-risk directories based on observed filesystem access patterns; blocks repositioning into `.git/`, `/proc/`, `/sys/`, `/dev/`, `/run/`
- **eBPF Kernel Sensor** (`agent/monitor_ebpf.py`) — TRACEPOINT_PROBE-based rename syscall monitoring at the kernel boundary; velocity burst detection; ransomware family profiling (LockBit 5.0 / Akira / ESXi); BCC 0.35, kernel ≥ 6.19
- **Combined Threat Scoring** — Fuses entropy and lineage signals into a weighted threat score for accurate severity classification
- **False Positive Suppression** — Comprehensive whitelist system (`agent/exceptions.py`) covering browsers, package managers, system paths, archive formats, media files, and smart temp-dir filtering to eliminate noise on live Linux systems

### Auto-Containment Pipeline
When a CRITICAL threat is detected, the system automatically executes a tree-aware multi-stage containment sequence across the entire process tree:
1. **SIGSTOP** — Immediately freezes the malicious process and all children (two-sweep enumeration catches race conditions)
2. **Evidence Capture** — Collects process metadata, open files, and network connections (up to 48 files per process tree)
3. **iptables DROP** — Blocks all outbound network traffic from the process owner UID
4. **SIGKILL** — Terminates the process tree permanently

### AI Threat Analyst
- Multi-provider fallback chain: **Cerebras** (fastest, optional) → **NVIDIA API** (key 1) → **NVIDIA/Groq** (key 2)
- Auto-detects Groq keys by `gsk_` prefix; backward compatible with `NVIDIA_API_KEY` / `NVIDIA_API_KEY_ALERTS`
- Publishes a PENDING state immediately, then updates with the real result
- AI results cached in Redis for 24 hours for forensic export
- Auto-acknowledges alerts classified as Benign or LOW risk
- System health check: analyzes recent activity patterns and reports overall endpoint status

### SIEM Dashboard
- Kibana-style 3-column layout: **FacetRail** filter panel, center (MetricsStrip + stacked histogram + sortable AlertsTable), **DetailFlyout** on alert click
- **TopBar** horizontal navigation with 6 tabs + live alert count badge; **StatusBar** at the bottom with agents/EPS/WS status/cluster
- **D3 v7 force-directed filesystem graph** — Obsidian-style node graph inside DetailFlyout and EventDetailModal; zoom, drag, tooltip, selected path pulled to center
- Clickable TacticalResponseLog events → EventDetailModal with Summary/Entity/MITRE/Filesystem/Raw tabs
- Live WebSocket feed — MetricsStrip, histogram, and table refresh instantly on new events
- Host risk panel with radial risk score gauge and alert breakdown by severity
- AI Analyst page with pending spinners, error cards, and 4-minute analysis persistence
- **PDF Forensic Export** — date filter, severity filter, host-aware Hosts Overview table, per-alert drill-down with AI analysis; SHA-256 integrity footer on every page

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Linux Endpoint                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Sensor: inotify (watchdog) OR eBPF (kernel 6.19+)  │   │
│  │   monitor.py                 monitor_ebpf.py         │   │
│  │   (watchdog, userspace)      (TRACEPOINT_PROBE,      │   │
│  │                               velocity burst,        │   │
│  │                               family profiling)      │   │
│  └───────────────────┬─────────────────────────────────┘   │
│                      │                                      │
│  ┌───────────────┐   │   ┌───────────────┐   ┌──────────┐  │
│  │   Entropy     │◀──┴──▶│    Lineage    │   │Extension │  │
│  │   Engine      │       │    Scorer     │   │Detection │  │
│  └───────────────┘       └───────────────┘   └──────────┘  │
│         │                        │                │         │
│         ▼                        ▼                ▼         │
│  ┌──────────────┐       ┌─────────────────────────────┐    │
│  │    Markov    │       │     Auto-Containment         │    │
│  │ Repositioner │       │  SIGSTOP→evidence→iptables   │    │
│  └──────────────┘       │  →SIGKILL (tree-aware)       │    │
│                         └─────────────────────────────┘    │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP POST /api/events
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                         │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │   Events     │   │   Alerts     │   │     Hosts      │  │
│  │   Router     │   │   Router     │   │    Router      │  │
│  └──────┬───────┘   └──────────────┘   └────────────────┘  │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │    Celery    │   │  PostgreSQL  │   │     Redis      │  │
│  │   Workers    │   │  (Events,    │   │  (Broker +     │  │
│  │  (AI, ACK,   │   │   Alerts,    │   │   3 WS chans)  │  │
│  │   WS push)   │   │   Hosts)     │   │                │  │
│  └──────────────┘   └──────────────┘   └────────┬───────┘  │
└─────────────────────────────────────────────────┼───────────┘
                                                  │ WebSocket
                                                  ▼
┌─────────────────────────────────────────────────────────────┐
│              React 19 SIEM Dashboard (Vite 5)                │
│  TopBar + 6 tabs │ FacetRail │ Histogram │ D3 force graph   │
│  Alert flyout │ AI analysis │ Host risk │ PDF export        │
└─────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent (inotify) | Python 3.13, watchdog 6, psutil, networkx, scipy, numpy |
| Agent (eBPF) | Python 3.13, BCC 0.35 (`python3-bpfcc`), Linux kernel ≥ 6.19 |
| Backend | FastAPI, SQLAlchemy (async), PostgreSQL, asyncpg |
| Task Queue | Celery, Redis |
| AI | Cerebras / NVIDIA / Groq (OpenAI-compatible, multi-provider fallback) |
| Frontend | React 19, Vite 5, Tailwind CSS 3, **D3 v7**, Recharts, jsPDF, IBM Plex Sans/Mono, Font Awesome 6.5.1 |
| Infrastructure | Docker Compose (PostgreSQL + Redis), Node.js 22 |

---

## Getting Started

### Prerequisites
- Python 3.13
- Node.js 22
- Docker & Docker Compose
- **For eBPF sensor (default):** Linux kernel ≥ 6.19 + `sudo apt install python3-bpfcc bpfcc-tools -y`
  - If kernel is older or BCC unavailable, set `SENSOR_BACKEND=inotify` in `.env`

### Quick Start (recommended)

**Step 1 — Clone and run first-time setup**
```bash
git clone https://github.com/Mohhudib/hybrid-rsentry.git
cd hybrid-rsentry
# Install BCC for eBPF sensor (skip if using inotify fallback)
sudo apt install python3-bpfcc bpfcc-tools -y
bash setup.sh
```

`setup.sh` installs system packages (requires sudo), creates the Python venv, installs all Python and Node dependencies, and copies `.env.example` to `.env`.

**Step 2 — Configure your environment**
```bash
# Edit .env — you must set these before running:
#   POSTGRES_PASSWORD   — choose a strong password
#   DATABASE_URL        — update to match POSTGRES_PASSWORD
#   NVIDIA_API_KEY      — your AI provider API key
#   NVIDIA_API_KEY_ALERTS
#   WATCH_PATH          — a directory OUTSIDE the project folder
nano .env
```

**Step 3 — Start everything**
```bash
bash start.sh
```

`start.sh` starts all five processes in the correct order and logs to `/tmp/rsentry-*.log`. Press `Ctrl+C` to stop all services cleanly.

Open [http://localhost:3000](http://localhost:3000) to access the dashboard.

---

### Subsequent Runs

Once the venv and node_modules are in place, just:
```bash
bash start.sh
```

---

### Manual Start (for development or debugging)

Each process runs in its own terminal.

**Terminal 1 — Infrastructure**
```bash
docker compose up -d
```

**Terminal 2 — Backend**
```bash
set -a && source .env && set +a
source venv/bin/activate
uvicorn backend.main:app --reload
```

**Terminal 3 — Celery workers**
```bash
set -a && source .env && set +a
source venv/bin/activate
PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info
```

**Terminal 4 — Agent** (requires root to set iptables rules)
```bash
set -a && source .env && set +a
sudo -E venv/bin/python -m agent.monitor
```

> `sudo -E` is mandatory — it preserves `WATCH_PATH` and the AI keys through the privilege boundary. Without it the agent watches the wrong path.

**Terminal 5 — Frontend**
```bash
cd frontend
npm start
```

Open [http://localhost:3000](http://localhost:3000) to access the dashboard.

> **Important:** `WATCH_PATH` must point to a directory **outside** the project folder. Placing canary files inside the repo corrupts `.git/refs`. The agent will refuse to start if this rule is violated.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password — used by Docker Compose and `DATABASE_URL` |
| `DATABASE_URL` | Yes | PostgreSQL connection string (asyncpg) — no default, backend fails immediately if unset |
| `REDIS_URL` | Yes | Redis connection string |
| `SECRET_KEY` | Yes | Secret key (32+ chars for production) |
| `HOST_ID` | Yes | Identifier for this endpoint (e.g. `kali-endpoint-01`) |
| `BACKEND_URL` | Yes | Backend URL the agent posts events to |
| `WATCH_PATH` | Yes | Directory to monitor — **must be outside the project folder** |
| `CANARY_COUNT` | No | Number of canary files to place (default: `15`) |
| `NVIDIA_API_KEY` | Yes* | API key for live event AI analysis (also readable as `AI_API_KEY`) |
| `NVIDIA_API_KEY_ALERTS` | Yes* | API key for on-demand alert AI analysis (also readable as `AI_API_KEY_ALERTS`) |
| `AI_API_KEY_CEREBRAS` | No | Cerebras API key — if set, becomes the primary AI provider (fastest); NVIDIA/Groq used as fallback |

*Groq keys are also accepted — auto-detected by the `gsk_` prefix.

---

## Alert Severity Levels

| Severity | Trigger | Auto-Action |
|---|---|---|
| CRITICAL | Canary file touched or deleted; ransomware extension rename on a document; combined score ≥ 70 | Immediate tree-aware auto-containment |
| HIGH | Combined score 40–69 (entropy + lineage); new file with ransomware extension | AI analysis + alert record |
| MEDIUM | Entropy spike alone | AI analysis + alert record |
| LOW | Heartbeat / system events | Logged only |

---

## Project Structure

```
hybrid-rsentry/
├── agent/                       # Endpoint monitoring agent
│   ├── monitor.py               # Main watchdog orchestrator (inotify backend)
│   ├── monitor_ebpf.py          # eBPF kernel sensor (TRACEPOINT_PROBE, BCC 0.35)
│   ├── graph.py                 # Filesystem graph + BFS canary placement
│   ├── entropy.py               # Shannon entropy engine (memory-capped)
│   ├── lineage.py               # Process lineage scorer + dpkg hash verification
│   ├── adaptive.py              # Markov chain repositioner + _is_safe_target() guard
│   ├── containment.py           # Tree-aware auto-containment pipeline
│   ├── exceptions.py            # Whitelist rules + smart /tmp filter
│   └── client.py                # Backend HTTP client
├── backend/
│   ├── main.py                  # FastAPI app entry point
│   ├── models/                  # SQLAlchemy ORM + Pydantic schemas
│   ├── routers/                 # events, alerts, hosts, ws
│   ├── services/                # AI analyst (multi-provider fallback chain)
│   └── workers/                 # Celery tasks
├── frontend/
│   ├── index.html               # Vite root; IBM Plex fonts + Font Awesome 6.5.1
│   ├── vite.config.js           # Vite: React plugin + proxy + process.env shim
│   └── src/
│       ├── App.jsx              # Root — TopBar + StatusBar layout; WS + AI state
│       ├── index.css            # CSS variable design system + SIEM utility classes
│       ├── pages/               # Overview, AlertsPage, HostsPage, FilesystemPage,
│       │                        # AIAnalystPage, ReportsPage
│       ├── components/          # TopBar, StatusBar, FacetRail, MetricsStrip,
│       │                        # AlertsHistogram, AlertsTable, DetailFlyout,
│       │                        # EventDetailModal, FileSystemGraph, FileSystemTree,
│       │                        # TacticalResponseLog, AIAnalystPanel, ...
│       ├── hooks/               # useWebSocket
│       └── api/                 # Axios client
├── landing/                     # 3D cinematic landing page (React Three Fiber + Framer Motion)
├── tests/
│   ├── unit/agent/              # 71 tests — entropy, lineage, adaptive, severity (89% coverage)
│   └── test_lockbit.py          # LockBit 5.0 4-metric evaluation — all targets met
├── simulations/                 # Attack simulation scripts
│   ├── sim_common.py            # Shared engine (profile, corpus, run_attack, backup/restore)
│   ├── sim_lockbit.py           # LockBit 5.0 two-pass simulation
│   ├── sim_akira.py             # Akira intermittent encryption simulation
│   ├── sim_qilin.py             # Qilin percent-encryption simulation
│   └── sim_depth.py / sim_dfs.py / sim_random.py   # Earlier traversal simulations
├── docs/
│   └── CODE_WALKTHROUGH.md      # Full file-by-file code walkthrough
├── .github/workflows/           # CI lint + Docker build + landing page deploy
├── start.sh                     # One-command startup script
├── test_event.sh                # One-command pipeline test (sends CANARY_TOUCHED event)
└── docker-compose.yml
```

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

71 tests covering `entropy.py`, `lineage.py`, `adaptive.py`, severity classification, and simulation safety. All tests are isolated (no live services required).

---

## Detection Flow

```
File system event
      │
      ▼
Is it a canary file? ──YES──▶ CRITICAL alert → Auto-containment
      │
      NO
      ▼
Ransomware extension rename? ──YES──▶ CRITICAL (doc) or HIGH alert
      │
      NO
      ▼
Is path/process whitelisted? ──YES──▶ Skip (suppress false positive)
      │
      NO
      ▼
Entropy delta > threshold?
      │
      ├──YES──▶ Lineage score >= 40? ──YES──▶ COMBINED_ALERT (CRITICAL/HIGH)
      │                               └──NO───▶ ENTROPY_SPIKE (MEDIUM)
      │
      └──NO───▶ Lineage score >= 40? ──YES──▶ PROCESS_ANOMALY (CRITICAL/HIGH)
                                     └──NO───▶ Skip (low signal)
      │
      ▼
AI analyst classifies threat → publishes result to dashboard
```

---

## Security

A security audit of this repository was conducted in May 2026. The following issues were identified and fixed:

| Fix | Detail |
|---|---|
| Removed `python-jose` dependency | Had CVE-2024-33664 and CVE-2024-33663; was never imported |
| Removed hardcoded DB password fallback | `database.py` now raises a clear `RuntimeError` if `DATABASE_URL` is unset |
| Parameterised Docker Compose credentials | `docker-compose.yml` reads `${POSTGRES_PASSWORD}` from the environment |
| Canary file git corruption prevented | `.gitignore` excludes `AAA_*.txt`; agent validates `WATCH_PATH` at startup; Markov repositioner blocks `.git/` targets |

**Dependabot:** The frontend has been migrated from Create React App to Vite, which resolved all 26 npm security alerts that were embedded in the `react-scripts` build toolchain.

For reporting vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. In brief:

1. Fork the repository
2. Create a feature branch off `main` (`git checkout -b feature/your-feature`)
3. Commit your changes using the `feat:` / `fix:` / `docs:` prefix style
4. Push and open a Pull Request against **`main`**

PRs that introduce new false positives on a live Kali system will not be merged.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE).

---

<div align="center">
Built as a cybersecurity capstone project — combining behavioral detection, adaptive defense, and AI-assisted threat analysis.
</div>
