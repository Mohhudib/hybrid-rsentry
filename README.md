# 🛡️ Hybrid R-Sentry

<div align="center">

**A real-time ransomware detection and auto-containment system for Linux endpoints**

[![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)](https://reactjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Celery](https://img.shields.io/badge/Celery-5.x-37814A?style=flat-square)](https://docs.celeryq.dev)
[![Redis](https://img.shields.io/badge/Redis-7.x-DC382D?style=flat-square&logo=redis)](https://redis.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat-square&logo=postgresql)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## Overview

Hybrid R-Sentry is a **hybrid ransomware detection system** that combines multiple detection layers with an AI-powered analyst to identify, classify, and automatically contain ransomware threats on Linux endpoints — in real time.

Unlike signature-based solutions, Hybrid R-Sentry uses **behavioral analysis** to catch unknown and zero-day ransomware variants before they can cause significant damage.

---

## Features

### Detection Engine
- **Canary Files** — Strategically placed bait files (`AAA_*.txt`) that trigger an immediate CRITICAL alert if touched by any process
- **Shannon Entropy Analysis** — Monitors file entropy deltas to detect encryption activity in progress
- **Process Lineage Scoring** — Scores suspicious process ancestry chains to identify malicious parent-child relationships
- **Markov Chain Repositioning** — Adaptively moves canary files to predicted high-risk directories based on observed filesystem access patterns
- **Combined Threat Scoring** — Fuses entropy and lineage signals into a weighted threat score for accurate severity classification

### Auto-Containment Pipeline
When a CRITICAL threat is detected, the system automatically executes a multi-stage containment sequence:
1. **SIGSTOP** — Immediately freezes the malicious process
2. **Evidence Capture** — Collects process metadata, open files, and network connections
3. **iptables DROP** — Blocks all outbound network traffic from the process
4. **SIGKILL** — Terminates the process permanently

### AI Threat Analyst
- Automated threat classification using a large language model
- Analyzes every HIGH/CRITICAL/MEDIUM event and returns structured JSON: threat type, technique, behavior summary, risk level, and recommendation
- Two independent API keys — one for live event analysis, one for on-demand alert analysis — to prevent rate-limit blocking
- System health check: analyzes recent activity patterns and reports overall endpoint status
- Auto-acknowledges alerts classified as Benign or LOW risk

### Live Dashboard
- Real-time WebSocket feed with three independent Redis pub/sub channels
- 6 live stat cards (events, alerts by severity, canary hits, contained hosts)
- Filesystem tree with canary zone indicators, entropy bars, and live flash on activity
- Tactical Response Log with procedure names and severity filters
- Alert management with per-alert ACK and bulk "Acknowledge All" button
- Host risk panel with radial risk score gauge
- AI Analyst page with pending spinners, error cards, and 4-minute analysis persistence

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Linux Endpoint                        │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │  Watchdog    │   │   Entropy    │   │    Lineage     │  │
│  │  Monitor     │──▶│   Engine     │──▶│    Scorer      │  │
│  └──────────────┘   └──────────────┘   └────────────────┘  │
│         │                                       │           │
│         ▼                                       ▼           │
│  ┌──────────────┐                    ┌────────────────────┐ │
│  │    Markov    │                    │  Auto-Containment  │ │
│  │ Repositioner │                    │ SIGSTOP→iptables   │ │
│  └──────────────┘                    └────────────────────┘ │
└─────────────────────────────┬───────────────────────────────┘
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
│                     React Dashboard                          │
│         Live alerts · AI analysis · Host risk               │
└─────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent | Python 3.13, watchdog, psutil, networkx |
| Backend | FastAPI, SQLAlchemy (async), PostgreSQL, asyncpg |
| Task Queue | Celery, Redis |
| AI | LLM API (OpenAI-compatible endpoint) |
| Frontend | React 18, Tailwind CSS, Recharts, WebSocket |
| Infrastructure | Docker Compose (PostgreSQL + Redis) |

---

## Getting Started

### Prerequisites
- Python 3.13
- Node.js 18+
- Docker & Docker Compose

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/Mohhudib/hybrid-rsentry.git
cd hybrid-rsentry
```

**2. Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your database URL, Redis URL, and AI API key
```

**3. Start infrastructure**
```bash
docker compose up -d
```

**4. Set up Python environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**5. Start the backend**
```bash
uvicorn backend.main:app --reload
```

**6. Start Celery workers**
```bash
set -a && source .env && set +a
PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info
```

**7. Start the agent**
```bash
sudo venv/bin/python -m agent.monitor
```

**8. Start the frontend**
```bash
cd frontend
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000) to access the dashboard.

---

## Environment Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (asyncpg) |
| `REDIS_URL` | Redis connection string |
| `AI_API_KEY` | API key for AI threat analysis |
| `HOST_ID` | Identifier for this endpoint |
| `WATCH_PATH` | Directory to monitor (keep outside project folder) |
| `CANARY_COUNT` | Number of canary files to place (default: 15) |
| `BACKEND_URL` | Backend URL for the agent to report to |

---

## Alert Severity Levels

| Severity | Trigger | Auto-Action |
|---|---|---|
| CRITICAL | Canary file touched | Immediate auto-containment |
| HIGH | Entropy spike + high lineage score | AI analysis + alert |
| MEDIUM | Entropy spike alone | AI analysis + alert |
| LOW | Heartbeat / system events | Logged only |

---

## Project Structure

```
hybrid-rsentry/
├── agent/              # Endpoint monitoring agent
│   ├── monitor.py      # Main watchdog orchestrator
│   ├── graph.py        # Filesystem graph + canary placement
│   ├── entropy.py      # Shannon entropy engine
│   ├── lineage.py      # Process lineage scorer
│   ├── adaptive.py     # Markov chain repositioner
│   ├── containment.py  # Auto-containment pipeline
│   └── client.py       # Backend HTTP client
├── backend/
│   ├── main.py         # FastAPI app entry point
│   ├── models/         # SQLAlchemy ORM + Pydantic schemas
│   ├── routers/        # API route handlers
│   ├── services/       # AI analyst service
│   └── workers/        # Celery task definitions
└── frontend/
    ├── src/
    │   ├── pages/      # Dashboard pages
    │   ├── components/ # Reusable UI components
    │   ├── hooks/      # WebSocket hook
    │   └── api/        # Axios API client
    └── public/
```

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
Entropy delta > threshold?
      │
      ├──YES──▶ Lineage score >= 40? ──YES──▶ COMBINED_ALERT (CRITICAL/HIGH)
      │                               └──NO───▶ ENTROPY_SPIKE (MEDIUM)
      │
      └──NO───▶ Lineage score >= 40? ──YES──▶ PROCESS_ANOMALY (HIGH)
                                     └──NO───▶ Skip (low signal)
      │
      ▼
AI analyst classifies threat → publishes result to dashboard
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request against `develop`

---

## License

This project is licensed under the MIT License.

---

<div align="center">
Built as a cybersecurity capstone project — combining behavioral detection, adaptive defense, and AI-assisted threat analysis.
</div>
