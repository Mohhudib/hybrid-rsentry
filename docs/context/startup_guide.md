# Startup Guide

**Last updated:** 2026-06-09 (eBPF sensor startup added; simulation commands updated; Vite output corrected)

---

## Prerequisites

- Kali Linux (or any Debian-based Linux)
- Docker + Docker Compose installed
- Python 3.13 venv at `~/hybrid-rsentry/venv`
- `.env` file at `~/hybrid-rsentry/.env` (copy from `.env.example` and fill in values)
- Node.js + npm installed

First-time setup:
```bash
cd ~/hybrid-rsentry && bash setup.sh
```

---

## Startup sequence (5 terminals in order)

### Terminal 1 — Docker (Postgres + Redis)
```bash
cd ~/hybrid-rsentry && docker compose up -d
```
Wait until: `docker compose ps` shows both containers as `healthy`.

---

### Terminal 2 — FastAPI Backend
```bash
cd ~/hybrid-rsentry && set -a && source .env && set +a && source venv/bin/activate && uvicorn backend.main:app --reload
```
Wait until: `Application startup complete.`

**Why source .env:** `database.py` reads `DATABASE_URL` via `os.getenv()` at module import time and raises RuntimeError immediately if it's missing.

---

### Terminal 3 — Celery Worker
```bash
cd ~/hybrid-rsentry && set -a && source .env && set +a && PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info
```
Wait until: `celery@hostname ready.`

**Why source .env:** `ai_analyst.py` reads `NVIDIA_API_KEY` and `NVIDIA_API_KEY_ALERTS` via `os.getenv()`. Without them, all AI analysis tasks silently fail with `analysis_failed: True`.

---

### Terminal 4 — Agent (file monitor)

**eBPF sensor (default — requires kernel ≥ 6.19; `lsm=bpf` boot param is optional and enables inline blocking):**
```bash
cd ~/hybrid-rsentry && set -a && source .env && set +a && sudo -E ~/hybrid-rsentry/venv/bin/python -m agent.monitor
```
Wait until: `[ebpf] BPF loaded.` (with `lsm=bpf`: `[ebpf] mode=enforce lsm=True …`; without it: `mode=sigstop`)

**inotify fallback (any kernel, no BCC required):**
```bash
cd ~/hybrid-rsentry && set -a && source .env && set +a && SENSOR_BACKEND=inotify sudo -E ~/hybrid-rsentry/venv/bin/python -m agent.monitor
```
Wait until: `Monitor running. Press Ctrl+C to stop.`

**Why `sudo -E`:** The agent needs root for iptables (containment). `-E` preserves the shell environment through sudo so WATCH_PATH and other vars are not stripped.

---

### Terminal 5 — React Frontend
```bash
cd ~/hybrid-rsentry/frontend && npm start
```
Wait until: `VITE v5.x.x  ready in … ms` and `Local: http://localhost:3000/`

Open browser: **http://localhost:3000**

---

## Quick health check (after all 5 are running)
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"hybrid-rsentry-backend"}

curl http://localhost:8000/api/alerts/counts
# {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0,"TOTAL":0}
```

---

## Trigger a test event manually
```bash
curl -X POST http://localhost:8000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "ATOMIC",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "CANARY_TOUCHED",
    "severity": "CRITICAL",
    "pid": 0,
    "process_name": "test",
    "file_path": "/home/mohammad/Documents/AAA_000.txt",
    "entropy_delta": 0,
    "lineage_score": 0,
    "canary_hit": true,
    "details": {}
  }'
```
You should see a CRITICAL alert appear in the dashboard within ~1 second.

---

## Run a ransomware simulation (safe, sandboxed test directory only)

All simulations create a disposable corpus under `/tmp/rsentry_sim_*`, run the attack, then restore the originals. They will not touch any real files.

```bash
# LockBit 5.0 — two-pass, 16-char random extension, prioritises .vmdk/.vmx
python simulations/sim_lockbit.py

# Akira — intermittent encryption (partial corpus), .akiranew extension
python simulations/sim_akira.py

# Qilin — percent-mode (40 % of corpus), 7-char random extension
python simulations/sim_qilin.py

# Write-offset isolation — proves write-offset layer necessity independently
python simulations/sim_writeoffset_only.py

# Run all simulations sequentially — full detection coverage validation
python simulations/sim_all.py
# Generic patterns (earlier traversal sims):
python simulations/sim_random.py --delay 0.1
python simulations/sim_depth.py  --delay 0.1
python simulations/sim_dfs.py

# Dry run (prints what it would do, no file modifications):
python simulations/sim_random.py --dry-run
```

All simulations support `--validate-defense` to check that containment fired:
```bash
python simulations/sim_lockbit.py --validate-defense
```
---

## Run the forensic walkthrough demo (persistent artifacts for inspection)

Unlike the simulations above (which clean up automatically), `demo_forensic.py`
leaves a persistent corpus on disk so you can inspect before/after state:

```bash
sudo -E ./venv/bin/python demo_forensic.py <family>
```

Families: `akira`, `qilin`, `lockbit`, `entropy_only`, `canary_touch`, `writeoffset_only`

Cleanup when done:
```bash
sudo rm -rf /tmp/rsentry_demo
```
---

## Diagnostic commands

```bash
# See all processes
docker compose ps
ps aux | grep uvicorn
ps aux | grep celery
ps aux | grep agent.monitor

# Recent events in database
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "SELECT event_type, severity, file_path, timestamp FROM events ORDER BY timestamp DESC LIMIT 20;"

# Active alert counts
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "SELECT severity, COUNT(*) FROM alerts WHERE acknowledged=false GROUP BY severity;"

# Watch Redis live traffic
redis-cli subscribe rsentry:alerts

# Clear test alerts (marks all as acknowledged, does not delete)
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "UPDATE alerts SET acknowledged=true, resolved_at=NOW() WHERE acknowledged=false;"
```

---

## Hard rules — never violate these

1. **WATCH_PATH must be outside `~/hybrid-rsentry`** — canary files (AAA_*.txt) corrupt git refs if placed inside the project.
2. **Never run `docker compose down -v`** — the `-v` flag deletes the Postgres data volume permanently.
3. **Never edit `.env.example` thinking it is `.env`** — real secrets live in `.env` (gitignored).

---

## Emergency fixes

**Canary files in git refs:**
```bash
find ~/hybrid-rsentry/.git/refs -name "AAA_*" -delete
```

**Backend won't start (RuntimeError: DATABASE_URL not set):**
```bash
cat ~/hybrid-rsentry/.env | grep DATABASE_URL
# Must show: DATABASE_URL=postgresql+asyncpg://...
# If empty: copy from .env.example and fill in POSTGRES_PASSWORD
```

**Celery AI analysis always failing:**
```bash
cat ~/hybrid-rsentry/.env | grep NVIDIA_API_KEY
# Both NVIDIA_API_KEY and NVIDIA_API_KEY_ALERTS must be set
# Make sure you sourced .env before starting Celery (see Terminal 3 command)
```
