# Session 01 — Initial Kali Linux Deployment

**Date:** 2026-04-17  
**Goal:** Get Hybrid R-Sentry running end-to-end on Kali Linux for the first time.

---

## What was attempted

Install all dependencies, start all 5 processes, and verify the dashboard loads and events flow through.

---

## Problems hit and how they were fixed

### Problem 1 — PEP 668 pip block
**Symptom:** `pip install -r requirements.txt` blocked by Kali system Python protection ("externally-managed-environment").  
**Fix:** Create a venv first, then install inside it:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### Problem 2 — scipy compile failure (OpenBLAS not found)
**Symptom:** scipy 1.13.1 has no pre-built wheel for Python 3.13 on Kali. Attempts to compile from source and fails with "OpenBLAS/libatlas-base-dev not found."  
**Fix:** Install from apt, then copy into venv:
```bash
sudo apt install -y python3-scipy python3-numpy python3-pandas
cp -r /usr/lib/python3/dist-packages/scipy ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
cp -r /usr/lib/python3/dist-packages/numpy  ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
cp -r /usr/lib/python3/dist-packages/pandas ~/hybrid-rsentry/venv/lib/python3.13/site-packages/
```
**requirements.txt change:** `scipy>=1.14.0`, `numpy>=2.0.0` (allow binary wheels).

---

### Problem 3 — asyncpg ModuleNotFoundError
**Symptom:** venv was created with `--system-site-packages`, so it used system SQLAlchemy which couldn't see venv's asyncpg.  
**Fix:** Recreate venv without `--system-site-packages`. Always invoke `venv/bin/uvicorn` explicitly.

---

### Problem 4 — libopenblas-dev / libatlas-base-dev not found
**Symptom:** These packages don't exist on this Kali version when compiling scipy from source.  
**Fix:** Don't compile scipy — use apt version (see Problem 2).

---

### Problem 5 — asyncpg version incompatibility
**Symptom:** asyncpg==0.29.0 not available for Python 3.13.  
**Fix:** Use `asyncpg==0.31.0` in requirements.txt.

---

### Problem 6 — Celery worker can't find DATABASE_URL
**Symptom:** Celery workers fork before the shell .env is loaded, so DATABASE_URL is empty, causing SQLAlchemy ArgumentError.  
**Fix:** `tasks.py` reads `.env` directly as plain text — no dotenv dependency needed:
```python
def _env(key, default=""):
    value = os.getenv(key, "")
    if value:
        return value
    env_file = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.strip().startswith(f"{key}="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return default
```
Note: `_env()` is only for tasks.py internals. `database.py` and `ai_analyst.py` still use `os.getenv()` — so the shell must have the vars set (see startup guide).

---

### Problem 7 — Agent ignores WATCH_PATH
**Symptom:** Agent started with plain `sudo` drops all environment variables, so WATCH_PATH is missing and the agent watches `/home` instead of `/home/mohammad/Documents`.  
**Fix:** Use `sudo -E` to preserve the environment, and source `.env` first:
```bash
cd ~/hybrid-rsentry && set -a && source .env && set +a && sudo -E ~/hybrid-rsentry/venv/bin/python -m agent.monitor
```

---

### Problem 8 — Canary files corrupting git refs
**Symptom:** WATCH_PATH was set to the project folder. Canary files named `AAA_*.txt` ended up inside `.git/refs/heads/`, corrupting git.  
**Fix:** Always set `WATCH_PATH=/home/mohammad/Documents` (outside the project folder).  
**Emergency recovery:** `find ~/hybrid-rsentry/.git/refs -name "AAA_*" -delete`

---

### Problem 9 — Python 3.13 + Celery fork asyncio crash
**Symptom:** `asyncio.run()` fails inside forked Celery workers on Python 3.13 with "There is no current event loop."  
**Fix:** Create a new event loop per task:
```python
def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
```

---

## End state

All 5 processes running. Dashboard loads at http://localhost:3000. Events flow from agent → backend → Celery → Redis → WebSocket → frontend.
