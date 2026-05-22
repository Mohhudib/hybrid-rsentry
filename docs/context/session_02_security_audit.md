# Session 02 — Security Audit

**Date:** 2026-05-12  
**Goal:** Audit the codebase for real security vulnerabilities before public release.  
**Commit:** `a769870`

---

## What was audited

Every file in `backend/`, `agent/`, `docker-compose.yml`, `requirements.txt`, and `.env.example`.

---

## Vulnerabilities found and fixed

### Fix 1 — CVE-2024-33664 + CVE-2024-33663 (python-jose)
**File:** `requirements.txt`  
**Problem:** `python-jose==3.3.0` was listed as a dependency. It had two active CVEs (JWT algorithm confusion and key reuse). It was never actually imported anywhere in the codebase.  
**Fix:** Removed `python-jose==3.3.0` from `requirements.txt` entirely.

---

### Fix 2 — Hardcoded Postgres password in docker-compose.yml
**File:** `docker-compose.yml`  
**Problem:** Three places used the literal string `rsentry_pass` as the Postgres password, even in environment variable defaults.  
**Fix:** Changed all three to `${POSTGRES_PASSWORD:-rsentry_pass}` so the real password comes from `.env`.

---

### Fix 3 — Hardcoded DATABASE_URL fallback in database.py
**File:** `backend/models/database.py`  
**Problem:** `DATABASE_URL` had a hardcoded fallback default containing the Postgres password.  
**Fix:** Removed the fallback. Backend now raises `RuntimeError` immediately at startup if `DATABASE_URL` is not set:
```python
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set.")
```

---

### Fix 4 — .env.example missing POSTGRES_PASSWORD
**File:** `.env.example`  
**Problem:** `POSTGRES_PASSWORD` was not listed in the example file, so new contributors wouldn't know to set it.  
**Fix:** Added `POSTGRES_PASSWORD=` as the first entry in `.env.example`.

---

### Fix 5 — package-lock.json not committed (reproducible builds)
**File:** `frontend/package-lock.json`  
**Problem:** `package-lock.json` was gitignored, meaning `npm install` could pull different versions for different contributors.  
**Fix:** Generated and committed `package-lock.json`.

---

## What was NOT fixed (and why)

### 26 GitHub Dependabot npm alerts
All 26 alerts are inside `react-scripts` (jest, webpack-dev-server, workbox). They are build-time tooling only — not present in the production bundle. Running `npm audit fix --force` installs `react-scripts@0.0.0` which breaks the entire frontend build. These alerts are known and accepted.
