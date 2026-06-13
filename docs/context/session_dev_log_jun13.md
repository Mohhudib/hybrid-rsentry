# Dev Log — Jun 13 Session
# Hybrid R-Sentry: Full Cleanup, Feature Sprint & Hardening

**Date:** June 13, 2026  
**Total commits this session:** 66  
**Total repo commits (all time):** 392  
**Branch:** main  
**Pushed to:** https://github.com/Mohhudib/hybrid-rsentry

---

## Overview

This session covered the full 7-day weekly cleanup plan: dead code removal
across every layer of the stack, documentation accuracy fixes, script portability
fixes, and a complete feature sprint adding Bulk ACK, CSV export, sound alerts,
per-host timelines, an Exception Management UI, a simulation trigger API, and
integration tests.

---

## Bug Fix — Dual Dashboard (1 commit)

**Problem:** Two UIs showed simultaneously when launching via `start.sh`.
The `rsentry_frontend` Docker container (old nginx build, sidebar navigation,
v1.0.0) was binding port 3000 before the Vite dev server. The old UI always
won over the new TopBar SIEM dashboard.

**Fix:** Removed the entire `frontend` service block from `docker-compose.yml`.
Docker now manages infrastructure only (Postgres + Redis + Backend + Celery).
The Vite dev server (`npm start`) is the sole frontend.

**File changed:** `docker-compose.yml`

---

## Wiki Fixes (7 commits)

| File | Fix |
|---|---|
| `Roadmap.md` | Issue #51 description said `tests/integration/` was empty — actually has 7 live test files |
| `Architecture.md` | Added `sim_dfs.py` to simulations table |
| `Architecture.md` | Added `sim_depth.py` to simulations table |
| `Architecture.md` | Added `sim_random.py` to simulations table |
| `Architecture.md` | Added `sim_all.py` to simulations table |
| `Detection-Engine.md` | Added `sim_depth.py` to attack simulation table |
| `Detection-Engine.md` | Added `sim_all.py` to attack simulation table |

---

## Agent Dead Code Cleanup (11 commits)

Removed constants, functions, and imports that were defined but never called.

| Commit | File | What was removed |
|---|---|---|
| `dc546b6` | `agent/graph.py` | `CANARY_PREFIX = "AAA_"` constant — never used after refactor |
| `ad7bfac` | `agent/graph.py` | `CANARY_CONTENT` constant — replaced by `_canary_content()` |
| `221d19d` | `agent/graph.py` | `strategy` parameter from `place_canaries()` — always ignored |
| `f936875` | `agent/monitor.py` | `CANARY_STRATEGY = os.getenv(...)` env var — dead config |
| `dc749fa` | `agent/monitor.py` | `strategy=CANARY_STRATEGY` call site in `place_canaries()` call |
| `461e670` | `agent/containment.py` | `_read_uid(pid)` function — leftover from old iptables UID check |
| `7988912` | `agent/entropy.py` | `EntropyRecord.as_series()` method — defined but never called |
| `9a2b728` | `agent/monitor_ebpf.py` | `_PRIORITY_EXTS: Set[str]` constant block — never referenced |
| `40a162f` | `agent/lineage.py` | Moved `import glob` from inside function body to module top level |
| `9d33b51` | `agent/lineage.py` | Renamed `WEIGHT_HASH_MISMATCH` → `WEIGHT_EXE_UNREADABLE` (more accurate) |
| `950237e` | `agent/exceptions.py` | Fixed triple blank lines → double blank lines (PEP 8 E303) |

---

## Backend Dead Code Cleanup + Version Bump (12 commits)

| Commit | File | Change |
|---|---|---|
| `ebaca9a` | `backend/services/ai_analyst.py` | Wired `GROQ_BASE_URL` constant in `_get_client_events()` |
| `1742c09` | `backend/services/ai_analyst.py` | Wired `GROQ_MODEL` constant in `_get_client_events()` |
| `8eaa778` | `backend/services/ai_analyst.py` | Wired `GROQ_BASE_URL` constant in `_get_client_alerts()` |
| `3be84d3` | `backend/services/ai_analyst.py` | Wired `GROQ_MODEL` constant in `_get_client_alerts()` |
| `c094c7f` | `backend/services/ai_analyst.py` | Removed dead `GROQ_RATE_DELAY = 0.5` constant |
| `6bc30e5` | `backend/services/ai_analyst.py` | Removed dead `CEREBRAS_RATE_DELAY = 0.5` constant |
| `b0173d5` | `backend/services/ai_analyst.py` | Removed dead `_RATE_KEY_CEREBRAS` constant |
| `9f43003` | `backend/services/ai_analyst.py` | Extracted `_make_openai_client()` helper to deduplicate both client functions |
| `c0aa00e` | `backend/routers/ws.py` | Removed dead `publish_to_channel()` async function (8 lines) |
| `558b745` | `backend/routers/ws.py` | Removed unused `from typing import Any` import |
| `0891e3d` | `backend/main.py` | Bumped `version="1.0.0"` → `version="2.2.0"` in FastAPI constructor |
| `2429ab6` | `backend/main.py` | Updated root endpoint response string to `v2.2.0` |

---

## Frontend Dead Code Cleanup + Event Types (9 commits)

| Commit | File | Change |
|---|---|---|
| `dc305df` | `frontend/src/api/client.js` | Removed dead `getEvent(id)` — never imported anywhere |
| `61b204a` | `frontend/src/api/client.js` | Removed dead `getAlert(id)` — never imported anywhere |
| `db1bcc0` | `frontend/src/api/client.js` | Removed dead `getHost(id)` — never imported anywhere |
| `8b3c0cf` | `frontend/src/components/AlertsTable.jsx` | Removed dead `STATUS_LABEL` constant — defined, never used |
| `5b3eab2` | `frontend/src/components/FileSystemTree.jsx` | Removed unused `useRef` from React import |
| `e0bcdd6` | `frontend/src/constants/eventTypes.js` | Added `RANSOMWARE_RENAME` to `RULE_NAME` map |
| `7ac8294` | `frontend/src/constants/eventTypes.js` | Added `RANSOMWARE_CREATED` to `RULE_NAME` map |
| `be080a4` | `frontend/src/constants/eventTypes.js` | Added `RANSOMWARE_RENAME` → MITRE T1486 mapping |
| `24abc22` | `frontend/src/constants/eventTypes.js` | Added `RANSOMWARE_CREATED` → MITRE T1486 mapping |

---

## Documentation Fixes (9 commits)

### `docs/context/project_architecture.md`

| Commit | Fix |
|---|---|
| `aa1f7f3` | Updated "Last updated" date from 2026-05-22 to 2026-06-13 |
| `68ef601` | Stack table: React 18 → React 19 + Vite 5 |
| `3b173b3` | AI layer: "NVIDIA API" → "Cerebras → NVIDIA → Groq fallback chain" |
| `25ec0fd` | Agent row: added eBPF/BCC to technology list |
| `8a02ec0` | Canary file description: now shows all 4 prefixes (AAA_, aaa_, ZZZ_, zzz_) |
| `6a74a16` | `ai_analyst.py` key file map: updated to reflect multi-provider |
| `1921a5c` | AI analysis paths table: env var names updated to canonical aliases |

### `docs/context/startup_guide.md`

| Commit | Fix |
|---|---|
| `b2d1559` | `lsm=bpf` boot param marked as optional — enables inline block, falls back to SIGSTOP without it |
| `2047357` | Removed stale "Never run `npm audit fix --force`" rule — no longer relevant after Vite migration |

---

## Scripts Fix (2 commits)

Both `restart_celery.sh` and `restart_worker.sh` had `/home/mohammad/hybrid-rsentry`
hardcoded. Any other user's machine would silently fail.

**Fix:** Both scripts now resolve the project root dynamically:
```bash
RSENTRY_ROOT="$(cd "$(dirname "$0")" && pwd)"
```

| Commit | File |
|---|---|
| `d0ea6a5` | `restart_celery.sh` |
| `84d50b8` | `restart_worker.sh` |

---

## Maintenance (2 commits)

| Commit | Change |
|---|---|
| `dca9313` | `.gitignore`: added `.env.save` and `.env.save.*` patterns |
| `7a241db` | `tests/test_simulations.py`: 6 smoke tests for all simulation modules + sim_all family list |

---

## New Features (15 commits)

### Bulk ACK
Acknowledge all open alerts in one click instead of one at a time.

- **Backend** (`2d14a5b`): `POST /api/alerts/acknowledge-all` — bulk UPDATE on unacknowledged alerts, triggers host risk recalculation for all affected hosts
- **Frontend** (`e413322`): `acknowledgeAllAlerts()` added to `client.js`
- **Frontend** (`05d0012`): Bulk ACK button added to Alerts page toolbar

### CSV Export
Download the full alert list with all event details as a spreadsheet.

- **Backend** (`2d14a5b` → fixed `8f3c64b`): `GET /api/alerts/export/csv` — joins Alert + Event tables, returns 14-column CSV including `event_type`, `file_path`, `process_name`, `entropy_delta`, `lineage_score`, `canary_hit`
- **Frontend** (`05d0012`): CSV button in Alerts page toolbar opens download in new tab

### Auto-Refresh Interval Selector
Previously the Alerts page refreshed every 10 seconds with no way to change it.

- **Frontend** (`05d0012`): Dropdown selector added — 5s / 10s / 30s / Off

### Extended Search
The Alerts page search bar now searches across more fields.

- **Frontend** (`05d0012`): Added `file_path`, `process_name`, `event_type` to search in addition to host/severity/ID. Event data is joined in during fetch so these fields are available client-side.

### Sound Alert on CRITICAL
A short beep plays in the browser when a CRITICAL alert arrives via WebSocket.

- **Frontend** (`e7b16c2`): `_beep()` using the Web Audio API (880 Hz sine wave, 0.4s). No external dependency. Called from `handleWsMessage` when `msg.severity === 'CRITICAL'`.

### eBPF Sensor Badge in StatusBar
The status bar now shows which sensor backend the agent is running.

- **Frontend** (`838c5c9`): Chip showing `eBPF` or `inotify` (polls `/health` for `sensor_backend` field, defaults to `eBPF`). Version label updated from `v1.0.0` → `v2.2.0`.

### Per-Host Event Timeline
Each host card in the Hosts page now shows a collapsible recent events list.

- **Frontend** (`33adc79`): `HostTimeline` component added inside `HostsPage.jsx`. Fetches last 10 events for the host on expand. Shows time, severity dot, event type, and filename.

### Clear All Alerts
Bulk-resolve all open alerts with one button — same as the manual SQL command.

- **Backend** (`d982d17`): `POST /api/alerts/clear-all` — sets `acknowledged=True` and `resolved_at=now()` for all open alerts, triggers host risk recalculation
- **Frontend** (`bc0b0ec`): "Clear" button (red label, trash icon) added to Alerts page toolbar with confirmation dialog

### Exception Management Page
Browse all agent whitelist rules from the dashboard without opening Python files.

- **Backend** (`61b5a9f`): `GET /api/exceptions` — returns all 5 rule sets from `agent/exceptions.py` (processes, path prefixes, extensions, temp-dir prefixes, suspicious-in-temp extensions)
- **Frontend** (`0b32f5c`): New `ExceptionsPage.jsx` with collapsible sections per rule group. Added "Exceptions" tab to TopBar nav. Wired into App.jsx routing.

### Simulation Trigger API
Query which simulation commands to run without memorising module names.

- **Backend** (`f42f28e`): `POST /api/simulate/{family}` — accepts family name (lockbit / akira / qilin / all), returns the exact CLI command to run with the active venv. `GET /api/simulate` lists available families.

### AI Pipeline Integration Test
End-to-end test verifying the full event → Celery → AI → Redis pub/sub chain.

- **Tests** (`fc97f05`): `tests/integration/test_ai_pipeline.py` — POSTs a synthetic CRITICAL event, subscribes to `rsentry:ai` Redis channel, waits up to 60s for an analysis message, asserts `verdict`, `risk_score`, and `explanation` are present. Auto-skips if backend or Redis is not running (safe for CI).

### CSV Export Fix
The first version of CSV export only included alert metadata (IDs, dates). No event details.

- **Backend** (`8f3c64b`): Rewrote the query to `JOIN` Alert with Event. CSV now has 14 columns: `alert_id`, `host_id`, `severity`, `acknowledged`, `alert_created_at`, `resolved_at`, `event_type`, `event_timestamp`, `pid`, `process_name`, `file_path`, `entropy_delta`, `lineage_score`, `canary_hit`.

---

## Summary Table

| Category | Commits |
|---|---|
| Bug fix (dual dashboard) | 1 |
| Wiki fixes | 7 |
| Agent dead code cleanup | 11 |
| Backend dead code cleanup + version bump | 12 |
| Frontend dead code cleanup + event types | 9 |
| Documentation fixes | 9 |
| Scripts portability fix | 2 |
| Maintenance (.gitignore, tests) | 2 |
| New features | 15 |
| **Total (this session)** | **66** |
| **Total repo commits (all time)** | **392** |
