# Changelog

All notable changes to Hybrid R-Sentry are documented here.

---

## [2.2.0] — 2026-06-09

### Fixed

- **LockBit / Qilin speed gap closed** (`agent/monitor_ebpf.py`) — Ultra-fast bulk encryption completing in under 1 second (1 400 files in ~0.6 s for LockBit) was escaping containment because the BPF behavioral score reached `SCORE_ALERT` (50) but not `SCORE_BLOCK` (70), and the Python `_handle_behavior` callback required `entropy >= 6.5` — a check that always returned 0.0 because the simulation had already deleted and restored files before the 1 ms perf buffer poll ran. Three-part fix:
  1. **Signal 6 — hyper-fast unlink burst:** `del_per_sec >= 20 && files_deleted >= 5 → +15` added to `__calc_score`. Pushes LockBit/Qilin score from 60 → 75, crossing `SCORE_BLOCK` before the `alerted` flag is set.
  2. **`_block_on_unlink_score` in `__handle_unlink`:** When score reaches `SCORE_BLOCK`, the PID is immediately written into the `blocked_pids` BPF map at the kernel level. Previously `__handle_unlink` could only submit a `behavior_event` perf buffer entry — it had no path to `blocked_pids.update()`.
  3. **Entropy gate relaxed in `_handle_behavior`:** Changed `if entropy >= 6.5:` → `if entropy >= 6.5 or ev.score >= 70:`. High-confidence kernel scores now trigger SIGSTOP without requiring a readable sample file.

- **Celery `update_host_risk` race on `CONTAINMENT_COMPLETE`** (`backend/routers/events.py`, `backend/workers/tasks.py`) — `update_host_risk.delay()` was called in `events.py` concurrently with `auto_ack_containment`, so the risk recalculation often ran before the acknowledgment was committed and showed a stale elevated score. Fix: removed the call from `events.py`; `update_host_risk.delay()` is now called at the end of `auto_ack_containment` and `auto_ack_by_event` after the DB commit.

### Changed

- **FacetRail toggle** (`frontend/src/pages/AlertsPage.jsx`, `frontend/src/components/FacetRail.jsx`) — A sliders button inside the search bar toggles the FacetRail open/closed; the rail itself has an X close button. Both call the same `setRailOpen` state so they stay in sync.

- **DetailFlyout conditional mount** (`frontend/src/pages/AlertsPage.jsx`) — `DetailFlyout` is now only rendered when an alert is selected (`{selected && <DetailFlyout … />}`). Previously it was always mounted and showed a placeholder, wasting layout space and making a blank third column the default state.

- **PDF / JSON export hardened** (`frontend/src/pages/ReportsPage.jsx`):
  - Replaced `ΔH` column header (U+0394 outside WinAnsiEncoding) with `Entr` — eliminates the jsPDF UCS-2 BE encoding fallback that corrupted the PDF in some viewers.
  - `triggerDownload` now keeps the `<a>` element and object URL alive for 5 seconds before revoking — fixes Firefox silently cancelling downloads where the URL was revoked before the browser started the transfer.

---

## [2.1.1] — 2026-06-08

### Fixed

- **eBPF IGNORE_COMMS enforcement** — `_handle_write` and `_handle_exec` in `monitor_ebpf.py` now check `comm in IGNORE_COMMS` before any flagging or containment, matching the existing guard in `_handle_behavior`. Previously, an inverted `or`-fallback in `_handle_write` fabricated `SILENT_ENCRYPTION` events for safelisted comms (including `dockerd`, `containerd`, `runc`), causing the Docker stack to be SIGKILLed during live testing. `_handle_exec` had the same inversion. Both handlers now mirror `_handle_behavior`'s early `return` pattern; detection sensitivity for non-safelisted processes is unchanged.

- **Docker image — `alembic.ini` not found** — `Dockerfile.backend` now copies `alembic.ini` into the image (`COPY alembic.ini ./`). Previously the backend container crash-looped with `FileNotFoundError: /app/alembic.ini` because the file was never included in the build context. `backend/migrations/env.py` also guards `fileConfig()` with an `os.path.exists()` check so migrations survive a missing ini (defense-in-depth).

- **Alembic migration path resolution** — `backend/main.py._run_migrations()` previously used a CWD-relative `Config("alembic.ini")`, which failed when uvicorn was launched from any directory other than the repo root. Migration config and `script_location` are now resolved to absolute paths derived from the project root, making startup reliable regardless of launch directory.

- **Simulation import safety guard** — `tests/unit/sims/test_simulations.py` tightened the live-watchdog import guard from a plain substring match (`"agent.monitor"`) to a negative-lookahead regex (`agent\.monitor(?!_ebpf)`). The old guard incorrectly blocked the legitimate, side-effect-free `agent.monitor_ebpf` import used by the defense-validation harness in `sim_lockbit.py`.

---

## [2.1.0] — 2026-06-07

### Added
- **GitHub Milestones** — v2.1.0 (CI, Docs & Security, due 2026-06-15) and v2.2.0 (Feature Completeness, due 2026-07-31) created; all 5 open issues assigned to milestones
- **Ransomware detection benchmark** — `bench/` suite measuring detection latency and accuracy for Akira, Qilin, and LockBit 5.0 under realistic conditions
- **Fail-secure agent heartbeat** — agent now sends periodic heartbeat to backend; backend raises alert if heartbeat goes missing (prevents silent agent crash from going undetected)
- **Backend coverage tests** — `tests/unit/backend/` covers routers (`events`, `alerts`, `hosts`), `ai_analyst.py`, and Celery tasks; containment pipeline tests added

### eBPF Hardening (6 improvements)
1. **Write-offset tracking + SILENT_ENCRYPTION detection** — in-place file rewrites (same inode, write at offset 0) now detected as silent encryption; PID frozen immediately
2. **Entropy-based ransomware-extension filter** — extension-rename detection now requires actual high entropy (≥ 6.5 bits) to confirm encryption rather than trusting the extension alone; reduces false positives on legitimate file conversions
3. **Realistic canary content + backdated mtimes** — canary files now contain syntactically valid document fragments (header + Lorem Ipsum body) and have mtimes backdated by 30–365 days; hardened against file-skipping ransomware that reads content or mtime before encrypting
4. **Block backup-destruction tooling at execve** — `vssadmin`, `wbadmin`, `bcdedit`, `cipher.exe`, `sdelete`, and `wmic shadowcopy` are blocked at the BPF `execve` hook; attempts → CRITICAL + containment
5. **Per-PID per-CPU rate limiting** — BPF rate limiting prevents a high-frequency process from flooding the perf ring buffer; excess events are dropped rather than queuing up and delaying detection of concurrent threats
6. **Full 5-syscall behavioral detection system** — `proc_profile` BPF map accumulates per-process counters across `openat`, `vfs_write`, `unlink`, `rename`, `execve`; behavioral scoring fires when score ≥ threshold; `BPF LSM` blocks canary renames with `-EPERM` in nanoseconds; `blocked_pids` BPF map prevents subsequent renames by the offending PID; ransomware family profiling (LockBit 5.0, Akira, ESXi)

### Fixed (major)
- **Canary content** — 4 naming prefixes (`AAA_`, `aaa_`, `ZZZ_`, `zzz_`) all covered in `.gitignore`; `is_canary()` updated to check all 4 prefixes
- **Rapid-exit lineage score** — lowered from 40 to 25 to reduce false positives from short-lived benign processes (package managers, shell scripts)
- **IGNORE_COMMS** — fixed `containerd` deduplication and `glean.dispatche` truncation (BPF `comm` field is 15 chars max)
- **SHA-256 binary cache** — replaced `lru_cache` with mtime-aware cache so binary swaps (e.g. malware replacing a legitimate process) are detected instead of returning a stale MATCH verdict
- **`EntropyEngine._records`** — changed from plain `dict` (FIFO-only eviction) to `OrderedDict` with true LRU eviction; prevents stale entries from accumulating under the 5 000-entry cap
- **Postgres + Redis** — bound to `127.0.0.1` only (`docker-compose.yml`); prevents accidental exposure on multi-interface hosts
- **Evidence directory** — created with `mode=0o700` (was world-readable); evidence from containment is now accessible only to root
- **POSTGRES_PASSWORD** — removed insecure fallback default; `POSTGRES_PASSWORD` is now required in `.env` (like `DATABASE_URL`)
- **`/api/with-events`** — severity/event_type enums serialized via `.value`; was crashing JSON serialization on some Python versions
- **Stale forensic export Redis.get()** — moved sync Redis call off the event loop using `asyncio.to_thread`
- **Frontend** — removed 3 dead components (Sidebar, ForensicExport, AIAnalystPanel); fixed D3 cleanup memory leaks (zoom handler detach, tooltip mounted guard); fixed stale WebSocket URL (now derived from `window.location`); fixed TopBar alert badge counting
- **Removed `.enc` from WHITELISTED_EXTENSIONS** — canonical ransomware extension was incorrectly suppressed
- **`_validate_watch_path()`** — added `.exists()` check; `set_sim()` path validation added
- **SQLAlchemy** — replaced deprecated `lazy='dynamic'` with `lazy='write_only'` (2.x compatibility); reduced pool_size to 5/max_overflow 10 for single-host deployment
- **Celery bumped 5.4.0 → 5.6.3**, starlette bumped 1.0.0 → 1.2.1 (security)

### CI & Code Quality
- **GitHub Actions CI workflow** — backend lint (ruff), Docker build, landing page deploy; Dependabot auto-merge configuration added
- **Ruff linting** — narrowed to F-series; all 25 F401/F841 violations fixed across `agent/` and `backend/`
- **Coverage gate** — 75% minimum coverage enforced in CI for `entropy.py`, `lineage.py`, `adaptive.py`
- **Pinned action versions** — all GitHub Actions workflows use exact commit SHA pins (supply chain security hardening)
- **Pytest consolidation** — pytest config moved to `pyproject.toml`; `pytest.ini` removed; `test_lockbit.py` converted to pytest format; `monitor_ebpf`/`monitor` selftests integrated into CI

### Documentation
- README badges updated (coverage 89%, version v2.1.0), Roadmap & Issue Tracking section added
- `docs/CODE_WALKTHROUGH.md` — added `simulations/` and `tests/` sections; expanded eBPF Phase 3 documentation
- All 11 wiki pages refreshed (Home, Installation, Detection Engine, Architecture, Roadmap)

---

## [2.0.0] — 2026-06-03

### Added
- **SIEM Dashboard redesign** — Kibana-style 3-column layout: **FacetRail** (left filter panel with collapsible field groups) + center (MetricsStrip + stacked AlertsHistogram + sortable AlertsTable) + **DetailFlyout** (right panel on alert click)
- **TopBar** — horizontal navigation bar with 6 tabs (Overview, Alerts, Hosts, Detections, AI Analyst, Reports) + live unacknowledged alert count badge
- **StatusBar** — bottom status bar showing agents, EPS, WebSocket status, last refreshed, cluster name
- **D3 v7 force-directed filesystem graph** — Obsidian-style node graph inside `DetailFlyout` and `EventDetailModal`; zoom, drag, tooltip, selected path pulled to center with blue glow
- **EventDetailModal** — click any event in `TacticalResponseLog` to open a modal with Summary / Entity / MITRE / Filesystem / Raw JSON tabs
- **React 19** upgrade from React 18 (`index.js` → `index.jsx`, all hooks updated, Recharts 2.12.7 React 19 compatible)
- **Vite 5 migration** — replaced Create React App (`react-scripts`) entirely; fixes all 26 npm security alerts embedded in CRA build toolchain; `npm run build` now outputs to `frontend/dist/`
- **Node.js 22** — used in CI (`deploy-landing.yml`) and Docker build (`Dockerfile.frontend`)
- **`process.env` shim** — `vite.config.js` defines `{ 'process.env': {} }` to handle legacy CRA-era env references without code changes
- **Attack simulations** — `simulations/sim_lockbit.py` (LockBit 5.0, two-pass, 16-char extension), `sim_akira.py` (intermittent encryption), `sim_qilin.py` (percent-encryption), shared `sim_common.py` engine
- **LockBit 5.0 evaluation** — `tests/test_lockbit.py` 4-metric test suite: files-before-detection < 3, latency < 500 ms, FP = 0%, coverage = 100% — all targets met
- **Multi-provider AI fallback chain** documented and exposed: Cerebras (optional, fastest) → NVIDIA/Groq key 1 → key 2
- **3D cinematic landing page** — deployed at [https://mohhudib.github.io/hybrid-rsentry/](https://mohhudib.github.io/hybrid-rsentry/) (React Three Fiber + Framer Motion, 8 sections, lazy-loaded 3D canvases)

### Fixed
- **CORS** — `api/client.js` changed from hardcoded `http://localhost:8000` to relative path `''`; Axios now uses `/api/…` routed through Vite proxy regardless of which port Vite picks
- **Duplicate process port conflict** — clean restart procedure documented in Known Issues & Fixes wiki page
- Pydantic version pins loosened (`chore(deps): loosen pydantic version pins`) for broader Python 3.13 compatibility

### Dependencies
- `date-fns` 3 → 4.3.0
- `lucide-react` 0.395 → 1.16.0
- `watchdog` 4 → 6
- `websockets` 12 → 14
- `uvicorn` 0.28 → 0.30

---

## [1.4.0] — 2026-05-29

### Added
- **Landing page deployed** — cinematic 3D landing page live at https://mohhudib.github.io/hybrid-rsentry/
  (React Three Fiber + Framer Motion, all 8 sections, lazy-loaded 3D canvases)
- **Unit test suite** — 71 tests, 89% coverage on `entropy.py`, `lineage.py`, `adaptive.py`, severity logic, and simulation safety (`tests/unit/`)
- **Host-aware PDF export** — `ReportsPage.jsx`: Hosts Overview table on page 1 showing per-host alert breakdown; shortened host UUIDs in Alerts Log; auto-dump of unknown `details` keys in drill-down cards
- **requirements-dev.txt** — pinned dev dependencies for reproducible test environment
- **pytest.ini** — `unit` and `integration` markers configured

### Fixed
- **Canary git corruption prevention** — three-layer fix: `AAA_*.txt` excluded in `.gitignore`; `_validate_watch_path()` in `monitor.py` exits if `WATCH_PATH` is inside a git repo; `_is_safe_target()` in `adaptive.py` blocks Markov repositioner from targeting `.git/`, `/proc/`, `/sys/`, `/dev/`, `/run/`
- Removed accidentally committed canary files `AAA_008.txt` and `simulations/AAA_014.txt`

### Dependencies
- `structlog` bumped 24.2.0 → 25.5.0
- `networkx` bumped 3.3 → 3.6.1

---

## [1.3.0] — 2026-05-26

### Added
- **AI WebSocket fix** — `App.jsx` now handles both `ai_analysis` and `ai_analysis_update` message types; previously AJahmadcyber's tasks.py change broke the AI Analyst page
- **test_event.sh** — one-command pipeline test: sends a `CANARY_TOUCHED` event and verifies the full alert + AI analysis flow
- **start.sh** — one-command startup script that launches all 5 processes and logs to `/tmp/rsentry-*.log`

### Fixed
- docker-compose.yml: Celery container now receives `NVIDIA_API_KEY` and `NVIDIA_API_KEY_ALERTS`
- `entropy.py`: memory cap (5 000 files, LRU evict) + partial reads (65 KB) prevents OOM on large WATCH_PATHs
- `exceptions.py`: smart temp-dir filter — files in `/tmp/` with document extensions bypass the whitelist

---

## [1.2.0] — 2026-05-25

### Added
- **Multi-provider AI fallback chain** — Cerebras (optional, fastest) → NVIDIA/Groq key 1 → NVIDIA/Groq key 2; Groq keys auto-detected by `gsk_` prefix; backward compatible with old `NVIDIA_API_KEY` / `NVIDIA_API_KEY_ALERTS` names
- **Tree-aware containment** — `containment.py` now stops and kills the entire process tree (two-sweep enumeration); collects evidence across up to 48 files per tree
- **dpkg hash verification** — `lineage.py` verifies process binary against 416 K dpkg SHA-256 hashes (MATCH / MISMATCH / UNKNOWN verdicts); SHA-256 cache (512-entry LRU); rapid process exit detection (40-point baseline score)
- **Ransomware extension detection** — `monitor.py`: renames to `.enc`, `.locked`, `.wcry`, `.crypted` etc. fire CRITICAL (if source was a document) or HIGH; canary deletion fires CRITICAL; new files with ransomware extensions fire HIGH
- **PDF forensic export** — `ReportsPage.jsx`: landscape A4, date filter, severity filter, per-alert drill-down cards, AI analysis included; SHA-256 integrity footer on every page
- **Forensic export endpoint** — `GET /api/alerts/{id}/forensic-export`
- **PENDING state** — Celery publishes a PENDING WebSocket message immediately, then updates with the real AI result
- **AI results Redis cache** — 24-hour cache for forensic export
- **Auto-containment for extension renames** — `events.py`: `RANSOMWARE_RENAME` and `RANSOMWARE_CREATED` events trigger containment explicitly

### Fixed
- `ai_analyst.py`: `_get_client_cerebras()` returns `None` instead of raising `RuntimeError` when `AI_API_KEY_CEREBRAS` is not set; `_call_with_fallback()` skips `None` clients silently
- `events.py`: canary-moved events now correctly create alerts (previously silently missed)
- `lineage.py`: score improvements, SHA-256 cache, early exit on rapid process exit, `pid=0` handling

---

## [1.1.0] — 2026-05-22

### Fixed
- `alerts.py`: `analyze_alert` endpoint now passes correct `alert_id` (not `event_id`) to `analyze_alert_ai` task — auto-acknowledge now works end-to-end
- `alerts.py`: embeds `event_id` in `event_data` so the AI Analyst page can display on-demand analysis cards
- `tasks.py`: `analyze_alert_ai` publishes `event_id` in the Redis message so `App.jsx` can match and render the correct card
- `hosts.py`: `/api/hosts/{id}/risk` now returns `alert_count` and `event_count` — HostsPage risk panel no longer shows `—`
- `client.py`: `send_containment_complete` no longer uses wrong dict key `"name"` from `ContainmentResult`
- `CLAUDE.md` + `setup.sh`: startup for Terminal 2 (uvicorn) and Terminal 3 (Celery) now includes `set -a && source .env && set +a`

---

## [1.0.1] — 2026-05-12

### Security
- Removed `python-jose` from `requirements.txt` (CVE-2024-33664, CVE-2024-33663 — algorithm confusion attacks; was never imported)
- `docker-compose.yml`: replaced hardcoded Postgres password with `${POSTGRES_PASSWORD:-rsentry_pass}`
- `database.py`: raises `RuntimeError` if `DATABASE_URL` is not set (removed hardcoded fallback `postgresql://rsentry:rsentry_pass@localhost/rsentry_db`)

---

## [1.0.0] — 2026-04-27

### Added
- **Detection Engine** — Shannon entropy analysis, process lineage scoring, canary file monitoring
- **Markov Chain Repositioner** — adaptive canary placement based on filesystem access patterns
- **Auto-Containment Pipeline** — SIGSTOP → evidence capture → iptables DROP → SIGKILL
- **AI Threat Analyst** — LLM-powered event and alert classification with dual API key rotation
- **System Health Check** — AI analysis of recent activity patterns
- **Auto-ACK** — automatically acknowledges alerts classified as Benign or LOW risk
- **Live Dashboard** — React 18 with real-time WebSocket feed (3 Redis pub/sub channels)
- **Alert Management** — per-alert ACK, bulk acknowledge, live count badges
- **Host Risk Gauge** — radial score that recalculates after every acknowledgement
- **False Positive Suppression** — whitelist system for browsers, package managers, system paths, archives
- **Celery Workers** — AI analysis, WebSocket push, host risk scoring, auto-ACK tasks
- **REST API** — events, alerts (`/counts` endpoint), hosts, containment endpoints
- **Docker Compose** — PostgreSQL + Redis infrastructure
- **Dependabot** — weekly dependency scanning for pip, npm, and Docker
