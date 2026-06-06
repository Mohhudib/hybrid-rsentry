# Session 06 — Full Code Review

**Date:** 2026-06-06  
**Scope:** Entire codebase — bugs · security · dead code · improvement opportunities  
**Methodology:** 4 parallel deep-read review agents (backend/, agent/, frontend/src/, simulations+tests+landing/) with structured findings  
**Prior sessions baseline:** session_02 (security audit) and session_04 (full review) findings are NOT re-reported unless regressed  
**Out of scope this pass:** implementing fixes — this is a findings-only report for triage

---

## What changed since the last review (2026-05-22)

All of the following landed AFTER session_04 and are reviewed fresh:

- BPF-LSM kernel-level canary blocking (`LSM_PROBE path_rename`, -EPERM)
- 5-syscall behavioral scoring engine (openat/vfs_write/unlink/rename/execve)
- Silent encryption detection (entropy ≥ 6.5 on in-place rewrites)
- Static Docker network 192.168.100.0/24
- `load_dotenv()` auto-loading `.env` at agent startup
- Markov repositioner disabled for eBPF backend
- 4-prefix canary system (AAA_/aaa_/ZZZ_/zzz_) + `.gitignore` gap (already fixed 2026-06-06)
- `/api/alerts/with-events` endpoint
- `--workers 2` added to `Dockerfile.backend`
- ruff lint passes, 71 unit tests passing

---

## Summary table

| Severity | Backend | Agent | Frontend | Sim+Test+Landing | **Total** |
|---|---|---|---|---|---|
| CRITICAL | — | — | 2 | — | **2** |
| HIGH | 4 | 5 | 8 | 2 | **19** |
| MEDIUM | 7 | 9 | 6 | 7 | **29** |
| LOW | 6 | 10 | 5 | 5 | **26** |
| **Total** | **17** | **24** | **21** | **14** | **76** |

---

## CRITICAL findings

### [CRITICAL] Bug — frontend/src/components/AlertsTable.jsx (~line 28)
**Finding**: `riskScore()` applies `alert.id % N` arithmetic on a UUID string, producing `NaN` for every row.
**Detail**: `alert.id` is a UUID string. In JavaScript `"uuid-string" % 10 === NaN`. Every row in `AlertsTable` shows a broken risk meter and the text "NaN" where a score should appear.
**Recommendation**: Replace with a deterministic hash: `parseInt(alert.id.replace(/-/g,'').slice(0,8), 16) % N` gives a stable numeric value. Or use flat per-severity defaults (CRITICAL → 95, HIGH → 72, MEDIUM → 48, LOW → 25).

---

### [CRITICAL] Bug — frontend/src/hooks/useWebSocket.js (~line 24)
**Finding**: The keepalive ping interval leaks if the WebSocket `onclose` fires asynchronously after unmount.
**Detail**: The `useEffect` cleanup calls `wsRef.current?.close()` but does NOT clear `ws._pingInterval`. If `onclose` fires after the React tree is torn down, `setConnected(false)` is called on an unmounted component. If `wsRef.current` is replaced during a reconnect race, the old socket's interval is permanently lost.
**Recommendation**: Store the ping interval in a `useRef` and clear it explicitly in the `useEffect` cleanup, before `ws.close()`.

---

## HIGH findings

### Backend

### [HIGH] Bug — backend/routers/alerts.py (~line 94, 98)
**Finding**: `/with-events` response returns raw SQLAlchemy Enum objects for `severity` and `event_type`, not strings.
**Detail**: The endpoint builds a plain `dict` without a Pydantic model. FastAPI's JSON serializer calls `str()` on Enum objects, which for `str`-based Enums yields `"Severity.CRITICAL"` instead of `"CRITICAL"`. All other paths in the file explicitly call `.value`. The PDF report frontend receives malformed severity strings.
**Recommendation**: Change `alert.severity` → `alert.severity.value` and `event.event_type` → `event.event_type.value` in the `/with-events` dict construction.

---

### [HIGH] Bug — backend/routers/alerts.py (~line 82)
**Finding**: `date_from`/`date_to` filter strings in `/with-events` are compared directly against a timezone-aware `TIMESTAMPTZ` column, which raises a type error with asyncpg at runtime.
**Detail**: Both query parameters are typed `Optional[str]` and passed raw into SQLAlchemy `.where(Alert.created_at >= date_from)`. asyncpg is strict about types and will raise a type mismatch error. The endpoint returns 500 whenever the PDF report generator passes a date filter. No try/except wraps this path.
**Recommendation**: Parse with `datetime.fromisoformat(date_from)` before the comparison, returning 422 on parse failure.

---

### [HIGH] Bug — backend/routers/ws.py + Dockerfile.backend
**Finding**: `--workers 2` in the Dockerfile CMD means each worker has its own `ConnectionManager` and Redis subscription — WebSocket clients connected to one worker never receive broadcasts from events handled by the other worker.
**Detail**: When Celery publishes to `rsentry:alerts`, only the worker whose Redis pub/sub subscription is active relays the message to its connected WebSocket clients. Clients on the other worker get no alerts. This does not affect the manual dev startup (`uvicorn --reload` is single-process) but breaks the Docker deployment.
**Recommendation**: Change `--workers 2` to `--workers 1` in `Dockerfile.backend`. Alternatively, move broadcasting fully to Redis pub/sub with one subscription per connection (already partially in place) so every worker relays to its own clients.

---

### [HIGH] Bug — backend/services/ai_analyst.py (~line 229)
**Finding**: `forensic_export` calls the synchronous `redis_lib.Redis.get()` inside an `async def` FastAPI route, blocking the entire event loop thread.
**Detail**: `ai_analyst._get_redis()` returns the synchronous `redis.Redis` client. Calling `.get()` on it from the async route does a blocking socket read on the event loop thread, stalling all WebSocket and HTTP handling for that worker until Redis responds.
**Recommendation**: Use `asyncio.get_event_loop().run_in_executor(None, r.get, key)` to push the sync call off the event loop, or switch this path to `redis.asyncio`.

---

### Agent

### [HIGH] Bug — agent/monitor_ebpf.py (~line 809)
**Finding**: `run_sensor()` crashes at startup if `/sys/kernel/security/lsm` is absent (securityfs not mounted).
**Detail**: `Path("/sys/kernel/security/lsm").read_text()` has no existence check. If securityfs is not mounted (minimal containers, hardened kernels), this raises `FileNotFoundError` and kills the sensor before any probes load.
**Recommendation**: Guard: `lsm_path = Path("/sys/kernel/security/lsm"); lsm_active = "bpf" in lsm_path.read_text() if lsm_path.exists() else False`.

---

### [HIGH] Bug — agent/monitor_ebpf.py (~line 1048)
**Finding**: The main eBPF perf buffer poll loop uses `timeout=0` (non-blocking), creating a 100% CPU busy-wait on an idle system.
**Detail**: `b.perf_buffer_poll(timeout=0)` returns immediately when there are no events, then the loop spins immediately again. On a quiet system this pins one CPU core at 100% indefinitely.
**Recommendation**: Change to `b.perf_buffer_poll(timeout=100)` to block for up to 100ms, reducing idle CPU to near zero.

---

### [HIGH] Bug — agent/monitor_ebpf.py (~lines 385, 387)
**Finding**: `_inode_path_cache` and `_write_burst` are class-level dicts, shared across all `DetectionEngine` instances — the selftest creates 15 instances and all share the same state.
**Detail**: Python class-level dict assignments produce a single shared dict. In selftests (`eng`, `eng2`, ..., `eng15`), inode→path mappings and write burst counters from one engine pollute all others. If the sensor restarts without a process restart, stale inode mappings persist.
**Recommendation**: Move to `__init__`: `self._inode_path_cache: dict = {}` and `self._write_burst: dict = {}`.

---

### [HIGH] Bug — agent/adaptive.py (~line 125)
**Finding**: Stationary distribution normalization divides by `stationary.sum()` without checking for zero, silently producing NaN that corrupts canary repositioning.
**Detail**: `stationary /= stationary.sum()` can produce `[nan, nan, ...]` for disconnected graph matrices or degenerate eigenvectors. `except LinAlgError` does not catch this. The NaN propagates to `np.argsort(stationary)`, producing bogus hotspot directories and silently reducing canary detection coverage.
**Recommendation**: After computing `stationary`, add: `if stationary.sum() == 0: raise np.linalg.LinAlgError("zero eigenvector")` to fall through to the row-sum fallback.

---

### [HIGH] Bug — agent/monitor_ebpf.py (~line 643, 729)
**Finding**: `ev.ppid` is populated with the calling thread's TID rather than the true parent PID in rename and write event structs.
**Detail**: `ev.ppid = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF)` extracts the lower 32 bits, which is the TID — not PPID. For multi-threaded processes (Python with greenlets, Java apps) this produces a wrong PPID in stored events and forensic data. The `sys_enter_execve` handler correctly uses `task->real_parent->tgid`.
**Recommendation**: In `__handle_rename` and `kprobe__vfs_write`, get PPID via: `struct task_struct *task = (struct task_struct *)bpf_get_current_task(); u32 ppid = task->real_parent ? task->real_parent->tgid : 0;`

---

### Frontend

### [HIGH] Bug — frontend/src/hooks/useWebSocket.js (~line 16)
**Finding**: WebSocket URL falls back to `ws://localhost:8000` — hardcoded, bypasses the Vite proxy, breaks in any non-localhost environment.
**Detail**: `new WebSocket('ws://localhost:8000/ws/alerts')` makes a direct connection rather than going through the Vite `/ws` proxy. In any deployed scenario (different host, reverse proxy, Docker) this fails silently.
**Recommendation**: Derive from `window.location`: `const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'; const WS_URL = \`${proto}//\${window.location.host}\`;`

---

### [HIGH] Bug — frontend/src/components/AIAnalystPanel.jsx (~line 5) and frontend/src/pages/AIAnalystPage.jsx (~line 5)
**Finding**: `axios.post(\`${API_URL}/api/ai/health\`, ...)` uses a hardcoded `http://localhost:8000` fallback that bypasses the Vite proxy.
**Detail**: All other API calls use the relative-path `api/client.js`. These two health-check calls use a full absolute URL, causing CORS failures or wrong-host errors in any deployed environment. `VITE_API_URL` is not documented in `.env.example`.
**Recommendation**: Import `api` from `'../api/client'` and call `api.post('/api/ai/health', { events })`. Remove the `API_URL` constant and `axios` import from both files.

---

### [HIGH] Bug — frontend/src/components/AlertsTable.jsx (~line 51, 113)
**Finding**: `AlertsTable` reads `alert.event_type` directly, but `AlertResponse` does not include `event_type` — it belongs to the linked `Event` object.
**Detail**: The `RULE_NAME` and `MITRE` lookups always fall back to defaults. Sorting by `'rule'` always compares empty strings. The rule column always shows `'Detection Alert'` regardless of the actual event type.
**Recommendation**: Switch `AlertsPage` to the `/api/alerts/with-events` endpoint (already used by `ReportsPage`), or join alert objects with the separately fetched events array already available in `AlertsPage.jsx`.

---

### [HIGH] Bug — frontend/src/components/DetailFlyout.jsx (~line 53)
**Finding**: `getAlertEvidence()` inside `useEffect` has no `AbortController` — sets state on unmounted component or stale alert ID when user navigates quickly.
**Detail**: Rapid clicking through alerts or navigating away while a request is in flight causes `setEvidence(r.data)` to fire on a component showing a different alert, producing stale flicker.
**Recommendation**: Add `AbortController` in `useEffect` cleanup; pass `signal` to `getAlertEvidence`.

---

### [HIGH] Bug — frontend/src/components/FileSystemGraph.jsx (~line 146)
**Finding**: `svg.call(zoom)` re-attaches a new zoom behavior on every effect run without removing the previous one.
**Detail**: When `events` or `highlightPath` changes, the cleanup only calls `sim.stop()`. The previous zoom handler accumulates. Concurrent `autoFit()` calls from the stopping and starting simulation can race to apply conflicting `zoom.transform` to the same SVG.
**Recommendation**: In cleanup: `svg.interrupt(); svg.on('.zoom', null); sim.stop();`

---

### [HIGH] DeadCode — frontend/src/components/Sidebar.jsx, ForensicExport.jsx, AIAnalystPanel.jsx
**Finding**: Three complete components are imported nowhere and never rendered — dead code adding ~400 lines to the bundle.
**Detail**: `Sidebar.jsx` was replaced by `TopBar.jsx` in the SIEM redesign. `ForensicExport.jsx` is superseded by inline export logic in `ReportsPage.jsx`. `AIAnalystPanel.jsx` is superseded by `pages/AIAnalystPage.jsx`.
**Recommendation**: Delete all three files.

---

### Simulations + Tests + Landing

### [HIGH] Bug — landing/src/components/three/NodeSphere.jsx (~line 78)
**Finding**: `colorsRef.current` is mutated directly in the render body (outside any hook), causing concurrent-mode tearing.
**Detail**: `colorsRef.current = nodeColors` on line 78 executes on every React render pass. ESLint flags this with the `react-hooks/refs` rule. Since `colorsRef` is never actually read anywhere in the component, it is also dead code.
**Recommendation**: Remove line 78. If the Float32Array needs to persist across renders, move the assignment into the initialising `useEffect`.

---

### [HIGH] Bug — landing/src/components/three/ArchGraph.jsx (~line 57) and SolarSystem.jsx (~line 31)
**Finding**: `new THREE.Color(node.color)` is allocated on every render without being used, creating GC pressure and indicating dead color-transition logic.
**Detail**: In both files, a `THREE.Color` object is constructed but `color` is never referenced — the original string `node.color` / `info.color` is used everywhere in JSX instead. This produces a fresh allocation on every re-render of every node.
**Recommendation**: Delete both unused `color` variables. If colour transitions are planned, cache via `useRef` inside `useFrame`.

---

## MEDIUM findings

### Backend

### [MEDIUM] Bug — backend/workers/tasks.py (~line 23)
**Finding**: `_env()` does not strip inline `# comment` suffixes from `.env` values, which would silently corrupt Redis/Postgres URLs containing comments.
**Recommendation**: After splitting on `=`, strip inline comments: `value = raw.split(" #")[0].strip().strip('"').strip("'")`

---

### [MEDIUM] Bug — backend/workers/tasks.py (~line 166)
**Finding**: `event_data.get('event_id', event_id)` in the AI cache key is dead code — `event_data` never contains `'event_id'`.
**Recommendation**: Simplify to `f"rsentry:ai_analysis:{event_id}"` directly.

---

### [MEDIUM] Bug — backend/workers/tasks.py (~lines 176–177)
**Finding**: When `analysis_failed=True`, the error dict is both published to WebSocket AND cached in Redis for 24 hours before the early-return check.
**Detail**: The `if result.get("analysis_failed"): return` guard fires after the cache `set` and the `ai_analysis_update` publish, not before. Forensic export reads and returns the error dict as `ai_analysis`, confusing incident responders.
**Recommendation**: Move the failure check to before both the Redis `set` and the WebSocket publish.

---

### [MEDIUM] Security — backend/services/ai_analyst.py (~lines 239, 269, 344)
**Finding**: All three `analyze_*` functions apply only `_RATE_KEY_CEREBRAS` rate limiting, regardless of which provider actually handles the call. `_RATE_KEY_GROQ` and `_RATE_KEY_NVIDIA` are dead code.
**Detail**: When falling back to NVIDIA, the 0.5s Cerebras delay is applied instead of the 3.0s NVIDIA delay, allowing burst calls that will hit NVIDIA rate limits rapidly.
**Recommendation**: Apply the rate limit for the provider actually called, or always apply `NVIDIA_RATE_DELAY` as the conservative default when any fallback occurs.

---

### [MEDIUM] Bug — backend/models/schemas.py (~lines 56, 57, 93)
**Finding**: Three relationships use `lazy="dynamic"` — a SQLAlchemy 1.x legacy API removed in future versions.
**Recommendation**: Replace with `lazy="write_only"` (SQLAlchemy 2.0+ preferred for large collections never loaded eagerly).

---

### [MEDIUM] Improvement — backend/routers/hosts.py (~line 47) and backend/routers/alerts.py (~line 42)
**Finding**: Both `host_risk_summary` and `alert_counts` execute 5 separate database queries (4 per-severity + 1 total) — a classic N+1 pattern.
**Recommendation**: Replace the severity loop with a single `SELECT severity, COUNT(*) ... GROUP BY severity` query, matching the pattern already used in `tasks.py:update_host_risk`.

---

### [MEDIUM] Security — docker-compose.yml (~line 16)
**Finding**: `${POSTGRES_PASSWORD:-rsentry_pass}` silently uses a known-public password if `.env` is absent or the variable is unset.
**Detail**: Postgres port 5432 is exposed on all interfaces — a missing `.env` on first clone leaves a network-reachable database with a publicly-known password.
**Recommendation**: Remove the default fallback (`${POSTGRES_PASSWORD}` only). Also bind both Postgres and Redis ports to `127.0.0.1` only (`127.0.0.1:5432:5432`, `127.0.0.1:6379:6379`).

---

### [MEDIUM] Security — docker-compose.yml (~lines 18, 39)
**Finding**: Both Postgres (5432) and Redis (6379) ports are exposed to all network interfaces on the host, not just `127.0.0.1`.
**Detail**: An unauthenticated Redis instance listening on `0.0.0.0:6379` is directly network-accessible. The static Docker subnet applies only inside the bridge network, not to host-level port bindings.
**Recommendation**: Change to `127.0.0.1:5432:5432` and `127.0.0.1:6379:6379`. Add Redis authentication (`requirepass`) in the Compose service config.

---

### Agent

### [MEDIUM] Bug — agent/graph.py (~line 71)
**Finding**: `is_canary()` hard-codes `name.endswith(CANARY_SUFFIX)` (`.txt` only) — misses `.docx`, `.xlsx`, `.pdf`, `.db`, `.vmdk` canaries seeded by `monitor_ebpf.seed_canaries()`.
**Detail**: When the eBPF backend falls back to `_ebpf.seed_canaries()` for canary placement, it creates files with `ATTRACTIVE_EXTS` (`.docx`, `.xlsx`, `.pdf`, `.db`, `.vmdk`). The inotify backend's `on_deleted` and `on_moved` handlers call `self.fs_graph.is_canary()` — a renamed `AAA_rsentry_canary0.docx` is NOT detected as a canary on the inotify path.
**Recommendation**: Remove the suffix requirement: `return name.startswith(("AAA_", "aaa_", "ZZZ_", "zzz_"))`. Detection should be prefix-based only, consistent with `.gitignore` and the detection-engine check in `monitor_ebpf.py:135`.

---

### [MEDIUM] Bug — agent/monitor_ebpf.py (~lines 591–613, BPF C)
**Finding**: `read_bytes` and `unique_dirs` fields in `proc_profile_t` are never written by any BPF probe — Signal 4's write/read ratio is permanently zero, making `+15` scoring points dead code.
**Recommendation**: Either add a `kprobe__vfs_read` handler to populate `read_bytes` and directory tracking for `unique_dirs`, or remove the dead fields and adjust the max possible behavioral score accordingly.

---

### [MEDIUM] Bug — agent/monitor_ebpf.py (~line 1010)
**Finding**: `_handle_behavior` emits a `PROCESS_ANOMALY` alert and queues scoring even when `sample_path` is empty (no file sample found, zero entropy evidence).
**Detail**: `if entropy >= 6.5 or not sample_path:` — the `or not sample_path` branch fires for any high-scoring process with no open files, including system daemons, producing spurious HIGH alerts with `entropy_sample=0.0`.
**Recommendation**: Change to `if entropy >= 6.5:` only. Log a debug message when `not sample_path` to track coverage gaps without alerting.

---

### [MEDIUM] Bug — agent/monitor.py (~line 86)
**Finding**: `_validate_watch_path()` silently succeeds when `WATCH_PATH` does not exist — the agent starts watching a non-existent path.
**Detail**: `Path(watch_path).resolve(strict=False)` (the Python default) returns the path as-is even if it doesn't exist. The agent starts; the inotify observer raises `RuntimeError`; the eBPF backend silently monitors nothing.
**Recommendation**: Add: `if not Path(watch_path).exists(): logger.critical("WATCH_PATH=%s does not exist", watch_path); sys.exit(1)`

---

### [MEDIUM] Security — agent/containment.py (~lines 19, 113)
**Finding**: Evidence is written to `/tmp/rsentry_evidence/` with world-readable permissions (755), and the captured `environ` artifact contains the contained process's full environment — including any secrets.
**Detail**: `evidence_dir.mkdir(parents=True, exist_ok=True)` uses the process umask with no `mode` argument. The `environ` capture from `/proc/PID/environ` exposes every environment variable of the targeted process, which may include database URLs, API keys, or shell secrets.
**Recommendation**: Use `evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)`. Consider moving `EVIDENCE_BASE` out of `/tmp` to a root-owned directory (e.g., `/var/lib/rsentry/evidence/`).

---

### [MEDIUM] Security — agent/exceptions.py (~line 47)
**Finding**: `.enc` is in `WHITELISTED_EXTENSIONS`, which causes the inotify backend to whitelist files before ransomware-rename detection can fire.
**Detail**: `is_whitelisted_path()` returns `True` for any file ending in `.enc`. The inotify handler calls `is_whitelisted(src_path)` — where `src_path` is the *new* path (e.g., `document.docx.enc`) — before entropy or rename analysis, silently dropping ENCRYPTED_RENAME events when the source is whitelisted. The eBPF backend bypasses `is_whitelisted()` and is not affected.
**Recommendation**: Remove `.enc` from `WHITELISTED_EXTENSIONS`. GPG output files should be allowed via the process whitelist (`gpg`, `gpg2`) rather than the extension whitelist.

---

### [MEDIUM] Security — agent/adaptive.py (~line 19)
**Finding**: `_UNSAFE_PREFIXES` does not include `/boot`, `/etc`, `/home`, `/root`, `/usr`, `/lib`, `/bin`, `/sbin` — the Markov repositioner could place canaries in critical system directories.
**Detail**: The current set is `("/.git/", "/proc/", "/sys/", "/dev/", "/run/")`. If the Markov chain observes file activity in `/etc/` (config changes) or `/boot/` (kernel updates), it may attempt `shutil.move` of a canary there. The agent runs as root.
**Recommendation**: Extend `_UNSAFE_PREFIXES` to include all system directories. The repositioner should only target paths within `WATCH_PATH`.

---

### [MEDIUM] Security — agent/monitor.py (~line 546)
**Finding**: `--run-sim` executes an arbitrary Python file passed on the command line as root, with no path validation.
**Detail**: `importlib.util.spec_from_file_location("_sim", sim_path)` followed by `_spec.loader.exec_module(_mod)` is arbitrary code execution at root privilege level. `sim_path` is taken directly from user input with no path check.
**Recommendation**: Validate that `sim_path` resolves within the project directory before execution, or gate `--run-sim` behind an explicit `--dev` flag.

---

### [MEDIUM] Bug — agent/monitor_ebpf.py (~line 1309)
**Finding**: The `--seed-canaries` argument block appears twice in the `__main__` entry — the second occurrence is unreachable dead code.
**Detail**: The first `if args.seed_canaries:` block calls `raise SystemExit(0)`. The identical second block (lines 1309–1314) is never reached.
**Recommendation**: Delete the second `if args.seed_canaries:` block.

---

### [MEDIUM] Bug — agent/graph.py (~line 43)
**Finding**: `_bfs_dirs()` follows symlinks via `e.is_dir()` with no symlink guard and no visited-set — a symlink loop or symlink pointing to a parent causes infinite re-traversal and can place canaries outside `WATCH_PATH`.
**Recommendation**: Add a `seen: set[Path]` and check `if e.resolve() in seen: continue; seen.add(e.resolve())`. Add `and not e.is_symlink()` filter or resolve+check for each candidate directory.

---

### Frontend

### [MEDIUM] Bug — frontend/src/hooks/useWebSocket.js (~line 30)
**Finding**: `if (data !== 'pong') { JSON.parse(data) }` — the pong guard is dead because `JSON.parse("pong")` always throws a `SyntaxError`, which is silently swallowed by `catch (_) {}`.
**Recommendation**: Check `if (event.data === 'pong') return;` before attempting `JSON.parse(event.data)`.

---

### [MEDIUM] Bug — frontend/src/App.jsx (~line 125)
**Finding**: `activeAlertCount` is `liveAlert ? 1 : 0` — always 0 or 1, never reflecting true unacknowledged alert volume.
**Recommendation**: Derive from a counter that increments on `new_alert` WebSocket events and resets when the user visits the Alerts page, or poll `/api/alerts/counts`.

---

### [MEDIUM] Bug — frontend/src/pages/ReportsPage.jsx (~lines 63, 471)
**Finding**: Date filter builds `"YYYY-MM-DDT23:59:59"` without a timezone suffix — JavaScript parses this as local time, causing up to 14 hours of drift for non-UTC operators.
**Recommendation**: Append explicit `Z` suffix or use `date-fns endOfDay` then `.toISOString()`.

---

### [MEDIUM] Bug — frontend/src/components/EventChart.jsx (~line 42) (+ HostRiskPanel.jsx, HostsPage.jsx, TacticalResponseLog.jsx)
**Finding**: `fetchAndBucket` is redeclared on every render without `useCallback`, and `useEffect` with `[]` captures a stale closure — the interval always calls the original function version.
**Recommendation**: Wrap with `useCallback` and include it in the `useEffect` dependency array, matching the pattern in `AlertFeed.jsx`.

---

### [MEDIUM] Bug — frontend/src/components/StatusBar.jsx (~line 12)
**Finding**: The clock updates every 30 seconds but displays HH:MM:**SS** — the seconds display is wrong by up to 29 seconds.
**Recommendation**: Either update every second (1000ms interval) to keep seconds accurate, or drop seconds from the display format.

---

### [MEDIUM] Improvement — frontend/src/components/FileSystemGraph.jsx (~lines 184–192)
**Finding**: D3 mouse event handlers can call `setTooltip()` on an unmounting component — React strict-mode warning and potential state-update-after-unmount.
**Recommendation**: Add a `mountedRef = useRef(true)` and check `if (mountedRef.current)` before `setTooltip()` calls.

---

### Simulations + Tests + Landing

### [MEDIUM] Security — simulations/ (sim_dfs.py, sim_random.py, sim_depth.py)
**Finding**: The three legacy sims have no git-repository guard and no backup/restore — running them against the project directory destroys files with no recovery.
**Detail**: `sim_common.main_for()` protects against this, but the three standalone sims bypass it. They also only skip `"AAA_"` prefix canaries, not all four prefixes.
**Recommendation**: Wrap each as a `Profile` + `main_for()` pair, or add the git-repo check and try/finally backup/restore from `sim_common` directly. Update `skip_aaa` filter to all four prefixes.

---

### [MEDIUM] Security — simulations/sim_common.py (~lines 45–65)
**Finding**: `populate_corpus()` silently overwrites pre-existing files if the target directory contains files matching the generated name pattern.
**Recommendation**: Raise `ValueError` if the target directory contains non-corpus files (or is non-empty), to prevent accidental overwrite of real user files.

---

### [MEDIUM] Bug — simulations/sim_common.py (~lines 156–159)
**Finding**: LockBit `two_pass` mode performs both encrypt passes in memory and writes only once — no intermediate rename event is produced on disk.
**Detail**: Real LockBit 5.0 produces two observable disk renames (partial pass then full pass). The simulation produces one rename. Any detection logic relying on the intermediate file or the two-rename pattern will not be exercised.
**Recommendation**: Write the partial result to `path + ".partial"` first, then rename to the final extension, producing two distinct disk operations.

---

### [MEDIUM] Bug — simulations/sim_common.py (~line 176)
**Finding**: The corpus backup is not atomic — a partial `shutil.copytree` failure causes `_restore_corpus` to reconstruct from an incomplete backup, destroying the original corpus.
**Recommendation**: After `copytree`, verify the file count matches the source before returning. In `_restore_corpus`, check that the backup directory is non-empty before `shutil.rmtree(root)`.

---

### [MEDIUM] TestQuality — tests/unit/agent/test_severity.py (~lines 50–53)
**Finding**: Two tests are tautological — they assert Python boolean literals, not production code.
**Detail**: `assert ("CRITICAL" if True else "LOW") == "CRITICAL"` — always passes regardless of any code change.
**Recommendation**: Replace with behavioral tests: call `DetectionEngine.observe_rename()` on all 4 canary prefix variants and assert `severity == "CRITICAL"`.

---

### [MEDIUM] TestQuality — tests/conftest.py + test_severity.py
**Finding**: The canary fixture and canary pattern tests only cover the `AAA_` prefix — the 4-prefix system added in commit b30ea5f (2026-06-05) is not tested.
**Detail**: No test verifies that `aaa_`, `ZZZ_`, or `zzz_` prefixed canary touches trigger CRITICAL severity. No test verifies that `enumerate_targets(skip_aaa=True)` correctly skips all four prefixes.
**Recommendation**: Update `tmp_canary_dir` to include one file per prefix. Add a parametrized test iterating all four prefix variants.

---

### [MEDIUM] TestQuality — tests/unit/agent/test_adaptive.py
**Finding**: No test verifies the `backend != "ebpf"` Markov gate added in commit 2dc19cf — a regression would silently restart repositioning during eBPF operation.
**Recommendation**: Add a test that instantiates `Monitor(backend="ebpf")`, patches `threading.Thread`, and asserts `_reposition_loop` is never registered as a thread target.

---

### [MEDIUM] TestQuality — tests/unit/sims/test_simulations.py
**Finding**: Tests cover only the three legacy sims — not the production `sim_akira`, `sim_qilin`, `sim_lockbit` that model named ransomware families.
**Recommendation**: Add the production sims to the `TestSafety` class. Add an integration-style test that runs `main_for()` against a `tmp_path` and asserts correct backup/restore and no out-of-directory file writes.

---

## LOW findings

### Backend

### [LOW] DeadCode — backend/routers/ws.py (~line 97)
**Finding**: `publish_alert()` function is defined but never called anywhere.
**Recommendation**: Remove.

---

### [LOW] DeadCode — backend/models/schemas.py (~line 147)
**Finding**: `AlertCreate` Pydantic schema is defined and exported but used by no router.
**Recommendation**: Remove from `schemas.py` and `__init__.py`.

---

### [LOW] DeadCode — backend/services/ai_analyst.py (~lines 32–33, 84–88, 105–109)
**Finding**: `_RATE_KEY_GROQ`, `_RATE_KEY_NVIDIA`, `_reset_client_events()`, and `_reset_client_alerts()` are defined but never called.
**Recommendation**: Either wire the rate keys into provider-specific rate limiting (see MEDIUM finding) and call the reset functions on `AuthenticationError`, or remove all four.

---

### [LOW] Improvement — backend/main.py (~line 67)
**Finding**: `/api/ai/health` accepts `list[dict]` with no schema validation — unbounded payload size, arbitrary dict contents.
**Recommendation**: Define a Pydantic model for the event items, or add `max_length` on the list.

---

### [LOW] Improvement — backend/models/database.py (~line 12)
**Finding**: `pool_size=10, max_overflow=20` allows up to 60 connections across 2 workers — may exhaust Postgres's default `max_connections=100` under load with Celery connections.
**Recommendation**: Reduce to `pool_size=5, max_overflow=10` per worker, or configure `max_connections` explicitly in the Postgres service.

---

### [LOW] Improvement — requirements.txt
**Finding**: Several packages appear unused: `aiohttp` (no import in backend/), `pydantic-settings` (no import), `structlog` (no import), `alembic` (installed but migrations are not used — `create_all` on startup).
**Recommendation**: Remove unused packages. Consider implementing proper Alembic migrations for production schema tracking.

---

### Agent

### [LOW] Bug — agent/monitor_ebpf.py (~line 630, BPF C)
**Finding**: The 1ms interval fast-block rule (second rename within 1ms = machine speed = ransomware) is too aggressive — legitimate shell one-liners can issue two renames within 1ms and be permanently blocked.
**Recommendation**: Remove the 1ms fast-block from the kernel-level LSM blocking path. Use it as a scoring signal only. Rely on `new_cnt >= VELOCITY_THRESHOLD` (3 renames in 3 seconds) for the guaranteed-block decision.

---

### [LOW] Security — agent/containment.py (~lines 182–207)
**Finding**: UID is read from psutil after SIGSTOP — narrow TOCTOU window where a setuid process dropping privileges between SIGSTOP and the psutil call could result in iptables blocking the wrong UID.
**Recommendation**: Read UID from `/proc/PID/status` immediately after SIGSTOP is confirmed, before any blocking.

---

### [LOW] Improvement — agent/client.py (~line 162)
**Finding**: `send_containment_triggered()` always passes `canary_hit=True` regardless of whether containment was triggered by a canary or by velocity burst.
**Recommendation**: Add a `canary_hit: bool` parameter and pass through the actual value.

---

### [LOW] Improvement — agent/entropy.py (~lines 82, 99)
**Finding**: LRU eviction strategy is FIFO (insertion order) — an actively-monitored file can be evicted while newer, less-relevant files remain, causing a false entropy delta of 0 on the next observation.
**Recommendation**: Use `collections.OrderedDict` with `move_to_end()` on access, or switch to `functools.lru_cache`.

---

### [LOW] Improvement — agent/lineage.py (~line 90)
**Finding**: `@lru_cache(maxsize=512)` on `_sha256_of_exe` caches the hash indefinitely — if ransomware replaces a system binary after the cache is populated, the old (correct) hash is returned forever.
**Recommendation**: Cache `(hash, mtime)` tuples and re-hash when `os.stat(exe_path).st_mtime` changes.

---

### [LOW] DeadCode — agent/monitor.py (~line 321)
**Finding**: `is_markov` is always `False` at that code point — `details` dict never contains `sub_type` when this check runs.
**Recommendation**: Remove the dead `is_markov` variable and simplify the containment condition.

---

### [LOW] DeadCode — agent/monitor_ebpf.py (~line 1309)
**Finding**: Second `if args.seed_canaries:` block is unreachable (covered in MEDIUM findings above).

---

### [LOW] Improvement — agent/monitor_ebpf.py (~line 42)
**Finding**: `IGNORE_COMMS` contains a duplicate `"containerd"` entry and `"glean.dispatche"` appears to be a truncated process name.
**Recommendation**: Deduplicate. Verify `"glean.dispatche"` is the exact 15-char comm name. Add comments explaining why browser thread names are included.

---

### [LOW] Improvement — agent/monitor_ebpf.py (~line 477)
**Finding**: `ATTRACTIVE_EXTS` does not include high-value ransomware targets: `.sql`, `.mdf`, `.edb` (Exchange DB), `.pst`, `.kdbx` (KeePass — an excellent canary with near-zero FP risk).
**Recommendation**: Expand to at least `.kdbx` and `.edb`.

---

### [LOW] Improvement — agent/lineage.py (~line 296)
**Finding**: Exited-too-fast score of 40.0 is at the `COMBINED_HIGH` boundary — any short-lived process touching a watched file generates a `PROCESS_ANOMALY` alert.
**Recommendation**: Lower the default rapid-exit score to 25.0, or add a `reasons` tag of `process_exited_rapidly` and skip alert generation for that specific case.

---

### Frontend

### [LOW] DeadCode — frontend/src/components/AlertsTable.jsx (~line 86)
**Finding**: "Columns" and "Sort" toolbar buttons have no `onClick` handlers — purely decorative.
**Recommendation**: Wire up or remove.

---

### [LOW] DeadCode — frontend/src/pages/AlertsPage.jsx (~line 96)
**Finding**: "Last 24 hours" time-range pill is decorative — no filtering is applied.
**Recommendation**: Implement or remove.

---

### [LOW] DeadCode — frontend/src/components/TopBar.jsx (~line 50)
**Finding**: Bell and question-mark icon buttons have no `onClick` handlers.
**Recommendation**: Wire up or remove.

---

### [LOW] Improvement — frontend/src/components/DetailFlyout.jsx (~line 164) (and other files)
**Finding**: `RULE_NAME` and `MITRE` mapping objects are copy-pasted with subtle divergences into `DetailFlyout.jsx`, `AlertsTable.jsx`, `EventDetailModal.jsx`, and `TacticalResponseLog.jsx`.
**Recommendation**: Extract to `frontend/src/constants/eventTypes.js`. Single source of truth for all four files.

---

### [LOW] Improvement — frontend/src/components/StatusBar.jsx (~line 9)
**Finding**: `hostCount` and `eventRate` props are never passed from `App.jsx` — metrics always show hardcoded fallback values.
**Recommendation**: Fetch from `/api/alerts/counts` and `/api/events` in `App.jsx` or inside `StatusBar` itself.

---

### Simulations + Tests + Landing

### [LOW] DeadCode — simulations/sim_common.py (~line 78)
**Finding**: `enumerate_targets(skip_aaa=True)` filter skips only `"AAA_"` and `"zzz_"` — misses `"aaa_"` and `"ZZZ_"` prefixes from the 4-prefix canary system.
**Recommendation**: Update all three `startswith()` calls to `startswith(("AAA_", "aaa_", "ZZZ_", "zzz_"))`.

---

### [LOW] DeadCode — landing/src/components/sections/ThreatTimeline.jsx (~lines 71–88)
**Finding**: `LAYOUT` and `SVG_CONNECTORS` constants are never referenced.
**Recommendation**: Delete both.

---

### [LOW] DeadCode — landing/src/components/sections/ThreatConsole.jsx (~lines 101, 104)
**Finding**: `setTS` (state setter for "Threats Stopped" counter) and `cycleRef` are declared but never used — the counter is permanently frozen at 23.
**Recommendation**: Either wire `setTS` into a live interval or change to `const threatsStopped = 23`.

---

### [LOW] DeadCode — landing/src/components/sections/Pillars.jsx (~lines 230, 236, 242)
**Finding**: The `hov` parameter in three icon arrow functions is accepted but ignored.
**Recommendation**: Change `(hov) => <WaveformIcon .../>` to `() => <WaveformIcon .../>` for the three unused cases.

---

### [LOW] TestQuality — tests/test_lockbit.py (~line 206)
**Finding**: FP-rate threshold is `< 5%` — a regression producing 4 false positives in 90 renames (4.4%) would still pass.
**Recommendation**: Increase corpus to ≥ 1,000 renames and tighten threshold to `< 0.5%`, or keep corpus and lower threshold to `< 2%`.

---

## Top 5 untested coverage gaps (ranked by risk × size)

1. **`agent/monitor_ebpf.py` (1,353 lines)** — no automated pytest coverage. The `DetectionEngine`, `seed_canaries`, velocity burst logic, and BPF probe loading have zero regression protection. A BCC version bump or kernel API change would only be caught in production.
2. **`agent/containment.py` (310 lines)** — no tests. The SIGSTOP → iptables → SIGKILL kill-chain, PID resolution from `/proc`, and the uid=0 guard are all untested. Mistakes here mean either ransomware remains running or innocent processes are killed.
3. **`agent/monitor.py` (716 lines)** — no tests. The inotify event dispatch, eBPF backend gate (`if self.backend != "ebpf"`), heartbeat loop, and `_reposition_loop` gate have no regression protection.
4. **`backend/workers/tasks.py` (322 lines)** — no tests. All Celery tasks (AI fallback chain, auto-ack conditions, WS publish payload shape) are only exercised in full integration. The `_env()` file reader has no unit test.
5. **`backend/routers/events.py` (174 lines)** — no tests. The alert creation entry point, severity classification, and Celery task dispatch are completely untested — the module with the most historically bug-prone logic (prior session UUID bug, severity mismatches).

---

## Already fixed / not re-reported

The following issues from session_02 and session_04 were verified as resolved and not re-reported:
- CVE-2024-33664/33663 (python-jose) — dependency removed
- Hardcoded Postgres password — now env var with RuntimeError on missing `DATABASE_URL`
- Alert UUID bug (event_id vs alert_id in tasks.py) — verified fixed
- `send_containment_complete` wrong dict key — verified fixed
- `docker-compose.yml` missing NVIDIA keys for Celery — verified fixed
- All startup commands missing `.env` sourcing — verified fixed
- Canary `.gitignore` prefix gap (AAA_ only) — fixed 2026-06-06 in commit 4221e8b (this session)
