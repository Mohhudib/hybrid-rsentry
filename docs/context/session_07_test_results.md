# Session 07 — Full Test Results & Coverage Analysis

**Date:** 2026-06-07
**Commit:** `f4a1e91` (branch `main`)
**Author of run:** automated test sweep

---

## Executive Summary

| Suite | Tests | Passed | Failed | Wall time |
|---|---|---|---|---|
| pytest (`tests/unit/`) | 87 | 87 | 0 | **2.05 s** |
| `monitor_ebpf.py --selftest` | 44 checks | 44 | 0 | **0.117 s** |
| `monitor.py --selftest` | 16 checks | 16 | 0 | **2.091 s** |
| `tests/test_lockbit.py` (standalone) | 4 metrics | 4 | 0 | **1.044 s** |
| **Total** | **151** | **151** | **0** | — |

**Net result: all green** — but only after two corrections made during this run (see below), and **only under the system Python 3.13 interpreter**. The project's own `venv` (Python 3.11.9) **cannot run the suite at all**. This is the single most important finding in this report.

### Corrections made during this run
1. **Fixed a stale assertion** in `tests/unit/agent/test_lineage.py::test_nonexistent_pid_baseline_score` — it still asserted `>= 40.0` after the rapid-exit lineage score was lowered to `25.0` (LOW fix #15). The sibling assertion in `test_severity.py` had been updated; this duplicate was missed. Now `>= 25.0`.
2. **Fixed `populate_corpus()`** non-empty guard to ignore dot-file sentinels, so `test_lockbit.py`'s `.rsentry_sandbox` marker no longer trips the "directory is non-empty" `ValueError`.

---

## Environment & Execution Notes

### ⚠️ Python version mismatch (blocking)
- **`venv/bin/python` = 3.11.9** — `agent/monitor_ebpf.py:765` uses an f-string with a backslash inside the expression (`{"" if not (enforce and lsm) else """...\n..."""}`). That syntax is **only legal on Python 3.12+** (PEP 701). Under 3.11 the module raises `SyntaxError` at import, so **pytest collection aborts** (`tests/test_lockbit.py` imports it directly, and the unit tests import `agent/*` transitively).
- **System `python3` = 3.13.12** — imports cleanly, has all deps (`numpy 2.3.5`, `scipy 1.16.3`, `pandas 2.3.3`, `psutil 7.1.0`, `pytest 9.0.2`).
- **`pyproject.toml` declares `target-version = "py313"`**, confirming 3.13 is the intended interpreter. **The committed venv is therefore stale/wrong** and should be rebuilt on 3.13, or the eBPF f-string rewritten to be 3.11-compatible.

All results below were produced with **system `python3` (3.13.12)**.

### Commands used
```bash
python3 -m pytest tests/ -v --durations=0 -p no:cacheprovider
python3 -m agent.monitor_ebpf --selftest
python3 -m agent.monitor --selftest
python3 tests/test_lockbit.py
```

### Config caveat
pytest prints `WARNING: ignoring pytest config in pyproject.toml`. Both `pytest.ini` **and** `[tool.pytest.ini_options]` in `pyproject.toml` define the same settings; `pytest.ini` wins and the pyproject block is dead. The two will drift.

---

## 1. pytest suite — per-test results

All 87 tests passed. Times are wall-clock `call` duration from `--durations=0`; entries marked **<5 ms** were below pytest's reporting threshold (rounded to 0.00 s).

### `tests/unit/agent/test_adaptive.py` — MarkovRepositioner (18 tests)
What the module does: learns the ransomware's directory-traversal pattern and predicts where to move canaries (inotify backend only).

| Test | Status | Time | What it verifies |
|---|---|---|---|
| `TestObserve::test_adds_state` | PASS | <5 ms | Observing a path registers it in the state index |
| `TestObserve::test_multiple_states` | PASS | <5 ms | Three distinct observations → three states |
| `TestObserve::test_n_obs_zero_with_one_event` | PASS | <5 ms | A single observation yields 0 transitions |
| `TestObserve::test_n_obs_increments` | PASS | <5 ms | Second observation increments the transition counter |
| `TestObserve::test_counts_updated` | PASS | <5 ms | Transition-count matrix sums to 1 after one transition |
| `TestShouldReposition::test_false_no_observations` | PASS | <5 ms | No data → never reposition |
| `TestShouldReposition::test_false_below_min` | PASS | <5 ms | Below the minimum-observation gate → no reposition |
| `TestShouldReposition::test_true_strong_pattern` | PASS | <5 ms | 20 repetitions of a strong A→B pattern → reposition fires |
| `TestPredictedHotspots::test_empty_before_min_obs` | PASS | <5 ms | No prediction before minimum observations |
| `TestPredictedHotspots::test_returns_list_after_enough` | PASS | <5 ms | Returns a list once enough data is gathered |
| `TestPredictedHotspots::test_top_n_respected` | PASS | <5 ms | `top_n=2` caps the prediction list length |
| `TestReposition::test_returns_list` | PASS | <5 ms | `reposition()` returns a list of canary paths |
| `TestReposition::test_returns_original_no_hotspots` | PASS | <5 ms | With no hotspots, original canary set is returned |
| `TestReposition::test_updates_fs_graph` | PASS | <5 ms | When passed an fs_graph, its `canary_paths` is updated |
| `TestSummary::test_returns_dict` | PASS | <5 ms | `summary()` returns a dict |
| `TestSummary::test_required_keys` | PASS | <5 ms | Summary contains n_states/n_observations/should_reposition/top_hotspots |
| `TestSummary::test_initial_values` | PASS | <5 ms | Fresh repositioner reports zeroed counters |
| `TestMarkovGate::test_ebpf_backend_skips_repositioner` | PASS | **0.02 s** | `Monitor.start()` does **not** launch the `_reposition_loop` thread when `backend='ebpf'` (patches `Thread.start` and asserts the target was never registered) |

### `tests/unit/agent/test_entropy.py` — Shannon entropy engine (21 tests)
What the module does: rolling per-file Shannon entropy; fires `ENTROPY_SPIKE` when the delta crosses a threshold.

| Test | Status | Time | What it verifies |
|---|---|---|---|
| `TestShannonEntropy::test_empty_bytes_returns_zero` | PASS | <5 ms | Empty input → 0.0 bits |
| `TestShannonEntropy::test_uniform_bytes_high_entropy` | PASS | <5 ms | All 256 byte values → > 7.5 bits |
| `TestShannonEntropy::test_single_repeated_byte_low_entropy` | PASS | <5 ms | 1000× same byte → < 0.1 bits |
| `TestShannonEntropy::test_returns_float` | PASS | <5 ms | Return type is float |
| `TestShannonEntropy::test_between_zero_and_eight` | PASS | <5 ms | Result bounded to [0, 8] bits |
| `TestShannonEntropy::test_random_data_high_entropy` | PASS | <5 ms | 1 KB `os.urandom` → > 6.0 bits |
| `TestEntropyRecord::test_initial_delta_zero` | PASS | <5 ms | Empty record → delta 0 |
| `TestEntropyRecord::test_single_sample_delta_zero` | PASS | <5 ms | One sample → delta 0 |
| `TestEntropyRecord::test_delta_max_minus_min` | PASS | <5 ms | Delta = max − min over the window |
| `TestEntropyRecord::test_latest_returns_last` | PASS | <5 ms | `latest()` returns most recent sample |
| `TestEntropyRecord::test_latest_empty_zero` | PASS | <5 ms | `latest()` on empty record → 0 |
| `TestEntropyRecord::test_window_respected` | PASS | <5 ms | Window size caps retained samples (5 added, window=3 → 3 kept) |
| `TestEntropyRecord::test_recent_spike_false_one_sample` | PASS | <5 ms | Single sample never counts as a spike |
| `TestEntropyRecord::test_recent_spike_true_on_large_delta` | PASS | <5 ms | 1.0→6.0 jump exceeds 3.5 threshold → spike |
| `TestEntropyRecord::test_recent_spike_false_small_delta` | PASS | <5 ms | 4.0→4.5 below threshold → no spike |
| `TestEntropyEngine::test_nonexistent_file_returns_none` | PASS | <5 ms | Missing file → None |
| `TestEntropyEngine::test_single_observation_no_spike` | PASS | <5 ms | First observation never spikes |
| `TestEntropyEngine::test_spike_returns_alert` | PASS | <5 ms | Zeros→random rewrite emits `ENTROPY_SPIKE` ⚠️ *conditional assert* |
| `TestEntropyEngine::test_flush_removes_record` | PASS | <5 ms | `flush(path)` removes the tracked record |
| `TestEntropyEngine::test_bulk_scan_returns_list` | PASS | <5 ms | `bulk_scan()` returns a list |
| `TestEntropyEngine::test_stats_dataframe_empty` | PASS | <5 ms | `stats_dataframe()` returns a pandas DataFrame |

### `tests/unit/agent/test_lineage.py` — process-ancestry scorer (15 tests)
What the module does: scores a PID's suspicion from parent names, spawn path, binary SHA-256, and dpkg integrity.

| Test | Status | Time | What it verifies |
|---|---|---|---|
| `TestProcessLineage::test_to_dict_has_required_keys` | PASS | <5 ms | `to_dict()` exposes all 8 expected keys |
| `TestProcessLineage::test_score_rounded` | PASS | <5 ms | Score rounded to 2 dp in dict |
| `TestProcessLineage::test_cmdline_joined` | PASS | <5 ms | cmdline list joined with spaces |
| `TestProcessLineage::test_initial_score_zero` | PASS | <5 ms | New lineage starts at score 0 |
| `TestProcessLineage::test_initial_reasons_empty` | PASS | <5 ms | New lineage has empty reasons |
| `TestSha256OfExe::test_valid_file_returns_64char_hex` | PASS | <5 ms | Hashing a file → 64-char hex |
| `TestSha256OfExe::test_nonexistent_returns_none` | PASS | <5 ms | Missing path → None |
| `TestSha256OfExe::test_same_content_same_hash` | PASS | <5 ms | Identical bytes → identical hash |
| `TestSha256OfExe::test_different_content_different_hash` | PASS | <5 ms | Differing bytes → differing hash |
| `TestCollectAncestors::test_no_parent_empty_lists` | PASS | <5 ms | No parent → empty name/path lists |
| `TestCollectAncestors::test_single_parent_captured` | PASS | <5 ms | One parent (sshd) captured in names |
| `TestCollectAncestors::test_access_denied_handled` | PASS | <5 ms | `psutil.AccessDenied` swallowed gracefully |
| `TestScoreForEvent::test_returns_dict` | PASS | **0.79 s** | `score_for_event(getpid())` returns a dict — **first call loads the 492,869-entry dpkg hash DB** (dominates total suite time) |
| `TestScoreForEvent::test_required_keys` | PASS | <5 ms | Result has all required keys |
| `TestScoreForEvent::test_nonexistent_pid_baseline_score` | PASS | <5 ms | Dead PID → `lineage_score >= 25.0` (**corrected this run** from 40.0) |
| `TestScoreForEvent::test_score_is_float` | PASS | <5 ms | lineage_score is float |
| `TestScoreForEvent::test_ancestors_is_list` | PASS | <5 ms | ancestors is a list |

### `tests/unit/agent/test_severity.py` — severity classification (12 tests)
What the module does: maps entropy/lineage/canary signals to CRITICAL/HIGH/MEDIUM/LOW.

| Test | Status | Time | What it verifies |
|---|---|---|---|
| `TestEntropySeverity::test_alert_has_severity_field` | PASS | <5 ms | Entropy alert carries a severity field ⚠️ *conditional assert* |
| `TestEntropySeverity::test_alert_event_type_correct` | PASS | <5 ms | Entropy alert event_type is `ENTROPY_SPIKE` ⚠️ *conditional assert* |
| `TestEntropySeverity::test_entropy_delta_non_negative` | PASS | <5 ms | entropy_delta ≥ 0 ⚠️ *conditional assert* |
| `TestLineageSeverity::test_current_process_low_score` | PASS | <5 ms | Current (benign) process scores ≤ 60 |
| `TestLineageSeverity::test_nonexistent_pid_baseline` | PASS | <5 ms | Dead PID baseline ≥ 25.0 |
| `TestLineageSeverity::test_score_capped_at_100` | PASS | <5 ms | Score never exceeds 100 (mocked extreme process) |
| `TestCanarySeverity::test_all_four_canary_prefixes_present` | PASS | <5 ms | Fixture seeds AAA_/aaa_/ZZZ_/zzz_ canaries |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[AAA_]` | PASS | <5 ms | `is_canary()` matches AAA_ across .txt/.docx/.vmdk |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[aaa_]` | PASS | <5 ms | …matches aaa_ |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[ZZZ_]` | PASS | <5 ms | …matches ZZZ_ |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[zzz_]` | PASS | <5 ms | …matches zzz_ |
| `TestCanarySeverity::test_non_canary_not_detected` | PASS | <5 ms | report.docx / important_file.txt / aaaaaa_file.txt are **not** flagged |

### `tests/unit/sims/test_simulations.py` — simulation safety (21 tests)
What the module does: guards that the ransomware simulators are safe (no SIGSTOP, no agent import, sandboxed) and exposes the expected profiles.

| Test | Status | Time | What it verifies |
|---|---|---|---|
| `TestImports::test_sim_dfs_importable` | PASS | <5 ms | sim_dfs imports |
| `TestImports::test_sim_random_importable` | PASS | <5 ms | sim_random imports |
| `TestImports::test_sim_depth_importable` | PASS | <5 ms | sim_depth imports |
| `TestImports::test_sim_akira_importable` | PASS | <5 ms | sim_akira imports |
| `TestImports::test_sim_qilin_importable` | PASS | <5 ms | sim_qilin imports |
| `TestImports::test_sim_lockbit_importable` | PASS | <5 ms | sim_lockbit imports |
| `TestSafety::test_no_sigstop_in_sims` | PASS | <5 ms | No simulator contains the string `SIGSTOP` |
| `TestSafety::test_no_agent_monitor_import` | PASS | <5 ms | No simulator imports `agent.monitor` |
| `TestSafety::test_no_canary_files_touched` | PASS | <5 ms | Legacy sims never `open` an `AAA_` file |
| `TestSafety::test_sim_dir_under_tmp` | PASS | <5 ms | sim_dfs TEST_DIR is under /tmp |
| `TestProductionSimProfiles::test_profile_mode[akira-intermittent]` | PASS | <5 ms | Akira profile mode == intermittent |
| `TestProductionSimProfiles::test_profile_mode[qilin-percent]` | PASS | <5 ms | Qilin profile mode == percent |
| `TestProductionSimProfiles::test_profile_mode[lockbit-two_pass]` | PASS | <5 ms | LockBit profile mode == two_pass |
| `TestProductionSimProfiles::test_profile_has_ext_fn[akira]` | PASS | <5 ms | Akira `ext_fn()` returns non-empty string |
| `TestProductionSimProfiles::test_profile_has_ext_fn[qilin]` | PASS | <5 ms | Qilin `ext_fn()` returns non-empty string |
| `TestProductionSimProfiles::test_profile_has_ext_fn[lockbit]` | PASS | <5 ms | LockBit `ext_fn()` returns non-empty string |
| `TestProductionSimProfiles::test_uses_main_for[akira]` | PASS | <5 ms | Akira uses `sim_common.main_for()` (git-guard + backup/restore) |
| `TestProductionSimProfiles::test_uses_main_for[qilin]` | PASS | <5 ms | Qilin uses `main_for()` |
| `TestProductionSimProfiles::test_uses_main_for[lockbit]` | PASS | <5 ms | LockBit uses `main_for()` |

---

## 2. Standalone harnesses (not collected by pytest)

These run via `python3 -m … --selftest` / direct invocation. **They are not pytest tests**, so CI running `pytest tests/` does **not** execute them.

### `agent/monitor_ebpf.py --selftest` — 44 checks, ALL PASS (0.117 s)
Covers the eBPF userspace `DetectionEngine` with **no kernel/BCC dependency**:
- Severity rule chain (5), canary detection incl. write-by-inode (3)
- Userspace velocity burst — no alert on file 1, alert on file 2 (LockBit two-pass) (4)
- Kernel-decided burst event schema + active-pid arming (3)
- Ransomware family profiling: Akira / LockBit5 / ESXi (3)
- Noise suppression: own-PID, NEVER_AUTO_KILL comm, Markov self-move (3)
- Benign `.bak` renames never alert (1)
- Cooldown regression: first alert fires at ts≈0 (1)
- Option-A system-wide encrypted-rename capture outside watch dir (5)
- `seed_canaries` placement/naming/4-prefix/extensions/existence (11)
- `build_bpf` text generation across all enforce×lsm variants, `-EPERM` presence (6)

### `agent/monitor.py --selftest` — 16 checks, ALL PASS (2.091 s)
End-to-end wiring of the inotify backend: lineage_fn / entropy_fn adapters return floats in range; `send_event` adapter passes all typed fields; containment runs (DRY_RUN); Markov self-move suppression; whitelist contains git/rsync/dockerd. (Slow because it loads the 492 K dpkg DB and numexpr.)

### `tests/test_lockbit.py` — LockBit 5.0 detection metrics, ALL TARGETS MET (1.044 s)

| Metric | Result | Target | Pass |
|---|---|---|---|
| Files before detection (avg) | 1.7 | < 3 | ✓ |
| Detection latency (avg) | 0.365 ms | < 500 ms | ✓ |
| False-positive rate | 0.0 % | < 2 % | ✓ |
| Coverage rate | 100 % | > 95 % | ✓ |

Detection lands on file #1–#2 across dfs/random/depth traversals (canary on rename #1, velocity threshold on rename #2). Note results vary run-to-run because the 16-char extension is randomised — avg files fluctuates ~1.3–1.7.

---

## 3. Timing analysis

- **Suite total: 2.05 s** for 87 tests. **96 % of that is one test** — `test_lineage.py::test_returns_dict` (0.79 s) on first dpkg DB load. Every other test is < 25 ms; the vast majority < 5 ms.
- The dpkg load is incurred once per process. A session-scoped fixture that pre-warms (or mocks) `_load_dpkg_hashes()` would drop suite time to ~0.3 s.
- `monitor.py --selftest` (2.1 s) pays the same dpkg cost plus numexpr init.

---

## 4. Coverage gaps

### Modules with **zero** pytest coverage
| Module | Risk | Note |
|---|---|---|
| `agent/containment.py` | **HIGH** | The destructive path — SIGSTOP → evidence → iptables DROP → SIGKILL, plus the new `/proc/PID/status` TOCTOU UID read. Only exercised by `monitor.py --selftest` in DRY_RUN. |
| `agent/graph.py` | MED | `FilesystemGraph` BFS + canary placement + `is_canary()` prefix logic — only indirectly hit. |
| `agent/client.py` | MED | HTTP payload builder + retry; `send_containment_triggered` `canary_hit` param (recently changed) untested. |
| `agent/exceptions.py` | MED | Whitelist + smart `/tmp` filter — security-relevant, untested directly. |
| `agent/monitor.py` / `monitor_ebpf.py` | — | Have rich `--selftest` harnesses, but those are **not pytest-discoverable** → invisible to `pytest tests/` and CI. |
| **All of `backend/`** | **HIGH** | `routers/{alerts,events,hosts,ws}.py`, `services/ai_analyst.py`, `workers/tasks.py` have **no tests**. The recently-rewritten GROUP-BY alert-count queries, the async SQLAlchemy dependency chain, the AI provider fallback/rate-limit logic, and the `HealthCheckRequest` `max_length` cap are all unverified. |
| **All of `frontend/` & `landing/`** | MED | No test runner configured (vite only). `AlertsTable.riskScore` (UUID-hex parse), `StatusBar` host fetch, WebSocket reducer untested. |

### Empty scaffolding
- `tests/integration/` contains only `__init__.py`. The `integration` pytest marker is **defined but never applied** to any test.

---

## 5. Weaknesses found

1. **Conditional assertions silently pass.** Several tests use the pattern `r = ...; if r: assert r[...]`. If the operation returns `None` (e.g. no spike detected), the test passes **without ever asserting**. Affected: `test_entropy.py::test_spike_returns_alert`, and all three `test_severity.py::TestEntropySeverity` tests. These should assert `r is not None` first, or be structured so the alert is guaranteed.
2. **Duplicated assertions drift.** The rapid-exit baseline (`>= 40.0`) was asserted in **two** files; the LOW-fix update touched only one, leaving a latent failure that surfaced this run. Tests asserting the same constant in multiple places should reference a shared constant or be deduplicated.
3. **`test_lockbit.py` lives in `tests/` but isn't a pytest module.** It's an argparse `main()` script. Under pytest it contributes **0 collected tests** (3.13) or a **collection error** (3.11). It should either move to `scripts/`/`benchmarks/` or be refactored into parametrized pytest tests so its metrics gate CI.
4. **Selftests are invisible to CI.** ~60 high-value checks live in `--selftest` entrypoints that `pytest tests/` never runs. A thin pytest wrapper (`subprocess` or direct call of `_selftest()`) would surface them.
5. **Interpreter/venv mismatch.** The committed `venv` (3.11.9) cannot import the codebase. Anyone running `source venv/bin/activate && pytest` gets a `SyntaxError`. Either rebuild the venv on 3.13 or make `monitor_ebpf.py` 3.11-safe.
6. **Dual pytest config.** `pytest.ini` and `pyproject.toml` both configure pytest; the latter is silently ignored. Consolidate to one.
7. **Randomised LockBit metrics aren't reproducible.** The 16-char extension is random, so `avg files before detection` and `latency` vary per run. A fixed seed (or asserting only the pass/fail thresholds, which it does) keeps the gate stable but the reported numbers non-deterministic — fine for a gate, noisy for a benchmark trend.
8. **No coverage measurement.** `pytest-cov` isn't installed, so line/branch coverage is unknown; the gaps above are inferred from file structure, not measured.

---

## 6. Recommendations (prioritised)

### P0 — unblock the toolchain
- [ ] **Rebuild `venv` on Python 3.13** (or rewrite the `monitor_ebpf.py:765` f-string to avoid a backslash in the expression so 3.11 works). Document the required interpreter in `CLAUDE.md`.
- [ ] **Consolidate pytest config** into one location (drop the `pyproject.toml` block or the `pytest.ini`).

### P1 — close the highest-risk coverage gaps
- [ ] **`agent/containment.py` unit tests** — mock `psutil`/`subprocess`; verify UID parse from `/proc/PID/status`, the uid=0 iptables skip, evidence dir `mode=0o700`, and tree-freeze ordering. This is the destructive path; it deserves the most tests and currently has the fewest.
- [ ] **Backend router tests** with `httpx.AsyncClient` + a test Postgres (or SQLite) — cover `/api/alerts/counts` GROUP BY, alert creation severity logic, `HealthCheckRequest` 200-item cap, and the contain/release endpoints.
- [ ] **`agent/exceptions.py` whitelist tests** — security-relevant allow/deny decisions, especially the `/tmp` filter.

### P2 — make existing checks count
- [ ] **Fix conditional assertions** — assert `r is not None` before dereferencing in the 4 affected tests.
- [ ] **Wrap the two `--selftest` suites in pytest** so CI runs all 60 checks.
- [ ] **Relocate or refactor `test_lockbit.py`** out of pytest collection, or convert to parametrized tests.

### P3 — hygiene & visibility
- [ ] **Add `pytest-cov`** and a coverage gate (start at the current line %, ratchet up).
- [ ] **Session-scoped dpkg fixture** to pre-warm/mature the hash DB once → ~7× faster suite.
- [ ] **Populate `tests/integration/`** and actually apply the `integration` marker (Redis/Postgres round-trip, agent→backend `POST /api/events`).
- [ ] **Frontend smoke tests** (Vitest) for `AlertsTable.riskScore` UUID parsing and the `StatusBar` fetch fallback.

---

## Appendix — raw totals

```
pytest:                 87 passed in 2.05s   (system python3 3.13.12, pytest 9.0.2)
monitor_ebpf selftest:  44/44 PASS  0.117s
monitor selftest:       16/16 PASS  2.091s
test_lockbit:           4/4 targets met 1.044s
------------------------------------------------
combined:              151/151 green
```

---

## Addendum — Resolution (same session)

All findings above were fixed in priority order; each is a separate commit.
The canonical test runner is now the project **venv (Python 3.11.9)**, which
runs the entire suite after the P0 fix.

| ID | Fix | Commit |
|---|---|---|
| **P0** | `build_bpf` f-string made 3.11-safe — conditional snippets hoisted to locals; generated BPF text verified byte-identical across all enforce×lsm variants. Suite now runs under both 3.11.9 and 3.13.12. | `de88c0e` |
| **P1a** | 59 backend tests: routers (alerts/events/hosts via httpx ASGI + in-memory SQLite), ai_analyst (mocked), tasks (`_env`/`_run`/WS push), main (health + 200-item cap). SQLite UUID shim is conftest-only; Celery `.delay` auto-patched. | `81b6aaa` |
| **P1b** | 26 containment tests — full SIGSTOP→evidence→iptables→SIGKILL pipeline with all syscalls mocked (incl. TOCTOU UID read, uid=0 skip, 0o700 evidence dir, two-sweep freeze). | `035c41c` |
| **P2a** | Both `--selftest` harnesses (~60 checks) wrapped as pytest tests so CI runs them. | `9b7b02d` |
| **P2b** | `test_lockbit.py` converted from argparse script to 8 pytest tests gating the 4 metrics; stable across 10 runs. CLI `main()` retained. | `0231d59` |
| **P3a** | 4 conditional assertions (`if r: assert …`) made unconditional via guaranteed-spike helper. | `f2249cc` |
| **P3b** | Dropped `pytest.ini`; `pyproject.toml` is the single config source (+ `asyncio_mode = strict`). No more "ignoring pyproject" warning. | `b37d858` |

### New totals

```
pytest:   182 passed in ~8s   (venv python3 3.11.9, pytest 9.0.3)
          = 96 agent + 59 backend + 19 sims + 8 lockbit
          (the 60 monitor/eBPF selftest checks now run inside pytest)
coverage: 54% overall (agent+backend) — was ~0% on backend
          containment.py 79% · ai_analyst 50% · routers 32–49% · tasks 44%
```

### Tooling installed into the venv (also pinned in `requirements-dev.txt`)
`pytest-asyncio==1.4.0`, `pytest-mock==3.15.1`, `pytest-cov==7.1.0`,
`freezegun==1.5.5`, `aiosqlite==0.22.1`.

### Not yet addressed (lower priority, from §6)
- `tests/integration/` still empty; the `integration` marker is registered but
  unused (no Redis/Postgres round-trip test yet).
- Frontend/landing still have no test runner (Vitest).
- `agent/graph.py`, `client.py`, `exceptions.py` still lack dedicated unit tests
  (partially exercised via the monitor selftest).
- Router coverage is concentrated on decision logic; `with-events`,
  `forensic-export`, `analyze`, and evidence endpoints remain untested.
