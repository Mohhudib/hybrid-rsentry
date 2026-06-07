# Session 10 — Full End-to-End Pipeline Integration Test

**Date:** 2026-06-07
**Scope:** Live integration test of the running system (Docker stack, FastAPI,
Celery, Postgres, Redis, WebSocket) + full pytest suite. The attack simulations
(`simulations/sim_*.py`) were explicitly **out of scope** and were neither read
nor executed directly; they are run separately (see session_09).
**Environment:** Kali Linux, kernel 6.19, Python 3.11.9, all containers up.

## Executive summary

| Check | Result |
|---|---|
| 1. Docker containers healthy | ✅ 5/5 up (Postgres + Redis report `healthy`) |
| 2. `/health` endpoint | ✅ 200 in 0.145 s |
| 3. Agent→backend test event | ✅ POST 201, event_id returned |
| 4. Event reaches DB + WebSocket | ✅ persisted in Postgres + pushed over WS in 0.155 s |
| 5. Full pytest suite (182 tests) | ⚠️ **181 passed, 1 failed** in 17.58 s |
| 6. Total coverage | **55%** (backend + agent) |

> **One test failed** — `tests/unit/sims/test_simulations.py::TestSafety::test_no_agent_monitor_import`.
> This is a **real regression introduced in session_09**, not a pipeline fault.
> Root cause and fix are documented in the [pytest section](#failure-detail--regression-from-session_09). It was left
> unfixed in this session because modifying `simulations/sim_*.py` was out of scope.

---

## 1 — Docker container health

`docker compose ps` / `docker inspect`:

| Container | Image | Status | Health |
|---|---|---|---|
| `rsentry_postgres` | postgres:16-alpine | running | **healthy** |
| `rsentry_redis` | redis:7-alpine | running | **healthy** |
| `rsentry_backend` | hybrid-rsentry-backend | running | none (no healthcheck defined) |
| `rsentry_celery` | hybrid-rsentry-celery_worker | running | none (no healthcheck defined) |
| `rsentry_frontend` | hybrid-rsentry-frontend | running | none (no healthcheck defined) |

Backend and Celery have no Docker healthcheck, so they were verified by live
probes instead:

- **Backend:** `/health` → `200` (below).
- **Celery:** `celery -A backend.workers.tasks:celery_app inspect ping` →
  `celery@9828b2881329: OK / pong` — **1 node online**.

The stack was already running (uptime ~2 days); `docker compose up -d` was a
no-op confirming convergence rather than a cold start.

## 2 — `/health` endpoint

```
GET http://localhost:8000/health
http_code=200  time_total=0.145075s
body: {"status":"ok","service":"hybrid-rsentry-backend"}
```

## 3 & 4 — Agent → backend → DB → WebSocket

A WebSocket client connected to `ws://localhost:8000/ws/alerts` (which subscribes
to the `rsentry:alerts`, `rsentry:events`, `rsentry:ai` Redis channels), then a
benign `HEARTBEAT`/`LOW` event was POSTed to `/api/events` carrying a unique
marker `PIPELINE_E2E_22f01b36…` in `file_path`/`details`. A `HEARTBEAT`/`LOW`
event was chosen so the full transport path is exercised **without** triggering
containment/AI side-effects.

**Path exercised:** FastAPI `POST /api/events` → `Event` row + `db.commit()` →
`push_event_ws.delay(...)` (**Celery**) → `r.publish("rsentry:events", …)`
(**Redis** pub/sub) → WS server → connected client. This touches all four
backend components in one round trip.

| Stage | Timing | Result |
|---|---|---|
| WS connect | 0.2507 s | connected |
| HTTP POST `/api/events` | 1.1117 s | **201 Created**, `event_id=e30cfb42-e362-4402-8996-7d2dcc6cde79` |
| WS push latency (POST→received) | 0.1546 s | received `type=new_event`, `event_type=HEARTBEAT` with the marker |

**Database persistence** (`SELECT … FROM events WHERE id='e30cfb42-…'`):

```
                  id                  | host_id | event_type | severity | process_name |                  file_path
--------------------------------------+---------+------------+----------+--------------+----------------------------------------------
 e30cfb42-e362-4402-8996-7d2dcc6cde79 | ATOMIC  | HEARTBEAT  | LOW      | pipeline-e2e | /tmp/PIPELINE_E2E_22f01b36…076ade216d075dc6a6e.txt
```

Event count went **2140 → 2141**. The event was both persisted and delivered
over the WebSocket — the end-to-end pipeline is verified working.

---

## 5 — Full pytest suite (182 tests)

```
PYTHONPATH=. pytest -v --cov=backend --cov=agent --cov-report=term-missing --junitxml=…
================== 1 failed, 181 passed, 5 warnings in 17.58s ==================
```

- **Collected:** 182 · **Passed:** 181 · **Failed:** 1 · **Skipped:** 0
- **Wall-clock:** 17.58 s · **Sum of per-test times:** 8.356 s

### Slowest tests

| Time | Status | Test |
|---|---|---|
| 2441.0 ms | ✅ | `tests/test_lockbit.py::test_coverage_all_traversals_detected` |
| 2206.0 ms | ✅ | `test_lineage.TestScoreForEvent::test_returns_dict` |
| 1027.0 ms | ✅ | `test_ai_analyst.TestFallbackChain::test_falls_through_to_second_on_ratelimit` |
| 136.0 ms | ✅ | `test_routers_hosts::test_get_host_404` |
| 130.0 ms | ✅ | `test_tasks.TestPushTasks::test_push_alert_ws_payload` |
| 83.0 ms | ✅ | `test_routers_alerts::test_counts_group_by_assembly` |

### Failure detail — regression from session_09

```
FAILED tests/unit/sims/test_simulations.py::TestSafety::test_no_agent_monitor_import (6.0 ms)
```

The test asserts no simulation module's source contains the substring
`"agent.monitor"`:

```python
def test_no_agent_monitor_import(self):
    for m in _ALL_SIMS:
        assert "agent.monitor" not in inspect.getsource(m)
```

**Root cause:** session_09's defense-validation harness added
`from agent.monitor_ebpf import build_bpf` to `simulations/sim_lockbit.py`. The
module path `agent.monitor_ebpf` **contains the substring** `agent.monitor`, so
the blunt substring check trips — even though the import is `monitor_ebpf` (the
unit-testable DetectionEngine), **not** the live `agent.monitor` watchdog the
guard is meant to forbid. `sim_akira`/`sim_qilin` reach the engine indirectly via
`sim_common.build_validation_engine`, so their own source does not contain the
substring and they pass.

**Recommended fix (next session, when sim files are back in scope):** either
(a) tighten the test to forbid the watchdog precisely — e.g.
`re.search(r"agent\.monitor(?!_ebpf)\b", src)` — or (b) move the
`build_bpf`/engine imports out of `sim_lockbit.py` into the shared
`sim_common.py` helper so no family file names `agent.monitor_ebpf` directly.
Option (a) is preferred: the guard's real intent is "don't import the live
watchdog," and `monitor_ebpf` is legitimately allowed.

### Full per-test results

Every collected test, grouped by class, with status and exact time:
<!-- generated from JUnit XML (/tmp/pytest_junit.xml) -->

#### `tests/test_lockbit.py` (8 tests)

| Test | Status | Time |
|---|---|---|
| `test_coverage_all_traversals_detected` | ✅ PASS | 2441.0 ms |
| `test_each_traversal_detected[0-dfs]` | ✅ PASS | 2.0 ms |
| `test_each_traversal_detected[1-random]` | ✅ PASS | 1.0 ms |
| `test_each_traversal_detected[2-depth]` | ✅ PASS | 2.0 ms |
| `test_files_before_detection_under_3` | ✅ PASS | 1.0 ms |
| `test_detection_latency_under_500ms` | ✅ PASS | 2.0 ms |
| `test_false_positive_rate_under_2pct` | ✅ PASS | 1.0 ms |
| `test_canary_latency_under_500ms` | ✅ PASS | 1.0 ms |

#### `test_adaptive` (18 tests)

| Test | Status | Time |
|---|---|---|
| `TestMarkovGate::test_ebpf_backend_skips_repositioner` | ✅ PASS | 46.0 ms |
| `TestObserve::test_adds_state` | ✅ PASS | 2.0 ms |
| `TestObserve::test_multiple_states` | ✅ PASS | 1.0 ms |
| `TestObserve::test_n_obs_zero_with_one_event` | ✅ PASS | 1.0 ms |
| `TestObserve::test_n_obs_increments` | ✅ PASS | 1.0 ms |
| `TestObserve::test_counts_updated` | ✅ PASS | 1.0 ms |
| `TestPredictedHotspots::test_empty_before_min_obs` | ✅ PASS | 1.0 ms |
| `TestPredictedHotspots::test_returns_list_after_enough` | ✅ PASS | 2.0 ms |
| `TestPredictedHotspots::test_top_n_respected` | ✅ PASS | 1.0 ms |
| `TestReposition::test_returns_list` | ✅ PASS | 3.0 ms |
| `TestReposition::test_returns_original_no_hotspots` | ✅ PASS | 2.0 ms |
| `TestReposition::test_updates_fs_graph` | ✅ PASS | 3.0 ms |
| `TestShouldReposition::test_false_no_observations` | ✅ PASS | 1.0 ms |
| `TestShouldReposition::test_false_below_min` | ✅ PASS | 1.0 ms |
| `TestShouldReposition::test_true_strong_pattern` | ✅ PASS | 1.0 ms |
| `TestSummary::test_returns_dict` | ✅ PASS | 1.0 ms |
| `TestSummary::test_required_keys` | ✅ PASS | 1.0 ms |
| `TestSummary::test_initial_values` | ✅ PASS | 1.0 ms |

#### `test_containment` (29 tests)

| Test | Status | Time |
|---|---|---|
| `TestCaptureEvidence::test_creates_dir_mode_0700` | ✅ PASS | 2.0 ms |
| `TestContainPipeline::test_full_pipeline_order_and_result` | ✅ PASS | 11.0 ms |
| `TestContainPipeline::test_skips_iptables_when_not_root` | ✅ PASS | 10.0 ms |
| `TestContainPipeline::test_skip_iptables_flag` | ✅ PASS | 11.0 ms |
| `TestContainPipeline::test_sigstop_total_failure_sets_error` | ✅ PASS | 11.0 ms |
| `TestContainmentResult::test_to_dict_keys` | ✅ PASS | 1.0 ms |
| `TestContainmentResult::test_tree_size_counts_root_plus_descendants` | ✅ PASS | 1.0 ms |
| `TestContainmentResult::test_evidence_dir_serialised_as_str_or_none` | ✅ PASS | 1.0 ms |
| `TestDryRun::test_no_kill_marks_dry_run` | ✅ PASS | 4.0 ms |
| `TestFreezeTree::test_stops_root_and_descendants` | ✅ PASS | 5.0 ms |
| `TestFreezeTree::test_second_sweep_catches_new_children` | ✅ PASS | 4.0 ms |
| `TestFreezeTree::test_root_stop_failure_still_reports` | ✅ PASS | 7.0 ms |
| `TestGetDescendants::test_returns_child_pids` | ✅ PASS | 5.0 ms |
| `TestGetDescendants::test_no_such_process_returns_empty` | ✅ PASS | 3.0 ms |
| `TestIptablesDrop::test_drops_for_non_root_uid` | ✅ PASS | 6.0 ms |
| `TestIptablesDrop::test_skips_uid_zero` | ✅ PASS | 6.0 ms |
| `TestIptablesDrop::test_missing_status_returns_none` | ✅ PASS | 4.0 ms |
| `TestIptablesDrop::test_iptables_binary_missing_returns_none` | ✅ PASS | 5.0 ms |
| `TestIptablesDrop::test_iptables_failure_returns_none` | ✅ PASS | 5.0 ms |
| `TestKillTree::test_kills_descendants_before_root` | ✅ PASS | 4.0 ms |
| `TestSigkill::test_success_then_reaped` | ✅ PASS | 5.0 ms |
| `TestSigkill::test_already_dead_returns_true` | ✅ PASS | 3.0 ms |
| `TestSigkill::test_permission_denied_returns_false` | ✅ PASS | 3.0 ms |
| `TestSigstop::test_success` | ✅ PASS | 5.0 ms |
| `TestSigstop::test_process_gone_returns_false` | ✅ PASS | 3.0 ms |
| `TestSigstop::test_permission_denied_returns_false` | ✅ PASS | 3.0 ms |

#### `test_entropy` (21 tests)

| Test | Status | Time |
|---|---|---|
| `TestEntropyEngine::test_nonexistent_file_returns_none` | ✅ PASS | 1.0 ms |
| `TestEntropyEngine::test_single_observation_no_spike` | ✅ PASS | 3.0 ms |
| `TestEntropyEngine::test_spike_returns_alert` | ✅ PASS | 3.0 ms |
| `TestEntropyEngine::test_flush_removes_record` | ✅ PASS | 3.0 ms |
| `TestEntropyEngine::test_bulk_scan_returns_list` | ✅ PASS | 3.0 ms |
| `TestEntropyEngine::test_stats_dataframe_empty` | ✅ PASS | 2.0 ms |
| `TestEntropyRecord::test_initial_delta_zero` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_single_sample_delta_zero` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_delta_max_minus_min` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_latest_returns_last` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_latest_empty_zero` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_window_respected` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_recent_spike_false_one_sample` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_recent_spike_true_on_large_delta` | ✅ PASS | 1.0 ms |
| `TestEntropyRecord::test_recent_spike_false_small_delta` | ✅ PASS | 1.0 ms |
| `TestShannonEntropy::test_empty_bytes_returns_zero` | ✅ PASS | 1.0 ms |
| `TestShannonEntropy::test_uniform_bytes_high_entropy` | ✅ PASS | 2.0 ms |
| `TestShannonEntropy::test_single_repeated_byte_low_entropy` | ✅ PASS | 2.0 ms |
| `TestShannonEntropy::test_returns_float` | ✅ PASS | 2.0 ms |
| `TestShannonEntropy::test_between_zero_and_eight` | ✅ PASS | 2.0 ms |
| `TestShannonEntropy::test_random_data_high_entropy` | ✅ PASS | 2.0 ms |

#### `test_lineage` (17 tests)

| Test | Status | Time |
|---|---|---|
| `TestCollectAncestors::test_no_parent_empty_lists` | ✅ PASS | 4.0 ms |
| `TestCollectAncestors::test_single_parent_captured` | ✅ PASS | 5.0 ms |
| `TestCollectAncestors::test_access_denied_handled` | ✅ PASS | 2.0 ms |
| `TestProcessLineage::test_to_dict_has_required_keys` | ✅ PASS | 1.0 ms |
| `TestProcessLineage::test_score_rounded` | ✅ PASS | 1.0 ms |
| `TestProcessLineage::test_cmdline_joined` | ✅ PASS | 1.0 ms |
| `TestProcessLineage::test_initial_score_zero` | ✅ PASS | 1.0 ms |
| `TestProcessLineage::test_initial_reasons_empty` | ✅ PASS | 1.0 ms |
| `TestScoreForEvent::test_returns_dict` | ✅ PASS | 2206.0 ms |
| `TestScoreForEvent::test_required_keys` | ✅ PASS | 6.0 ms |
| `TestScoreForEvent::test_nonexistent_pid_baseline_score` | ✅ PASS | 7.0 ms |
| `TestScoreForEvent::test_score_is_float` | ✅ PASS | 4.0 ms |
| `TestScoreForEvent::test_ancestors_is_list` | ✅ PASS | 3.0 ms |
| `TestSha256OfExe::test_valid_file_returns_64char_hex` | ✅ PASS | 2.0 ms |
| `TestSha256OfExe::test_nonexistent_returns_none` | ✅ PASS | 1.0 ms |
| `TestSha256OfExe::test_same_content_same_hash` | ✅ PASS | 2.0 ms |
| `TestSha256OfExe::test_different_content_different_hash` | ✅ PASS | 2.0 ms |

#### `test_selftests` (2 tests)

| Test | Status | Time |
|---|---|---|
| `test_monitor_ebpf_selftest_passes` | ✅ PASS | 8.0 ms |
| `test_monitor_selftest_passes` | ✅ PASS | 16.0 ms |

#### `test_severity` (12 tests)

| Test | Status | Time |
|---|---|---|
| `TestCanarySeverity::test_all_four_canary_prefixes_present` | ✅ PASS | 6.0 ms |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[AAA_]` | ✅ PASS | 6.0 ms |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[aaa_]` | ✅ PASS | 16.0 ms |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[ZZZ_]` | ✅ PASS | 9.0 ms |
| `TestCanarySeverity::test_is_canary_detects_all_prefixes[zzz_]` | ✅ PASS | 5.0 ms |
| `TestCanarySeverity::test_non_canary_not_detected` | ✅ PASS | 2.0 ms |
| `TestEntropySeverity::test_alert_has_severity_field` | ✅ PASS | 6.0 ms |
| `TestEntropySeverity::test_alert_event_type_correct` | ✅ PASS | 9.0 ms |
| `TestEntropySeverity::test_entropy_delta_non_negative` | ✅ PASS | 4.0 ms |
| `TestLineageSeverity::test_current_process_low_score` | ✅ PASS | 5.0 ms |
| `TestLineageSeverity::test_nonexistent_pid_baseline` | ✅ PASS | 2.0 ms |
| `TestLineageSeverity::test_score_capped_at_100` | ✅ PASS | 15.0 ms |

#### `test_ai_analyst` (16 tests)

| Test | Status | Time |
|---|---|---|
| `TestAnalyzeEventEnvelopes::test_returns_result_on_success` | ✅ PASS | 17.0 ms |
| `TestAnalyzeEventEnvelopes::test_auth_error_envelope` | ✅ PASS | 23.0 ms |
| `TestAnalyzeEventEnvelopes::test_json_error_envelope` | ✅ PASS | 17.0 ms |
| `TestBuildPrompt::test_includes_core_fields` | ✅ PASS | 35.0 ms |
| `TestBuildPrompt::test_markov_reposition_context_injected` | ✅ PASS | 10.0 ms |
| `TestBuildPrompt::test_handles_missing_fields` | ✅ PASS | 12.0 ms |
| `TestCallNvidia::test_extracts_clean_json` | ✅ PASS | 13.0 ms |
| `TestCallNvidia::test_extracts_json_embedded_in_text` | ✅ PASS | 12.0 ms |
| `TestCallNvidia::test_no_json_raises` | ✅ PASS | 13.0 ms |
| `TestCallNvidia::test_malformed_json_raises` | ✅ PASS | 13.0 ms |
| `TestFallbackChain::test_skips_none_clients` | ✅ PASS | 13.0 ms |
| `TestFallbackChain::test_falls_through_to_second_on_ratelimit` | ✅ PASS | 1027.0 ms |
| `TestFallbackChain::test_auth_error_stops_fallback` | ✅ PASS | 25.0 ms |
| `TestFallbackChain::test_all_fail_raises_last` | ✅ PASS | 14.0 ms |
| `TestRateLimit::test_proceeds_when_slot_free` | ✅ PASS | 14.0 ms |
| `TestRateLimit::test_waits_then_proceeds` | ✅ PASS | 16.0 ms |

#### `test_main` (5 tests)

| Test | Status | Time |
|---|---|---|
| `test_health` | ✅ PASS | 62.0 ms |
| `test_root` | ✅ PASS | 39.0 ms |
| `test_ai_health_accepts_within_cap` | ✅ PASS | 41.0 ms |
| `test_ai_health_rejects_over_cap` | ✅ PASS | 33.0 ms |
| `test_ai_health_empty_default` | ✅ PASS | 43.0 ms |

#### `test_routers_alerts` (9 tests)

| Test | Status | Time |
|---|---|---|
| `test_list_alerts_empty` | ✅ PASS | 63.0 ms |
| `test_list_alerts_returns_seeded` | ✅ PASS | 58.0 ms |
| `test_list_alerts_filter_by_severity` | ✅ PASS | 57.0 ms |
| `test_list_alerts_limit_cap` | ✅ PASS | 41.0 ms |
| `test_counts_all_zero_when_empty` | ✅ PASS | 43.0 ms |
| `test_counts_group_by_assembly` | ✅ PASS | 83.0 ms |
| `test_counts_excludes_acknowledged` | ✅ PASS | 56.0 ms |
| `test_acknowledge_alert` | ✅ PASS | 76.0 ms |
| `test_get_alert_404` | ✅ PASS | 44.0 ms |

#### `test_routers_events` (10 tests)

| Test | Status | Time |
|---|---|---|
| `test_ingest_creates_event_and_alert_for_high` | ✅ PASS | 62.0 ms |
| `test_ingest_low_severity_no_alert` | ✅ PASS | 54.0 ms |
| `test_ingest_markov_internal_skips_alert` | ✅ PASS | 50.0 ms |
| `test_ingest_upserts_host` | ✅ PASS | 51.0 ms |
| `test_auto_contain_on_canary_critical` | ✅ PASS | 63.0 ms |
| `test_no_auto_contain_for_high` | ✅ PASS | 61.0 ms |
| `test_auto_contain_on_high_lineage` | ✅ PASS | 64.0 ms |
| `test_ingest_dispatches_alert_tasks` | ✅ PASS | 69.0 ms |
| `test_ingest_validation_entropy_out_of_range` | ✅ PASS | 39.0 ms |
| `test_list_events_and_get` | ✅ PASS | 72.0 ms |

#### `test_routers_hosts` (7 tests)

| Test | Status | Time |
|---|---|---|
| `test_list_hosts_empty` | ✅ PASS | 38.0 ms |
| `test_list_and_filter_contained` | ✅ PASS | 55.0 ms |
| `test_get_host_404` | ✅ PASS | 136.0 ms |
| `test_risk_summary` | ✅ PASS | 60.0 ms |
| `test_risk_summary_404` | ✅ PASS | 43.0 ms |
| `test_contain_and_release` | ✅ PASS | 61.0 ms |
| `test_contain_404` | ✅ PASS | 35.0 ms |

#### `test_tasks` (12 tests)

| Test | Status | Time |
|---|---|---|
| `TestEnv::test_os_env_takes_precedence` | ✅ PASS | 10.0 ms |
| `TestEnv::test_reads_from_dotenv_file` | ✅ PASS | 11.0 ms |
| `TestEnv::test_strips_inline_comment` | ✅ PASS | 14.0 ms |
| `TestEnv::test_strips_quotes` | ✅ PASS | 11.0 ms |
| `TestEnv::test_single_quotes_stripped` | ✅ PASS | 12.0 ms |
| `TestEnv::test_skips_commented_line` | ✅ PASS | 11.0 ms |
| `TestEnv::test_default_when_missing` | ✅ PASS | 10.0 ms |
| `TestEnv::test_url_with_hash_not_truncated` | ✅ PASS | 11.0 ms |
| `TestPushTasks::test_push_alert_ws_payload` | ✅ PASS | 130.0 ms |
| `TestPushTasks::test_push_event_ws_payload` | ✅ PASS | 14.0 ms |
| `TestRun::test_runs_coroutine_returns_value` | ✅ PASS | 10.0 ms |
| `TestRun::test_propagates_exception` | ✅ PASS | 10.0 ms |

#### `test_simulations` (19 tests)

| Test | Status | Time |
|---|---|---|
| `TestImports::test_sim_dfs_importable` | ✅ PASS | 1.0 ms |
| `TestImports::test_sim_random_importable` | ✅ PASS | 1.0 ms |
| `TestImports::test_sim_depth_importable` | ✅ PASS | 1.0 ms |
| `TestImports::test_sim_akira_importable` | ✅ PASS | 1.0 ms |
| `TestImports::test_sim_qilin_importable` | ✅ PASS | 1.0 ms |
| `TestImports::test_sim_lockbit_importable` | ✅ PASS | 1.0 ms |
| `TestProductionSimProfiles::test_profile_mode[…akira-intermittent]` | ✅ PASS | 2.0 ms |
| `TestProductionSimProfiles::test_profile_mode[…qilin-percent]` | ✅ PASS | 1.0 ms |
| `TestProductionSimProfiles::test_profile_mode[…lockbit-two_pass]` | ✅ PASS | 1.0 ms |
| `TestProductionSimProfiles::test_profile_has_ext_fn[…akira]` | ✅ PASS | 1.0 ms |
| `TestProductionSimProfiles::test_profile_has_ext_fn[…qilin]` | ✅ PASS | 1.0 ms |
| `TestProductionSimProfiles::test_profile_has_ext_fn[…lockbit]` | ✅ PASS | 2.0 ms |
| `TestProductionSimProfiles::test_uses_main_for_for_safe_orchestration[…akira]` | ✅ PASS | 1.0 ms |
| `TestProductionSimProfiles::test_uses_main_for_for_safe_orchestration[…qilin]` | ✅ PASS | 1.0 ms |
| `TestProductionSimProfiles::test_uses_main_for_for_safe_orchestration[…lockbit]` | ✅ PASS | 7.0 ms |
| `TestSafety::test_no_sigstop_in_sims` | ✅ PASS | 2.0 ms |
| `TestSafety::test_no_agent_monitor_import` | ❌ **FAIL** | 6.0 ms |
| `TestSafety::test_no_canary_files_touched` | ✅ PASS | 2.0 ms |
| `TestSafety::test_sim_dir_under_tmp` | ✅ PASS | 1.0 ms |

---

## 6 — Coverage

`--cov=backend --cov=agent` (term-missing). **Total: 55%** (1321 of 2912
statements missed).

| Module | Stmts | Miss | Cover |
|---|---|---|---|
| `agent/adaptive.py` | 116 | 41 | 65% |
| `agent/client.py` | 66 | 66 | **0%** |
| `agent/containment.py` | 183 | 38 | 79% |
| `agent/entropy.py` | 99 | 12 | 88% |
| `agent/exceptions.py` | 31 | 31 | **0%** |
| `agent/graph.py` | 86 | 59 | 31% |
| `agent/lineage.py` | 193 | 37 | 81% |
| `agent/monitor.py` | 434 | 251 | 42% |
| `agent/monitor_ebpf.py` | 806 | 356 | 56% |
| `backend/main.py` | 42 | 7 | 83% |
| `backend/migrations/env.py` | 34 | 34 | **0%** |
| `backend/models/database.py` | 13 | 3 | 77% |
| `backend/models/schemas.py` | 136 | 0 | **100%** |
| `backend/routers/alerts.py` | 122 | 83 | 32% |
| `backend/routers/events.py` | 75 | 47 | 37% |
| `backend/routers/hosts.py` | 55 | 28 | 49% |
| `backend/routers/ws.py` | 69 | 46 | 33% |
| `backend/services/ai_analyst.py` | 207 | 103 | 50% |
| `backend/workers/tasks.py` | 142 | 79 | 44% |
| **TOTAL** | **2912** | **1321** | **55%** |

**Coverage notes (not failures):** the lowest-covered files are exercised at
runtime rather than by unit tests — `agent/client.py` and `agent/exceptions.py`
(0%) are agent-side HTTP/whitelist paths; `backend/migrations/env.py` (0%) is the
Alembic harness; the routers/tasks (32–44%) run their happy paths in this live
pipeline test but their unit coverage focuses on logic branches. `schemas.py` is
100%.

---

## How to reproduce

```bash
cd ~/hybrid-rsentry
docker compose ps                                    # 1. container health
curl -s -w '%{http_code} %{time_total}s\n' localhost:8000/health   # 2. health
docker exec rsentry_celery celery -A backend.workers.tasks:celery_app inspect ping
# 3/4: connect ws://localhost:8000/ws/alerts, POST a marked event to /api/events,
#      confirm WS receipt + SELECT … FROM events WHERE id=<event_id>
set -a && source .env && set +a
PYTHONPATH=. pytest -v --cov=backend --cov=agent --cov-report=term-missing   # 5/6
```

## Conclusion

The end-to-end pipeline is **fully operational**: all five containers run, the
backend and Celery worker respond, and an event flows API → Postgres → Celery →
Redis → WebSocket and is observed at both the database and the live socket. The
test suite is green **except for one pre-existing regression**
(`test_no_agent_monitor_import`) introduced by session_09's simulation changes,
which is documented above with a recommended fix and was left untouched because
simulation files were out of scope this session. Total coverage is **55%**.
