#!/usr/bin/env python3
"""
test_lockbit.py — Hybrid R-Sentry detection test for LockBit 5.0.

Measures the 4 project evaluation metrics:
  1. Files encrypted before detection
  2. Detection latency (ms)
  3. False-positive rate
  4. Coverage rate (% of traversal orders detected)

Usage:
    python3 tests/test_lockbit.py
"""
from __future__ import annotations

import os
import sys
import shutil
import tempfile
import time
from typing import List, Optional

# Allow running from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.monitor_ebpf import DetectionEngine, seed_canaries
from simulations.sim_common import populate_corpus, enumerate_targets, _prioritise
from simulations.sim_lockbit import PROFILE as LOCKBIT_PROFILE

HOST = "00000000-0000-0000-0000-000000000001"
TRAVERSAL_ORDERS = ["dfs", "random", "depth"]


def _make_sandbox() -> str:
    d = tempfile.mkdtemp(prefix="rsentry_lockbit_")
    open(os.path.join(d, ".rsentry_sandbox"), "w").close()
    return d


def _run_scenario(traversal: str, threshold: int = 2,
                  window: float = 3.0, verbose: bool = False) -> dict:
    root = _make_sandbox()
    try:
        populate_corpus(root, dirs=8, depth=4, files_per_dir=6)
        canary_paths = seed_canaries([root], per_dir=2)
        engine = DetectionEngine(
            HOST, [root], canary_paths,
            velocity_threshold=threshold,
            window_seconds=window,
            self_pid=os.getpid(),
        )

        targets = enumerate_targets(root, traversal, skip_aaa=False)
        targets = _prioritise(targets, LOCKBIT_PROFILE.priority_exts)

        events: List[dict] = []
        detection_file_index: Optional[int] = None
        t0 = time.perf_counter()
        detection_time: Optional[float] = None
        fake_pid = 31337
        ts = 1000.0

        for i, path in enumerate(targets):
            new_path = path + "." + LOCKBIT_PROFILE.ext_fn()
            evt = engine.observe_rename(fake_pid, 1, "lockbit5",
                                        path, new_path, ts=ts)
            ts += 0.001
            if evt is not None:
                events.append(evt)
                if detection_file_index is None:
                    detection_file_index = i + 1
                    detection_time = (time.perf_counter() - t0) * 1000
                if verbose:
                    print(f"  [event #{len(events)}] file={i+1} "
                          f"sev={evt['severity']} type={evt['event_type']}")

        elapsed = (time.perf_counter() - t0) * 1000
        return {
            "traversal":              traversal,
            "detected":               detection_file_index is not None,
            "files_before_detection": detection_file_index,
            "detection_latency_ms":   round(detection_time, 3) if detection_time else None,
            "total_files":            len(targets),
            "total_events":           len(events),
            "first_severity":         events[0]["severity"] if events else None,
            "first_event_type":       events[0]["event_type"] if events else None,
            "total_elapsed_ms":       round(elapsed, 3),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _run_fp_check() -> dict:
    root = _make_sandbox()
    try:
        populate_corpus(root, dirs=4, depth=2, files_per_dir=4)
        canary_paths = seed_canaries([root], per_dir=1)
        canary_set = set(os.path.normpath(p) for p in canary_paths)
        engine = DetectionEngine(HOST, [root], canary_paths,
                                 velocity_threshold=2, self_pid=os.getpid())
        targets = [p for p in enumerate_targets(root, "dfs")
                   if os.path.normpath(p) not in canary_set
                   and not os.path.basename(p).startswith(("AAA_", "zzz_"))]
        fp_events = []
        ts = 5000.0
        for path in targets[:30]:
            for suffix in (".bak", ".tmp", ".log"):
                evt = engine.observe_rename(9999, 1, "backup-tool",
                                            path, path + suffix, ts=ts)
                ts += 0.001
                if evt:
                    fp_events.append(evt)
        tested = len(targets[:30]) * 3
        return {
            "benign_renames_tested": tested,
            "false_positives":       len(fp_events),
            "fp_rate_pct":           round(len(fp_events) / max(1, tested) * 100, 2),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _run_latency_check() -> dict:
    root = _make_sandbox()
    try:
        populate_corpus(root, dirs=2, depth=1, files_per_dir=2)
        canary_paths = seed_canaries([root], per_dir=2)
        engine = DetectionEngine(HOST, [root], canary_paths, self_pid=os.getpid())
        victim = canary_paths[0]
        samples = []
        for i in range(10):
            t0 = time.perf_counter()
            engine.observe_rename(1234 + i, 1, "lockbit5",
                                  victim, victim + ".aaaaaaaaaaaa1234",
                                  ts=float(i))
            samples.append((time.perf_counter() - t0) * 1000)
        return {
            "canary_latency_avg_ms": round(sum(samples) / len(samples), 4),
            "canary_latency_max_ms": round(max(samples), 4),
            "under_500ms":           max(samples) < 500.0,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Pytest interface — gates the 4 evaluation metrics in CI.
# The scenarios run once via a module-scoped fixture; each metric is its own
# test so a failure points at the exact target that regressed.
# ---------------------------------------------------------------------------
import pytest


@pytest.fixture(scope="module")
def lockbit_metrics():
    """Run all detection scenarios once and return aggregated metrics."""
    results = [_run_scenario(t, threshold=2, window=3.0) for t in TRAVERSAL_ORDERS]
    detected = [r for r in results if r["detected"]]
    avg_files = (sum(r["files_before_detection"] for r in detected) / len(detected)
                 if detected else float("inf"))
    avg_latency = (sum(r["detection_latency_ms"] for r in detected) / len(detected)
                   if detected else float("inf"))
    return {
        "results": results,
        "coverage_pct": len(detected) / len(TRAVERSAL_ORDERS) * 100,
        "avg_files": avg_files,
        "avg_latency_ms": avg_latency,
        "fp": _run_fp_check(),
        "latency": _run_latency_check(),
    }


def test_coverage_all_traversals_detected(lockbit_metrics):
    # Target: > 95% of traversal orders detected
    assert lockbit_metrics["coverage_pct"] > 95, \
        f"coverage {lockbit_metrics['coverage_pct']:.0f}% — some traversals missed"


@pytest.mark.parametrize("idx,traversal", list(enumerate(TRAVERSAL_ORDERS)))
def test_each_traversal_detected(lockbit_metrics, idx, traversal):
    # Detection within the file budget is the invariant. The *severity* of the
    # first alert is not asserted — it legitimately varies (CANARY_TOUCHED vs a
    # velocity-burst PROCESS_ANOMALY) with which file the traversal reaches first.
    r = lockbit_metrics["results"][idx]
    assert r["detected"], f"traversal={traversal} did not detect LockBit"
    assert r["files_before_detection"] <= 3, \
        f"traversal={traversal} took {r['files_before_detection']} files to detect"


def test_files_before_detection_under_3(lockbit_metrics):
    assert lockbit_metrics["avg_files"] < 3, \
        f"avg files before detection {lockbit_metrics['avg_files']:.1f} >= 3"


def test_detection_latency_under_500ms(lockbit_metrics):
    assert lockbit_metrics["avg_latency_ms"] < 500, \
        f"avg detection latency {lockbit_metrics['avg_latency_ms']:.1f}ms >= 500ms"


def test_false_positive_rate_under_2pct(lockbit_metrics):
    fp_rate = lockbit_metrics["fp"]["fp_rate_pct"]
    assert fp_rate < 2, f"FP rate {fp_rate}% >= 2% on benign .bak/.tmp/.log renames"


def test_canary_latency_under_500ms(lockbit_metrics):
    assert lockbit_metrics["latency"]["under_500ms"], \
        f"canary-touch max latency {lockbit_metrics['latency']['canary_latency_max_ms']}ms >= 500ms"


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="LockBit 5.0 detection test")
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--window",    type=float, default=3.0)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    print("=" * 60)
    print("Hybrid R-Sentry — LockBit 5.0 Detection Test")
    print(f"Profile : {LOCKBIT_PROFILE.name} | mode={LOCKBIT_PROFILE.mode} "
          f"| ext=16-char-random | delay={LOCKBIT_PROFILE.delay}s")
    print(f"Engine  : threshold={args.threshold} | window={args.window}s")
    print("=" * 60)

    results = []
    detected_count = 0

    print("\n[1] Detection across traversal strategies")
    for traversal in TRAVERSAL_ORDERS:
        print(f"\n  traversal={traversal}")
        r = _run_scenario(traversal, args.threshold, args.window, args.verbose)
        results.append(r)
        if r["detected"]:
            detected_count += 1
            print(f"    ✓ Detected at file #{r['files_before_detection']}"
                  f"/{r['total_files']}"
                  f" | latency={r['detection_latency_ms']:.3f}ms"
                  f" | sev={r['first_severity']}"
                  f" | type={r['first_event_type']}")
        else:
            print(f"    ✗ NOT detected ({r['total_files']} files processed)")

    coverage_pct = detected_count / len(TRAVERSAL_ORDERS) * 100

    print("\n[2] False-positive check (benign .bak/.tmp/.log renames)")
    fp = _run_fp_check()
    print(f"    renames tested={fp['benign_renames_tested']} | "
          f"false positives={fp['false_positives']} | "
          f"FP rate={fp['fp_rate_pct']}%")

    print("\n[3] Canary-touch latency (target < 500ms)")
    lat = _run_latency_check()
    print(f"    avg={lat['canary_latency_avg_ms']}ms | "
          f"max={lat['canary_latency_max_ms']}ms | "
          f"under_500ms={lat['under_500ms']}")

    detected_results = [r for r in results if r["detected"]]
    avg_files   = (sum(r["files_before_detection"] for r in detected_results)
                   / len(detected_results)) if detected_results else float("inf")
    avg_latency = (sum(r["detection_latency_ms"] for r in detected_results)
                   / len(detected_results)) if detected_results else float("inf")

    print("\n" + "=" * 60)
    print("EVALUATION SUMMARY — LockBit 5.0")
    print("=" * 60)
    print(f"{'Metric':<40} {'Result':<20} {'Target'}")
    print("-" * 60)

    rows = [
        ("Files before detection (avg)", f"{avg_files:.1f}",   "< 3",    avg_files < 3),
        ("Detection latency ms (avg)",   f"{avg_latency:.3f}", "< 500ms", avg_latency < 500),
        ("False-positive rate",          f"{fp['fp_rate_pct']}%", "< 2%", fp["fp_rate_pct"] < 2),
        ("Coverage rate",                f"{coverage_pct:.0f}%",  "> 95%", coverage_pct > 95),
    ]
    all_pass = True
    for label, value, target, ok in rows:
        all_pass &= ok
        print(f"  {'✓' if ok else '✗'} {label:<38} {value:<20} {target}")

    print("=" * 60)
    print(f"  {'ALL TARGETS MET' if all_pass else 'SOME TARGETS MISSED'}")
    print("=" * 60)

    print("\nPer-traversal detail:")
    for r in results:
        status = "DETECTED" if r["detected"] else "MISSED"
        info   = f"file #{r['files_before_detection']}" if r["detected"] else "—"
        print(f"  {r['traversal']:<8}  {status:<10}  {info}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
