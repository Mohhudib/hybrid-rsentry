#!/usr/bin/env python3
"""
tests/evaluation/efficiency/runner.py — orchestrate the Efficiency latency sweep. [ROOT]

Reuses harness.run_trial over the MALICIOUS plan only (benign trials have no
detection timing → latency is malicious-only, design §2). For each trial the
harness already captures the full stage ladder on CLOCK_MONOTONIC plus
files_touched_before_freeze; this runner just records the raw trials and the
aggregation derives the §2 intervals.

It carries the SAME integrity guard as the efficacy runner (not reinvented):
warm-up excluded, resumable on sample_id, each trial wrapped in try/except
(failures recorded, never silently dropped), recorded-vs-planned reconciliation,
and a loud INCOMPLETE banner — a perfect-looking latency table must never hide
dropped trials.

Usage (root):
    sudo -E ~/hybrid-rsentry/venv/bin/python -m tests.evaluation.efficiency.runner --n 3
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.evaluation import harness
from tests.evaluation.conftest import RESULTS_DIR, append_trial_record, read_trials
from tests.evaluation.corpus import malicious_samples
from tests.evaluation.efficiency import metrics

WARMUP_PREFIX = metrics.WARMUP_PREFIX
EFFICIENCY_RAW = RESULTS_DIR / "efficiency_raw.json"
EFFICIENCY_REPORT = RESULTS_DIR / "efficiency_report.json"


# --------------------------------------------------------------------------- #
# Plan (malicious only)
# --------------------------------------------------------------------------- #

def _planned_malicious(n_per_family: int) -> Dict[str, str]:
    """{sample_id: family} for every malicious trial the sweep should run."""
    return {e["sample_id"]: e["family"]
            for e in malicious_samples.malicious_plan(n_per_family)}


def _warmup_entries(warmup_k: int) -> List[dict]:
    base = malicious_samples.malicious_plan(1)[0]            # an akira entry
    out = []
    for i in range(warmup_k):
        e = dict(base)
        e["sample_id"] = f"{WARMUP_PREFIX}{i:03d}"
        out.append(e)
    return out


def _append_error_record(entry: dict, exc: BaseException) -> None:
    """Record a FAILED malicious trial so a crash/error is a visible data point
    (all timing None → excluded from latency; surfaced by completeness)."""
    rec = {
        "sample_id": entry["sample_id"], "label": 1,
        "family_or_class": entry["family"],
        "detected": False, "contained": False, "layer_fired": None,
        "t0": None, "t_detect": None, "t_decide": None, "t_sigstop": None,
        "t_isolate": None, "t_kill": None, "t_complete": None,
        "canary_survived": None, "files_touched_before_freeze": None,
        "agent_restart_id": "", "host_loadavg": 0.0,
        "raw_log_excerpt": "", "error": f"{type(exc).__name__}: {exc}",
    }
    with open(EFFICIENCY_RAW, "a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


# --------------------------------------------------------------------------- #
# Aggregation → JSON (pure; callable without root via --aggregate-only)
# --------------------------------------------------------------------------- #

def write_efficiency_reports(results_dir: Path = RESULTS_DIR,
                             n_per_family: "int | None" = None) -> dict:
    """Read efficiency_raw.json and write efficiency_report.json. Returns the
    aggregate. Embeds completeness so an incomplete run can't pass as full-N."""
    trials = read_trials(EFFICIENCY_RAW)
    plan = [t for t in trials if not str(t.get("sample_id", "")).startswith(WARMUP_PREFIX)]

    comp = None
    if n_per_family is not None:
        comp = metrics.completeness(plan, _planned_malicious(n_per_family))

    stages = {name: metrics.summary_stats(metrics.collect_interval(plan, name))
              for name in metrics.STAGE_NAMES}
    report = {
        "_meta": {
            "n_trials": len(plan),
            "n_per_family": n_per_family,
            "completeness": comp,
            "complete": (comp["complete"] if comp else None),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "units": "milliseconds",
            "note": ("percentiles via numpy linear interpolation; medians carry an "
                     "Efron bootstrap 95% CI; latency is MALICIOUS-only"),
        },
        "stages": stages,
        "mttd_median_ci": list(metrics.bootstrap_ci_median(metrics.collect_interval(plan, "mttd"))),
        "mttr_median_ci": list(metrics.bootstrap_ci_median(metrics.collect_interval(plan, "mttr"))),
        "per_family": metrics.per_family_latency(plan),
        "damage": metrics.damage_stats(plan),
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    EFFICIENCY_REPORT.write_text(json.dumps(report, indent=2))
    return report


# --------------------------------------------------------------------------- #
# Sweep
# --------------------------------------------------------------------------- #

def run_efficiency_sweep(n_per_family: int = 30, *, lsm: bool = True, enforce: bool = True,
                         warmup_k: int = 3, response_timeout: float = 30.0) -> dict:
    if os.geteuid() != 0:
        raise PermissionError("efficiency sweep requires root (run_trial starts the agent).")

    completed = {t.get("sample_id") for t in read_trials(EFFICIENCY_RAW)}
    n_warmup_done = sum(1 for s in completed if str(s).startswith(WARMUP_PREFIX))
    n_errors = 0

    # ---- Warm-up (excluded from metrics) --------------------------------
    for entry in _warmup_entries(warmup_k):
        sid = entry["sample_id"]
        if sid in completed or n_warmup_done >= warmup_k:
            print(f"[warmup] skip {sid} (already done)")
            continue
        wl = malicious_samples.build_workload(entry)
        print(f"[warmup] {sid} (cache warm-up — EXCLUDED from metrics)")
        try:
            res = harness.run_trial(wl, lsm=lsm, enforce=enforce, response_timeout=response_timeout)
            append_trial_record(res, EFFICIENCY_RAW)
        except Exception as exc:
            print(f"[warmup] {sid} ERROR (ignored): {type(exc).__name__}: {exc}")
        n_warmup_done += 1

    # ---- Plan (malicious only) ------------------------------------------
    plan = malicious_samples.malicious_plan(n_per_family)
    total = len(plan)
    for i, entry in enumerate(plan, 1):
        sid = entry["sample_id"]
        if sid in completed:
            print(f"[eff {i}/{total}] skip {sid} (already recorded)")
            continue
        wl = malicious_samples.build_workload(entry)
        try:
            res = harness.run_trial(wl, lsm=lsm, enforce=enforce, response_timeout=response_timeout)
            append_trial_record(res, EFFICIENCY_RAW)
            iv = metrics.trial_intervals(res.to_dict())
            mttd = iv["mttd"]; mttr = iv["mttr"]; ftf = iv["files_touched_before_freeze"]
            print(f"[eff {i}/{total}] {sid:<22} mttd={_ms(mttd)} mttr={_ms(mttr)} "
                  f"files_before_freeze={ftf}")
        except Exception as exc:
            n_errors += 1
            _append_error_record(entry, exc)
            print(f"[eff {i}/{total}] {sid:<22} ERROR (recorded): {type(exc).__name__}: {exc}")

    # ---- Aggregate + completeness banner --------------------------------
    write_efficiency_reports(n_per_family=n_per_family)
    comp = metrics.completeness(
        [t for t in read_trials(EFFICIENCY_RAW)
         if not str(t.get("sample_id", "")).startswith(WARMUP_PREFIX)],
        _planned_malicious(n_per_family))
    print(f"\n[efficiency] sweep done → {EFFICIENCY_RAW}")
    print(f"[efficiency] COMPLETENESS: ran {comp['ran']}/{comp['planned']} planned, "
          f"missing={comp['missing']}, errored={comp['errored']}, complete={comp['complete']}")
    if not comp["complete"]:
        print("\n" + "!" * 72)
        print("WARNING: latency sweep is INCOMPLETE — percentiles are NOT over the full")
        print("planned N. Missing/errored per family:")
        for grp, g in sorted(comp["by_group"].items()):
            if g["missing"] or g["errored"]:
                print(f"   {grp:<14} ran {g['ran']}/{g['planned']}  "
                      f"missing={len(g['missing'])} errored={len(g['errored'])}")
        print("Re-run (resumable) to fill gaps, then --aggregate-only.")
        print("!" * 72)
    return comp


def _ms(v: "float | None") -> str:
    return "n/a" if v is None else f"{v:.2f}ms"


def main() -> int:
    ap = argparse.ArgumentParser(description="Efficiency latency sweep (root)")
    ap.add_argument("--n", type=int, default=30, dest="n_per_family",
                    help="malicious trials per family (3=smoke, 30=real)")
    ap.add_argument("--warmup", type=int, default=3, dest="warmup_k")
    ap.add_argument("--no-lsm", action="store_true")
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--aggregate-only", action="store_true",
                    help="skip running; just (re)write efficiency_report.json")
    args = ap.parse_args()

    if args.aggregate_only:
        rep = write_efficiency_reports(n_per_family=args.n_per_family)
        comp = rep["_meta"]["completeness"]
        print(f"[efficiency] aggregated → {EFFICIENCY_REPORT} | "
              f"complete={comp['complete'] if comp else 'n/a'}")
        return 0

    run_efficiency_sweep(n_per_family=args.n_per_family, lsm=not args.no_lsm,
                         enforce=not args.audit, warmup_k=args.warmup_k,
                         response_timeout=args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
