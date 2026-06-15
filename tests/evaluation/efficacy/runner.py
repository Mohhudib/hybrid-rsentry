#!/usr/bin/env python3
"""
tests/evaluation/efficacy/runner.py — orchestrate a full Efficacy sweep. [ROOT]

Runs the labeled trial plan (malicious_plan + benign_plan) one trial at a time,
each against a FRESH agent (§1.4), appends every TrialResult to
results/trials_raw.json as it goes (crash-safe + resumable), then aggregates the
confusion matrix and the per-family / per-benign-class breakdowns.

Warm-up policy (§1.4, Option A): ``warmup_k`` dedicated throwaway trials run
FIRST using the akira workload — same agent code path, so they warm the SAME
machine-level caches the real trials hit (dpkg-hash page cache, BPF JIT). They
are recorded with ``warmup_*`` sample_ids for audit but EXCLUDED from every
metric (filtered defensively in metrics.py). The exclusion count is recorded in
results/confusion_matrix.json ``_meta.warmup_excluded`` so the policy is
auditable from the output alone.

Resumability keys on ``sample_id``: any sample_id already present in
trials_raw.json is skipped. ``warmup_*`` ids never collide with plan ids
(``mal_*`` / ``ben_*``).

Usage (root):
    sudo -E ~/hybrid-rsentry/venv/bin/python -m tests.evaluation.efficacy.runner --n 3
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.evaluation import harness
from tests.evaluation.conftest import (
    RESULTS_DIR, TRIALS_RAW, append_trial_record, read_trials,
)
from tests.evaluation.corpus import benign_workloads, malicious_samples
from tests.evaluation.efficacy import metrics

WARMUP_PREFIX = metrics.WARMUP_PREFIX


# --------------------------------------------------------------------------- #
# Plan assembly
# --------------------------------------------------------------------------- #

def _build_plan(n_per_group: int) -> List[Tuple[dict, str]]:
    """Return [(entry, kind)] where kind ∈ {'malicious','benign'}, in run order."""
    plan: List[Tuple[dict, str]] = []
    for entry in malicious_samples.malicious_plan(n_per_group):
        plan.append((entry, "malicious"))
    for entry in benign_workloads.benign_plan(n_per_group):
        plan.append((entry, "benign"))
    return plan


def _build_workload(entry: dict, kind: str):
    return (malicious_samples.build_workload(entry) if kind == "malicious"
            else benign_workloads.build_workload(entry))


def _planned_manifest(n_per_group: int) -> Dict[str, str]:
    """{sample_id: group_name} for every trial the sweep is SUPPOSED to run —
    the ground truth the aggregation reconciles against (no silent drops)."""
    planned: Dict[str, str] = {}
    for entry in malicious_samples.malicious_plan(n_per_group):
        planned[entry["sample_id"]] = entry["family"]
    for entry in benign_workloads.benign_plan(n_per_group):
        planned[entry["sample_id"]] = entry["benign_class"]
    return planned


def _append_error_record(entry: dict, kind: str, exc: BaseException) -> None:
    """Record a FAILED trial so a crash/error is a visible data point, never a
    silent gap. detected=False (conservative) + an ``error`` marker that the
    completeness reconciliation surfaces."""
    rec = {
        "sample_id": entry["sample_id"],
        "label": 1 if kind == "malicious" else 0,
        "family_or_class": entry.get("family") or entry.get("benign_class"),
        "detected": False, "contained": False, "layer_fired": None,
        "t0": None, "t_detect": None, "t_decide": None, "t_sigstop": None,
        "t_isolate": None, "t_kill": None, "t_complete": None,
        "canary_survived": None, "files_touched_before_freeze": None,
        "agent_restart_id": "", "host_loadavg": 0.0,
        "raw_log_excerpt": "", "error": f"{type(exc).__name__}: {exc}",
    }
    with open(TRIALS_RAW, "a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


def _warmup_entries(warmup_k: int) -> List[dict]:
    """Throwaway akira entries with non-colliding warmup_* sample_ids."""
    base = malicious_samples.malicious_plan(1)[0]            # an akira entry
    out: List[dict] = []
    for i in range(warmup_k):
        e = dict(base)
        e["sample_id"] = f"{WARMUP_PREFIX}{i:03d}"
        out.append(e)
    return out


# --------------------------------------------------------------------------- #
# Aggregation → JSON (pure; callable without root to re-aggregate)
# --------------------------------------------------------------------------- #

def write_efficacy_reports(results_dir: Path = RESULTS_DIR,
                           n_per_group: "int | None" = None) -> Dict[str, int]:
    """Read trials_raw.json and write the three §1 JSON outputs. Returns the
    confusion counts.

    If ``n_per_group`` is given, reconcile the recorded trials against the PLANNED
    manifest and embed completeness in confusion_matrix.json ``_meta`` so a
    partial/incomplete run can never be mistaken for a full-N result.
    """
    trials = read_trials()
    warmup_excluded = sum(1 for t in trials if str(t.get("sample_id", "")).startswith(WARMUP_PREFIX))
    plan = [t for t in trials if not str(t.get("sample_id", "")).startswith(WARMUP_PREFIX)]

    comp = None
    if n_per_group is not None:
        comp = metrics.completeness(plan, _planned_manifest(n_per_group))

    c = metrics.confusion_counts(plan)
    f1_lo, f1_hi = metrics.bootstrap_f1_ci(plan)
    core = {
        "recall":      {"value": metrics.recall(c),      "ci": list(metrics.metric_ci("recall", c))},
        "precision":   {"value": metrics.precision(c),   "ci": list(metrics.metric_ci("precision", c))},
        "f1":          {"value": metrics.f1(c),          "ci": [f1_lo, f1_hi], "ci_method": "bootstrap"},
        "accuracy":    {"value": metrics.accuracy(c),    "ci": list(metrics.metric_ci("accuracy", c))},
        "fpr":         {"value": metrics.fpr(c),         "ci": list(metrics.metric_ci("fpr", c))},
        "fnr":         {"value": metrics.fnr(c),         "ci": list(metrics.metric_ci("fnr", c))},
        "specificity": {"value": metrics.specificity(c), "ci": list(metrics.metric_ci("specificity", c))},
    }
    confusion = {
        "_meta": {
            "warmup_excluded": warmup_excluded,
            "n_total": sum(c.values()),
            "n_malicious": c["TP"] + c["FN"],
            "n_benign": c["FP"] + c["TN"],
            "n_per_group": n_per_group,
            "completeness": comp,
            "complete": (comp["complete"] if comp else None),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ci_note": "proportions: Wilson 1927 95%; f1: Efron 1979 bootstrap 95%",
            "denominator_note": (
                "metrics computed over RECORDED trials; see completeness for "
                "planned-vs-ran reconciliation — recall/precision are NOT over the "
                "full planned N unless complete=true"),
        },
        **c,
        "metrics": core,
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "confusion_matrix.json").write_text(json.dumps(confusion, indent=2))
    (results_dir / "per_family_detection.json").write_text(
        json.dumps(metrics.per_family_rates(plan), indent=2))
    (results_dir / "benign_fpr_breakdown.json").write_text(
        json.dumps(metrics.benign_fpr(plan), indent=2))
    return c


# --------------------------------------------------------------------------- #
# Sweep
# --------------------------------------------------------------------------- #

def run_efficacy_sweep(n_per_group: int = 3, *, lsm: bool = True, enforce: bool = True,
                       warmup_k: int = 3, response_timeout: float = 30.0) -> Dict[str, int]:
    """Run warm-up + the full labeled plan, appending each result, then aggregate."""
    if os.geteuid() != 0:
        raise PermissionError("efficacy sweep requires root (run_trial starts the agent).")

    completed = {t.get("sample_id") for t in read_trials()}
    n_warmup_done = sum(1 for s in completed if str(s).startswith(WARMUP_PREFIX))

    n_errors = 0

    # ---- Warm-up phase --------------------------------------------------
    for entry in _warmup_entries(warmup_k):
        sid = entry["sample_id"]
        if sid in completed or n_warmup_done >= warmup_k:
            print(f"[warmup] skip {sid} (already done)")
            continue
        wl = _build_workload(entry, "malicious")
        print(f"[warmup] {sid} (cache warm-up — EXCLUDED from metrics)")
        try:
            res = harness.run_trial(wl, lsm=lsm, enforce=enforce, response_timeout=response_timeout)
            append_trial_record(res)
        except Exception as exc:                       # warm-up failure is non-fatal
            print(f"[warmup] {sid} ERROR (ignored): {type(exc).__name__}: {exc}")
        n_warmup_done += 1

    # ---- Plan phase -----------------------------------------------------
    plan = _build_plan(n_per_group)
    total = len(plan)
    for i, (entry, kind) in enumerate(plan, 1):
        sid = entry["sample_id"]
        if sid in completed:
            print(f"[sweep {i}/{total}] skip {sid} (already in trials_raw.json)")
            continue
        wl = _build_workload(entry, kind)
        # A single trial failing (sim crash, agent timeout, harness error) must
        # NOT abort the sweep AND must NOT silently vanish — record it as an
        # errored trial so completeness reconciliation sees it.
        try:
            res = harness.run_trial(wl, lsm=lsm, enforce=enforce, response_timeout=response_timeout)
            append_trial_record(res)
            d = res.to_dict()
            cell = metrics.confusion_cell(d)
            print(f"[sweep {i}/{total}] {sid:<22} label={d['label']} "
                  f"detected={str(d['detected']):<5} layer={d['layer_fired']} cell={cell}")
        except Exception as exc:
            n_errors += 1
            _append_error_record(entry, kind, exc)
            print(f"[sweep {i}/{total}] {sid:<22} ERROR (recorded): "
                  f"{type(exc).__name__}: {exc}")

    # ---- Aggregate ------------------------------------------------------
    c = write_efficacy_reports(n_per_group=n_per_group)
    comp = metrics.completeness(
        [t for t in read_trials() if not str(t.get("sample_id", "")).startswith(WARMUP_PREFIX)],
        _planned_manifest(n_per_group))
    print(f"\n[efficacy] sweep done → {TRIALS_RAW}")
    print(f"[efficacy] confusion: TP={c['TP']} FP={c['FP']} TN={c['TN']} FN={c['FN']}")
    print(f"[efficacy] recall={metrics.recall(c):.3f}  fpr={metrics.fpr(c):.3f}")
    print(f"[efficacy] COMPLETENESS: ran {comp['ran']}/{comp['planned']} planned, "
          f"missing={comp['missing']}, errored={comp['errored']}, "
          f"complete={comp['complete']}")
    if not comp["complete"]:
        print("\n" + "!" * 72)
        print("WARNING: sweep is INCOMPLETE — recall/precision are NOT over the full")
        print("planned N. Missing/errored per group:")
        for grp, g in sorted(comp["by_group"].items()):
            if g["missing"] or g["errored"]:
                print(f"   {grp:<14} ran {g['ran']}/{g['planned']}  "
                      f"missing={len(g['missing'])} errored={len(g['errored'])}")
        print("Re-run to fill gaps (resumable), then re-aggregate with --aggregate-only.")
        print("!" * 72)
    return c


def main() -> int:
    ap = argparse.ArgumentParser(description="Efficacy axis sweep (root)")
    ap.add_argument("--n", type=int, default=3, dest="n_per_group",
                    help="trials per family AND per benign class (3=smoke, 30=real)")
    ap.add_argument("--warmup", type=int, default=3, dest="warmup_k",
                    help="dedicated cache warm-up trials (excluded from metrics)")
    ap.add_argument("--no-lsm", action="store_true", help="run agent with --no-lsm")
    ap.add_argument("--audit", action="store_true", help="audit mode (no enforce)")
    ap.add_argument("--timeout", type=float, default=30.0, help="per-trial response timeout (s)")
    ap.add_argument("--aggregate-only", action="store_true",
                    help="skip running; just (re)write the JSON reports from trials_raw.json")
    args = ap.parse_args()

    if args.aggregate_only:
        c = write_efficacy_reports(n_per_group=args.n_per_group)
        comp = metrics.completeness(
            [t for t in read_trials() if not str(t.get("sample_id", "")).startswith(WARMUP_PREFIX)],
            _planned_manifest(args.n_per_group))
        print(f"[efficacy] aggregated → {RESULTS_DIR} | "
              f"TP={c['TP']} FP={c['FP']} TN={c['TN']} FN={c['FN']} | "
              f"ran {comp['ran']}/{comp['planned']} complete={comp['complete']}")
        return 0

    run_efficacy_sweep(n_per_group=args.n_per_group, lsm=not args.no_lsm,
                       enforce=not args.audit, warmup_k=args.warmup_k,
                       response_timeout=args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
