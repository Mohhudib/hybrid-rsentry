#!/usr/bin/env python3
"""
tests/evaluation/efficiency/metrics.py — Efficiency axis metrics. [NO ROOT]

Pure functions over the malicious TrialResult dicts. All latencies are in
MILLISECONDS. Implements docs/evaluation-design.md §2: the NIST-lifecycle
intervals (MTTD/MTTR), per-stage breakdown, and percentile-led summaries.

PERCENTILES, NOT MEANS, ARE THE HEADLINE. Detection/containment latency is
right-skewed and the TAIL is the operational risk (Dean & Barroso, "The Tail at
Scale"; Google SRE). The mean is dragged by — yet can still hide — a slow worst
case; p95/p99 surface it. We also report ``max`` alongside, because with small n
a single pathological trial only reaches the very top percentiles (a lone outlier
in 30 is invisible at p95 and shows only at p99/max).

Warm-up exclusion, plan filtering, and completeness reconciliation are REUSED
from the efficacy axis (not reinvented).
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import numpy as np

from tests.evaluation.efficacy.metrics import (  # reuse — do not reinvent
    WARMUP_PREFIX, _plan_trials, completeness,
)

# Stage ladder (design §2). MTTD/MTTR/total are the lifecycle metrics; the four
# middle stages decompose MTTR and sum to it.
STAGE_NAMES = ["mttd", "detect_freeze", "freeze_isolate", "isolate_kill",
               "kill_complete", "mttr", "total_response"]
NAN = float("nan")


# --------------------------------------------------------------------------- #
# Interval extraction (ns timestamps → ms), with the None / >=0 guards (§ design)
# --------------------------------------------------------------------------- #

def _ms(earlier: Optional[float], later: Optional[float]) -> Optional[float]:
    """(later - earlier) in ms, or None if either endpoint is missing or the
    delta is negative. A partial/!contained pipeline yields None for the stages
    it never reached — never a fabricated 0."""
    if earlier is None or later is None:
        return None
    delta_ms = (later - earlier) / 1e6
    return delta_ms if delta_ms >= 0 else None


def trial_intervals(trial: dict) -> Dict[str, Optional[float]]:
    """All §2 intervals (ms) for one trial, plus the damage measure. Missing/
    negative intervals are None."""
    g = trial.get
    t0, td, ts = g("t0"), g("t_detect"), g("t_sigstop")
    ti, tk, tc = g("t_isolate"), g("t_kill"), g("t_complete")
    return {
        "mttd":           _ms(t0, td),     # attack onset → detection
        "detect_freeze":  _ms(td, ts),     # detection → SIGSTOP
        "freeze_isolate": _ms(ts, ti),     # SIGSTOP → cgroup isolation
        "isolate_kill":   _ms(ti, tk),     # isolation → SIGKILL
        "kill_complete":  _ms(tk, tc),     # SIGKILL → CONTAINMENT COMPLETE
        "mttr":           _ms(td, tc),     # detection → full containment
        "total_response": _ms(t0, tc),     # onset → contained (= MTTD + MTTR)
        "files_touched_before_freeze": trial.get("files_touched_before_freeze"),
    }


def _malicious(trials: List[dict]) -> List[dict]:
    """Plan trials (warm-up excluded) that are malicious — latency is
    malicious-only (benign trials have no detection timing)."""
    return [t for t in _plan_trials(trials) if t.get("label") == 1]


def collect_interval(trials: List[dict], name: str) -> List[float]:
    """Every non-None value of one interval across malicious plan trials."""
    out: List[float] = []
    for t in _malicious(trials):
        v = trial_intervals(t).get(name)
        if v is not None:
            out.append(float(v))
    return out


# --------------------------------------------------------------------------- #
# Percentiles + summary
# --------------------------------------------------------------------------- #

def _np_percentile(values: List[float], p: float) -> float:
    """numpy.percentile with LINEAR interpolation (the default 'linear' method:
    interpolate between the two nearest ranks at position (n-1)*p/100). Pinned so
    results are reproducible and an interpolation-method regression is catchable."""
    try:
        return float(np.percentile(values, p, method="linear"))
    except TypeError:                       # numpy < 1.22 spelling
        return float(np.percentile(values, p, interpolation="linear"))


def percentiles(values: List[float], ps: Tuple[int, ...] = (50, 95, 99)) -> Dict[int, float]:
    """{p: value} for each requested percentile via linear interpolation. Empty
    input → NaN for every p. Percentiles are the headline metric (§2)."""
    if not values:
        return {p: NAN for p in ps}
    return {p: _np_percentile(values, p) for p in ps}


def summary_stats(values: List[float]) -> Dict[str, float]:
    """{n, mean, std, min, p50, p95, p99, max}. n first; percentiles lead;
    mean/std are SECONDARY (so 'mean < p95 under skew' is visible). std is the
    population std (numpy ddof=0). Empty → n=0, the rest NaN."""
    if not values:
        return {"n": 0, "mean": NAN, "std": NAN, "min": NAN,
                "p50": NAN, "p95": NAN, "p99": NAN, "max": NAN}
    arr = np.asarray(values, dtype=float)
    pct = percentiles(values, (50, 95, 99))
    return {
        "n": int(arr.size),
        "mean": float(arr.mean()),
        "std": float(arr.std()),               # population std (ddof=0)
        "min": float(arr.min()),
        "p50": pct[50], "p95": pct[95], "p99": pct[99],
        "max": float(arr.max()),
    }


def bootstrap_ci_median(values: List[float], resamples: int = 10000,
                        alpha: float = 0.05, seed: int = 0) -> Tuple[float, float]:
    """Efron (1979) percentile bootstrap CI on the MEDIAN. Deterministic given
    ``seed`` (numpy default_rng). Empty → (NaN, NaN)."""
    vals = [v for v in values if v is not None]
    if not vals:
        return (NAN, NAN)
    rng = np.random.default_rng(seed)
    arr = np.asarray(vals, dtype=float)
    medians = np.median(rng.choice(arr, size=(resamples, arr.size), replace=True), axis=1)
    lo = float(np.percentile(medians, 100 * alpha / 2))
    hi = float(np.percentile(medians, 100 * (1 - alpha / 2)))
    return (lo, hi)


# --------------------------------------------------------------------------- #
# Per-group breakdowns
# --------------------------------------------------------------------------- #

def per_family_latency(trials: List[dict]) -> Dict[str, dict]:
    """{family: {'n', 'mttd': summary_stats, 'mttr': summary_stats}} over each
    family's malicious plan trials."""
    by_family: Dict[str, List[dict]] = defaultdict(list)
    for t in _malicious(trials):
        by_family[t.get("family_or_class", "?")].append(t)
    out: Dict[str, dict] = {}
    for fam, ts in sorted(by_family.items()):
        mttd = [v for v in (trial_intervals(t)["mttd"] for t in ts) if v is not None]
        mttr = [v for v in (trial_intervals(t)["mttr"] for t in ts) if v is not None]
        out[fam] = {"n": len(ts), "mttd": summary_stats(mttd), "mttr": summary_stats(mttr)}
    return out


def damage_stats(trials: List[dict]) -> Dict[str, dict]:
    """{family: {n, p50, p95, max, mean}} of files_touched_before_freeze — the
    construct-valid harm measure (§2.6). Counts the malicious file ops that
    landed before SIGSTOP froze the process."""
    by_family: Dict[str, List[float]] = defaultdict(list)
    for t in _malicious(trials):
        v = t.get("files_touched_before_freeze")
        if v is not None:
            by_family[t.get("family_or_class", "?")].append(float(v))
    out: Dict[str, dict] = {}
    for fam, vals in sorted(by_family.items()):
        pct = percentiles(vals, (50, 95))
        out[fam] = {"n": len(vals), "p50": pct[50], "p95": pct[95],
                    "max": (max(vals) if vals else NAN),
                    "mean": (sum(vals) / len(vals) if vals else NAN)}
    return out
