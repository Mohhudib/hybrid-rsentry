#!/usr/bin/env python3
"""
tests/evaluation/efficiency/test_metrics.py — unit tests for efficiency metrics.
[NO ROOT]

The methodological core of this axis is the tail-risk demonstration: percentiles
reveal a slow tail that the mean hides. We pin the EXACT numpy linear-interp
values (method='linear', interpolating at rank (n-1)*p/100) so an interpolation
regression (linear vs lower vs nearest) is caught, not hidden behind loose '>'.
"""
from __future__ import annotations

import math
from typing import List

from tests.evaluation.efficiency import metrics

TOL = 1e-9


def _close(a: float, b: float) -> bool:
    return math.isclose(a, b, abs_tol=TOL)


def test_tail_TEST_A_single_outlier_hidden_below_p99():
    # TEST A — ONE slow trial in 30: [2.0]*29 + [50.0]
    # numpy linear interp, n=30, rank=(n-1)*p/100:
    #   p50: rank 14.5 -> 2.0
    #   p95: rank 27.55 -> still inside the 2.0 mass -> 2.0  (outlier NOT seen)
    #   p99: rank 28.71 -> 0.71 of the way into index 29 (50.0):
    #        2.0 + 0.71*(50-2) = 36.08            (outlier PARTIALLY surfaces)
    #   max: 50.0                                   (only here is it fully seen)
    # LESSON: a lone outlier in 30 is invisible at p50 AND p95; it shows at p99
    # (via interpolation) and at max. mean=3.6 is dragged up yet still hides the
    # 50ms worst case. => report max alongside percentiles; one bad trial in 30
    # needs p99/max to be seen at all.
    vals = [2.0] * 29 + [50.0]
    p = metrics.percentiles(vals)
    assert _close(p[50], 2.0), p[50]
    assert _close(p[95], 2.0), p[95]
    assert _close(p[99], 36.08), p[99]
    s = metrics.summary_stats(vals)
    assert _close(s["mean"], 3.6), s["mean"]          # (29*2 + 50)/30
    assert _close(s["max"], 50.0)
    assert s["n"] == 30
    # the point: mean (3.6) << max (50.0), and p95 doesn't reveal the tail at all
    assert s["mean"] < 4.0 < s["max"]


def test_tail_TEST_B_tail_mass_surfaces_at_p95():
    # TEST B — TWO slow trials in 30 (top ~6.7%): [2.0]*28 + [50.0]*2
    # numpy linear interp:
    #   p50: 2.0
    #   p95: rank 27.55 -> 0.55 into index 28 (50.0): 2.0 + 0.55*48 = 28.4
    #   p99: rank 28.71 -> between index 28 and 29 (both 50.0) -> 50.0
    # mean = (28*2 + 2*50)/30 = 5.2  -> still understates the 50ms tail.
    # HEADLINE: with enough tail mass (>=5%), p95 reveals what the mean hides.
    vals = [2.0] * 28 + [50.0] * 2
    p = metrics.percentiles(vals)
    assert _close(p[50], 2.0), p[50]
    assert _close(p[95], 28.4), p[95]
    assert _close(p[99], 50.0), p[99]
    s = metrics.summary_stats(vals)
    assert _close(s["mean"], 5.2), s["mean"]
    assert s["mean"] < s["p95"] < s["max"]            # mean hides, p95 reveals


def test_uniform_baseline_p99_equals_mean():
    # No skew: every percentile == the value, and p99 == mean.
    vals = [7.0] * 30
    p = metrics.percentiles(vals)
    s = metrics.summary_stats(vals)
    assert _close(p[50], 7.0) and _close(p[95], 7.0) and _close(p[99], 7.0)
    assert _close(s["mean"], 7.0) and _close(s["p99"], s["mean"])
    assert _close(s["std"], 0.0)


def test_empty_is_nan():
    p = metrics.percentiles([])
    assert all(math.isnan(v) for v in p.values())
    s = metrics.summary_stats([])
    assert s["n"] == 0 and math.isnan(s["mean"]) and math.isnan(s["p95"])


# --------------------------------------------------------------------------- #
# Interval extraction + per-family grouping
# --------------------------------------------------------------------------- #

def _mktrial(sid: str, fam: str, mttd_ms: float, mttr_ms: float,
             files: int, label: int = 1) -> dict:
    """Build a trial whose ns timestamps yield the given MTTD/MTTR (ms)."""
    t0 = 1_000_000_000                       # arbitrary monotonic ns origin
    t_detect = t0 + int(mttd_ms * 1e6)
    t_complete = t_detect + int(mttr_ms * 1e6)
    t_sigstop = t_detect + int(0.4 * mttr_ms * 1e6)
    t_isolate = t_detect + int(0.7 * mttr_ms * 1e6)
    t_kill = t_detect + int(0.9 * mttr_ms * 1e6)
    return {"sample_id": sid, "label": label, "family_or_class": fam,
            "detected": True, "contained": True, "layer_fired": "rename",
            "t0": t0, "t_detect": t_detect, "t_sigstop": t_sigstop,
            "t_isolate": t_isolate, "t_kill": t_kill, "t_complete": t_complete,
            "files_touched_before_freeze": files}


def test_trial_intervals_and_guards():
    t = _mktrial("mal_akira_000", "akira", mttd_ms=5.0, mttr_ms=20.0, files=3)
    iv = metrics.trial_intervals(t)
    assert _close(iv["mttd"], 5.0)
    assert _close(iv["mttr"], 20.0)
    assert _close(iv["total_response"], 25.0)         # MTTD + MTTR
    # sub-stages sum to MTTR
    assert _close(iv["detect_freeze"] + iv["freeze_isolate"]
                  + iv["isolate_kill"] + iv["kill_complete"], 20.0)
    assert iv["files_touched_before_freeze"] == 3
    # None / negative guards: missing endpoint -> None, never 0
    t2 = dict(t, t_complete=None)
    iv2 = metrics.trial_intervals(t2)
    assert iv2["mttr"] is None and iv2["total_response"] is None
    assert iv2["mttd"] == iv["mttd"]                  # MTTD still computable
    t3 = dict(t, t_detect=t["t0"] - 1)                # negative -> None
    assert metrics.trial_intervals(t3)["mttd"] is None


def test_per_family_grouping_and_warmup_exclusion():
    trials = [
        _mktrial("mal_akira_000", "akira", 4.0, 18.0, 2),
        _mktrial("mal_akira_001", "akira", 6.0, 22.0, 3),
        _mktrial("mal_lockbit_000", "lockbit", 3.0, 15.0, 1),
        _mktrial("warmup_000", "akira", 99.0, 99.0, 9),     # MUST be excluded
        {**_mktrial("mal_akira_002", "akira", 0, 0, 0), "label": 0},  # benign -> excluded
    ]
    fam = metrics.per_family_latency(trials)
    assert set(fam) == {"akira", "lockbit"}
    assert fam["akira"]["n"] == 2                      # warmup + benign excluded
    assert _close(fam["akira"]["mttd"]["p50"], 5.0)    # median of [4,6]
    assert _close(fam["lockbit"]["mttr"]["p50"], 15.0)
    # collect_interval also excludes warmup/benign
    assert sorted(metrics.collect_interval(trials, "mttd")) == [3.0, 4.0, 6.0]


def test_damage_stats_per_family():
    trials = [
        _mktrial("mal_akira_000", "akira", 4.0, 18.0, 2),
        _mktrial("mal_akira_001", "akira", 6.0, 22.0, 8),
    ]
    dmg = metrics.damage_stats(trials)
    assert dmg["akira"]["n"] == 2
    assert _close(dmg["akira"]["max"], 8.0)
    assert _close(dmg["akira"]["p50"], 5.0)            # median of [2,8]


def test_bootstrap_ci_median_deterministic():
    vals = [2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 50.0]
    lo1, hi1 = metrics.bootstrap_ci_median(vals, resamples=2000, seed=7)
    lo2, hi2 = metrics.bootstrap_ci_median(vals, resamples=2000, seed=7)
    assert (lo1, hi1) == (lo2, hi2)                    # deterministic given seed
    assert lo1 <= hi1
    # CI should bracket the sample median (robust central tendency)
    import statistics
    assert lo1 <= statistics.median(vals) <= hi1
    # NOTE: a *different* seed need NOT give a different CI — the bootstrap
    # distribution of the median is discrete, so the 2.5/97.5 bounds often land
    # on the same order statistics. Determinism-given-seed is the contract.
    assert math.isnan(metrics.bootstrap_ci_median([])[0])
