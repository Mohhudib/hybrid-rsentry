#!/usr/bin/env python3
"""
tests/evaluation/efficacy/test_metrics.py — unit tests for the efficacy metrics.
[NO ROOT] Synthetic trial lists with KNOWN TP/FP/TN/FN assert the math directly.
"""
from __future__ import annotations

import math
from typing import List

from tests.evaluation.efficacy import metrics


def _trial(sample_id: str, label: int, detected: bool,
           family_or_class: str = "akira", layer_fired=None) -> dict:
    return {"sample_id": sample_id, "label": label, "detected": detected,
            "family_or_class": family_or_class, "layer_fired": layer_fired}


def _known_set() -> List[dict]:
    """TP=3, FN=1, FP=1, TN=5 (N=10)."""
    t = []
    for i in range(3):
        t.append(_trial(f"mal_akira_{i:03d}", 1, True, "akira", "rename"))
    t.append(_trial("mal_akira_900", 1, False, "akira", None))           # FN
    t.append(_trial("ben_idle_000", 0, True, "idle", "write_offset"))     # FP
    for i in range(5):
        t.append(_trial(f"ben_idle_{i+1:03d}", 0, False, "idle", None))   # TN
    return t


def test_confusion_counts():
    c = metrics.confusion_counts(_known_set())
    assert c == {"TP": 3, "FP": 1, "TN": 5, "FN": 1}


def test_core_metrics_values():
    c = metrics.confusion_counts(_known_set())
    assert math.isclose(metrics.recall(c), 0.75)
    assert math.isclose(metrics.precision(c), 0.75)
    assert math.isclose(metrics.f1(c), 0.75)
    assert math.isclose(metrics.accuracy(c), 0.8)
    assert math.isclose(metrics.fpr(c), 1 / 6)
    assert math.isclose(metrics.fnr(c), 0.25)
    assert math.isclose(metrics.specificity(c), 5 / 6)
    # identities
    assert math.isclose(metrics.fnr(c), 1 - metrics.recall(c))
    assert math.isclose(metrics.specificity(c), 1 - metrics.fpr(c))


def test_warmup_trials_excluded():
    trials = _known_set()
    # A warm-up trial (label=1, detected) must NEVER be counted, even if present.
    trials.append(_trial("warmup_000", 1, True, "akira", "rename"))
    trials.append(_trial("warmup_001", 1, True, "akira", "rename"))
    c = metrics.confusion_counts(trials)
    assert c == {"TP": 3, "FP": 1, "TN": 5, "FN": 1}, "warmup leaked into counts"


def test_zero_denominator_is_nan():
    c = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for fn in (metrics.recall, metrics.precision, metrics.fpr,
               metrics.fnr, metrics.specificity, metrics.accuracy, metrics.f1):
        assert math.isnan(fn(c))


def test_wilson_ci_clean_sweep():
    # Rule-of-three regime: 30/30 → two-sided 95% lower bound ≈ 0.885 (§1.6).
    lo, hi = metrics.wilson_ci(30, 30)
    assert 0.88 < lo < 0.90, lo
    assert math.isclose(hi, 1.0)
    # n=0 → undefined
    assert all(math.isnan(v) for v in metrics.wilson_ci(0, 0))
    # symmetry around 0.5 for k=n/2
    lo2, hi2 = metrics.wilson_ci(5, 10)
    assert math.isclose((lo2 + hi2) / 2, 0.5, abs_tol=1e-9)


def test_metric_ci_maps_correct_proportion():
    c = metrics.confusion_counts(_known_set())
    # recall CI must be the Wilson interval for TP/(TP+FN) = 3/4
    assert metrics.metric_ci("recall", c) == metrics.wilson_ci(3, 4)
    # fpr CI must be FP/(FP+TN) = 1/6
    assert metrics.metric_ci("fpr", c) == metrics.wilson_ci(1, 6)
    try:
        metrics.metric_ci("f1", c)
        assert False, "f1 must not be a Wilson proportion"
    except ValueError:
        pass


def test_per_family_preserves_layer_distribution():
    trials = [
        _trial("mal_lockbit_000", 1, True, "lockbit", "rename"),
        _trial("mal_lockbit_001", 1, True, "lockbit", "rename"),
        _trial("mal_lockbit_002", 1, True, "lockbit", "write_offset"),
        _trial("mal_lockbit_003", 1, False, "lockbit", None),       # FN
        _trial("mal_entropy_only_000", 1, True, "entropy_only", "entropy"),
    ]
    fam = metrics.per_family_rates(trials)
    lk = fam["lockbit"]
    assert lk["n"] == 4 and lk["tp"] == 3
    assert math.isclose(lk["recall"], 0.75)
    # FULL distribution preserved (not collapsed to the mode)
    assert lk["layers"] == {"rename": 2, "write_offset": 1}
    assert lk["modal_layer"] == "rename"
    assert fam["entropy_only"]["modal_layer"] == "entropy"


def test_benign_fpr_headline_flag():
    trials = [
        _trial("ben_high_entropy_000", 0, True, "high_entropy", "write_offset"),  # FP
        _trial("ben_high_entropy_001", 0, False, "high_entropy", None),
        _trial("ben_bulk_ops_000", 0, False, "bulk_ops", None),
    ]
    ben = metrics.benign_fpr(trials)
    assert ben["high_entropy"]["headline"] is True
    assert ben["high_entropy"]["fp"] == 1 and ben["high_entropy"]["n"] == 2
    assert math.isclose(ben["high_entropy"]["fpr"], 0.5)
    assert ben["bulk_ops"]["headline"] is False


def test_completeness_flags_missing_and_errored():
    # planned: 3 akira + 2 qilin; recorded: all akira, only 1 qilin, + 1 errored.
    planned = {"mal_akira_000": "akira", "mal_akira_001": "akira", "mal_akira_002": "akira",
               "mal_qilin_000": "qilin", "mal_qilin_001": "qilin"}
    trials = [
        _trial("mal_akira_000", 1, True, "akira", "rename"),
        _trial("mal_akira_001", 1, True, "akira", "rename"),
        _trial("mal_akira_002", 1, True, "akira", "rename"),
        {**_trial("mal_qilin_000", 1, False, "qilin"), "error": "RuntimeError: boom"},  # errored
        # mal_qilin_001 never ran → missing
    ]
    comp = metrics.completeness(trials, planned)
    assert comp["planned"] == 5
    assert comp["ran"] == 4              # 3 akira + 1 errored qilin record
    assert comp["missing"] == 1          # mal_qilin_001
    assert comp["errored"] == 1
    assert comp["complete"] is False
    assert comp["by_group"]["akira"] == {"planned": 3, "ran": 3, "missing": [], "errored": []}
    assert comp["by_group"]["qilin"]["missing"] == ["mal_qilin_001"]
    assert comp["by_group"]["qilin"]["errored"] == ["mal_qilin_000"]


def test_completeness_complete_when_all_ran():
    planned = {"mal_akira_000": "akira", "ben_idle_000": "idle"}
    trials = [_trial("mal_akira_000", 1, True, "akira", "rename"),
              _trial("ben_idle_000", 0, False, "idle")]
    comp = metrics.completeness(trials, planned)
    assert comp["complete"] is True and comp["missing"] == 0 and comp["errored"] == 0


def test_errored_malicious_counts_as_FN_not_dropped():
    # An errored malicious trial (detected=False) must enter the denominator as FN,
    # never silently vanish — recall reflects the failure.
    trials = [
        _trial("mal_akira_000", 1, True, "akira", "rename"),
        {**_trial("mal_akira_001", 1, False, "akira"), "error": "Timeout"},
    ]
    c = metrics.confusion_counts(trials)
    assert c == {"TP": 1, "FP": 0, "TN": 0, "FN": 1}
    assert math.isclose(metrics.recall(c), 0.5)


def test_bootstrap_f1_deterministic_and_bounded():
    trials = _known_set()
    lo1, hi1 = metrics.bootstrap_f1_ci(trials, resamples=2000, seed=42)
    lo2, hi2 = metrics.bootstrap_f1_ci(trials, resamples=2000, seed=42)
    assert (lo1, hi1) == (lo2, hi2)             # deterministic given seed
    assert 0.0 <= lo1 <= hi1 <= 1.0
    # the bootstrap interval should sit in a sensible region around F1≈0.75
    assert lo1 < 0.75 < hi1 + 1e-9 or math.isclose(hi1, 0.75, abs_tol=0.3)
