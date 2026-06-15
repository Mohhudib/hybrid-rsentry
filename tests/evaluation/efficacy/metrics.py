#!/usr/bin/env python3
"""
tests/evaluation/efficacy/metrics.py — Efficacy axis metrics. [NO ROOT]

Pure, fully unit-testable functions over a list of TrialResult dicts (as written
to results/trials_raw.json). Implements docs/evaluation-design.md §1.2/§1.5:
confusion matrix from the Detection outcome, the seven core classification
metrics, Wilson score intervals for every proportion (Wilson 1927), and an Efron
percentile bootstrap CI for F1 (Efron 1979).

A trial dict carries at least: ``sample_id``, ``label`` (1=malicious, 0=benign),
``detected`` (bool, the Detection outcome D, §0.2), ``family_or_class``, and
``layer_fired``. ``warmup_*`` trials are EXCLUDED here defensively, so they can
never be counted even if present in trials_raw.json.
"""
from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from statistics import NormalDist
from typing import Dict, List, Tuple

WARMUP_PREFIX = "warmup_"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _is_warmup(trial: dict) -> bool:
    return str(trial.get("sample_id", "")).startswith(WARMUP_PREFIX)


def _plan_trials(trials: List[dict]) -> List[dict]:
    """Drop warm-up trials — they are never counted toward any metric (§1.4)."""
    return [t for t in trials if not _is_warmup(t)]


def _safe_div(num: float, den: float) -> float:
    """num/den, or NaN for the 0/0 (undefined) case so the report renders 'n/a'."""
    return num / den if den else float("nan")


def confusion_cell(trial: dict) -> str:
    """Assign one confusion cell from label + Detection outcome (design §1.2)."""
    malicious = trial.get("label") == 1
    detected = bool(trial.get("detected"))
    if malicious and detected:
        return "TP"            # ransomware correctly detected
    if malicious and not detected:
        return "FN"            # ransomware missed
    if (not malicious) and detected:
        return "FP"            # benign wrongly contained
    return "TN"                # benign correctly ignored


# --------------------------------------------------------------------------- #
# Confusion matrix + core metrics
# --------------------------------------------------------------------------- #

def confusion_counts(trials: List[dict]) -> Dict[str, int]:
    """Return {'TP','FP','TN','FN'} over the plan trials (warm-up excluded)."""
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for t in _plan_trials(trials):
        counts[confusion_cell(t)] += 1
    return counts


def recall(c: Dict[str, int]) -> float:
    """TP / (TP + FN) — sensitivity / TPR."""
    return _safe_div(c["TP"], c["TP"] + c["FN"])


def precision(c: Dict[str, int]) -> float:
    """TP / (TP + FP) — PPV."""
    return _safe_div(c["TP"], c["TP"] + c["FP"])


def f1(c: Dict[str, int]) -> float:
    """2·P·R / (P + R) — harmonic mean of precision and recall."""
    p, r = precision(c), recall(c)
    if math.isnan(p) or math.isnan(r) or (p + r) == 0:
        return float("nan")
    return 2 * p * r / (p + r)


def accuracy(c: Dict[str, int]) -> float:
    """(TP + TN) / N."""
    return _safe_div(c["TP"] + c["TN"], sum(c.values()))


def fpr(c: Dict[str, int]) -> float:
    """FP / (FP + TN) — false positive rate."""
    return _safe_div(c["FP"], c["FP"] + c["TN"])


def fnr(c: Dict[str, int]) -> float:
    """FN / (FN + TP) = 1 - recall."""
    return _safe_div(c["FN"], c["FN"] + c["TP"])


def specificity(c: Dict[str, int]) -> float:
    """TN / (TN + FP) = 1 - FPR."""
    return _safe_div(c["TN"], c["TN"] + c["FP"])


# --------------------------------------------------------------------------- #
# Confidence intervals
# --------------------------------------------------------------------------- #

def wilson_ci(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Wilson (1927) score interval for a binomial proportion k/n.

    Correct near p=0/1 and for small n — the regime the design lives in (§1.6).
    Returns (lo, hi) clamped to [0,1]; (NaN, NaN) for n==0.
    """
    if n <= 0:
        return (float("nan"), float("nan"))
    z = NormalDist().inv_cdf(1 - alpha / 2)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return (max(0.0, center - margin), min(1.0, center + margin))


# Which binomial (k, n) backs each core metric's Wilson CI.
_CI_MAP = {
    "recall":      lambda c: (c["TP"], c["TP"] + c["FN"]),
    "precision":   lambda c: (c["TP"], c["TP"] + c["FP"]),
    "fpr":         lambda c: (c["FP"], c["FP"] + c["TN"]),
    "specificity": lambda c: (c["TN"], c["TN"] + c["FP"]),
    "fnr":         lambda c: (c["FN"], c["FN"] + c["TP"]),
    "accuracy":    lambda c: (c["TP"] + c["TN"], sum(c.values())),
}


def metric_ci(name: str, c: Dict[str, int], alpha: float = 0.05) -> Tuple[float, float]:
    """Wilson CI for a proportion metric. (F1 is not a proportion — use
    bootstrap_f1_ci.)"""
    if name == "f1":
        raise ValueError("F1 is not a binomial proportion; use bootstrap_f1_ci()")
    if name not in _CI_MAP:
        raise KeyError(f"unknown metric {name!r}")
    k, n = _CI_MAP[name](c)
    return wilson_ci(k, n, alpha)


def bootstrap_f1_ci(trials: List[dict], resamples: int = 10000,
                    alpha: float = 0.05, seed: int = 0) -> Tuple[float, float]:
    """Efron (1979) percentile bootstrap CI for F1 over the plan trials.

    Resamples trials with replacement, recomputes F1 each time, returns the
    [alpha/2, 1-alpha/2] percentiles. A degenerate resample (no detections) has
    undefined F1 and contributes 0.0. Deterministic given ``seed``.
    """
    data = _plan_trials(trials)
    n = len(data)
    if n == 0:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    vals: List[float] = []
    for _ in range(resamples):
        sample = [data[rng.randrange(n)] for _ in range(n)]
        fv = f1(confusion_counts(sample))
        vals.append(0.0 if math.isnan(fv) else fv)
    vals.sort()
    lo = vals[int((alpha / 2) * resamples)]
    hi = vals[min(resamples - 1, int((1 - alpha / 2) * resamples))]
    return (lo, hi)


# --------------------------------------------------------------------------- #
# Per-group breakdowns (mandatory, not just pooled — §1.2)
# --------------------------------------------------------------------------- #

def per_family_rates(trials: List[dict]) -> Dict[str, dict]:
    """Per malicious family: detection rate + Wilson CI + the FULL layer
    distribution (preserved, not collapsed) and its mode.

    {family: {'n','tp','recall','ci':(lo,hi),'modal_layer','layers':{layer:count}}}
    """
    by_family: Dict[str, List[dict]] = defaultdict(list)
    for t in _plan_trials(trials):
        if t.get("label") == 1:
            by_family[t.get("family_or_class", "?")].append(t)

    out: Dict[str, dict] = {}
    for family, ts in sorted(by_family.items()):
        n = len(ts)
        detected = [t for t in ts if t.get("detected")]
        tp = len(detected)
        layers = Counter(t.get("layer_fired") or "none" for t in detected)
        out[family] = {
            "n": n,
            "tp": tp,
            "recall": _safe_div(tp, n),
            "ci": list(wilson_ci(tp, n)),
            "modal_layer": (layers.most_common(1)[0][0] if layers else None),
            "layers": dict(layers),           # full distribution preserved
        }
    return out


def completeness(trials: List[dict], planned: Dict[str, str]) -> dict:
    """Reconcile recorded trials against the PLANNED manifest so missing trials
    can never silently vanish from the denominator.

    planned: {sample_id: group_name} for every trial the sweep was SUPPOSED to
    run. Returns per-group and global ran/planned/missing/errored counts and a
    ``complete`` flag. A run with any missing or errored trial is NOT complete,
    and any claim like recall=1.000 must be qualified by this.
    """
    plan = _plan_trials(trials)
    ran_ids = {t.get("sample_id") for t in plan}
    err_ids = {t.get("sample_id") for t in plan if t.get("error")}
    planned_ids = set(planned)

    by_group: Dict[str, dict] = {}
    for sid, grp in planned.items():
        g = by_group.setdefault(grp, {"planned": 0, "ran": 0, "missing": [], "errored": []})
        g["planned"] += 1
        if sid in ran_ids:
            g["ran"] += 1
            if sid in err_ids:
                g["errored"].append(sid)
        else:
            g["missing"].append(sid)

    total_ran = len(ran_ids & planned_ids)
    total_err = len(err_ids & planned_ids)
    total_missing = len(planned_ids) - total_ran
    return {
        "by_group": by_group,
        "planned": len(planned_ids),
        "ran": total_ran,
        "missing": total_missing,
        "errored": total_err,
        "complete": (total_missing == 0 and total_err == 0),
    }


def benign_fpr(trials: List[dict]) -> Dict[str, dict]:
    """Per benign class: false-positive rate + Wilson CI. The high-entropy
    (compression/encryption) class is flagged ``headline=True`` (§1.3).

    {benign_class: {'n','fp','fpr','ci':(lo,hi),'headline':bool}}
    """
    by_class: Dict[str, List[dict]] = defaultdict(list)
    for t in _plan_trials(trials):
        if t.get("label") == 0:
            by_class[t.get("family_or_class", "?")].append(t)

    out: Dict[str, dict] = {}
    for cls, ts in sorted(by_class.items()):
        n = len(ts)
        fp = sum(1 for t in ts if t.get("detected"))
        out[cls] = {
            "n": n,
            "fp": fp,
            "fpr": _safe_div(fp, n),
            "ci": list(wilson_ci(fp, n)),
            "headline": cls == "high_entropy",
        }
    return out
