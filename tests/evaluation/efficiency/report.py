#!/usr/bin/env python3
"""
tests/evaluation/efficiency/report.py — render the §2 efficiency tables. [NO ROOT]

Reads efficiency_raw.json (the raw malicious trials), recomputes every metric via
metrics.py, and prints the §2 tables as plain ASCII (milliseconds). Percentiles
LEAD every table; the mean is a trailing column so it is visible that mean < p95
under skew. A completeness banner (planned-vs-ran) prints first.

Usage:
    python3 -m tests.evaluation.efficiency.report [path/to/efficiency_raw.json]
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import List

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.evaluation.conftest import RESULTS_DIR, read_trials
from tests.evaluation.corpus import malicious_samples
from tests.evaluation.efficacy.report import _table, _fmt, _ci   # reuse renderers
from tests.evaluation.efficiency import metrics
from tests.evaluation.efficiency.runner import EFFICIENCY_RAW, EFFICIENCY_REPORT

KNOWN_FAMILIES = list(malicious_samples.FAMILIES)
_STAGE_LABEL = {
    "mttd": "MTTD (onset->detect)", "detect_freeze": "detect->freeze",
    "freeze_isolate": "freeze->isolate", "isolate_kill": "isolate->kill",
    "kill_complete": "kill->complete", "mttr": "MTTR (detect->complete)",
    "total_response": "total (onset->complete)",
}


def _load_completeness() -> "dict | None":
    if not EFFICIENCY_REPORT.is_file():
        return None
    try:
        return json.loads(EFFICIENCY_REPORT.read_text()).get("_meta", {}).get("completeness")
    except (OSError, json.JSONDecodeError):
        return None


def completeness_banner(comp: "dict | None") -> str:
    if comp is None:
        return ("[EFFICIENCY] Completeness: UNKNOWN — no efficiency_report.json with a "
                "planned manifest. Run the sweep via runner.py so recorded-vs-planned "
                "can be reconciled.")
    status = "COMPLETE" if comp["complete"] else "*** INCOMPLETE ***"
    lines = [f"[EFFICIENCY] Completeness: {status}  (ran {comp['ran']}/{comp['planned']} "
             f"planned; missing={comp['missing']}, errored={comp['errored']})"]
    if not comp["complete"]:
        lines.append("  Latencies below are over the RECORDED trials only — NOT the full planned N.")
        for grp, g in sorted(comp["by_group"].items()):
            if g["missing"] or g["errored"]:
                lines.append(f"    {grp:<14} ran {g['ran']}/{g['planned']}  "
                             f"missing={len(g['missing'])} errored={len(g['errored'])}")
    return "\n".join(lines)


def stage_table(trials: List[dict]) -> str:
    rows = []
    for name in metrics.STAGE_NAMES:
        s = metrics.summary_stats(metrics.collect_interval(trials, name))
        rows.append([_STAGE_LABEL[name], str(s["n"]), _fmt(s["p50"]), _fmt(s["p95"]),
                     _fmt(s["p99"]), _fmt(s["mean"]), _fmt(s["max"])])
    return _table("[EFFICIENCY] Stage Latency Breakdown (ms; percentiles lead, mean is secondary)",
                  ["Stage", "n", "p50", "p95", "p99", "mean", "max"], rows)


def mttd_mttr_table(trials: List[dict]) -> str:
    rows = []
    for name in ("mttd", "mttr", "total_response"):
        vals = metrics.collect_interval(trials, name)
        s = metrics.summary_stats(vals)
        ci = metrics.bootstrap_ci_median(vals)
        rows.append([_STAGE_LABEL[name], str(s["n"]), _fmt(s["p50"]),
                     _fmt(s["p95"]), _fmt(s["p99"]), _ci(ci)])
    return _table("[EFFICIENCY] MTTD / MTTR Summary (ms)",
                  ["Metric", "n", "p50", "p95", "p99", "median 95% CI"], rows)


def per_family_table(trials: List[dict]) -> str:
    fam = metrics.per_family_latency(trials)
    rows = []
    for family in KNOWN_FAMILIES:
        d = fam.get(family)
        if d is None:
            rows.append([family + "  ⚠ MISSING", "0", "n/a", "n/a", "n/a"])
        else:
            rows.append([family, str(d["n"]), _fmt(d["mttd"]["p50"]),
                         _fmt(d["mttd"]["p95"]), _fmt(d["mttr"]["p50"])])
    return _table("[EFFICIENCY] Per-Family Latency (ms)",
                  ["Family", "n", "MTTD p50", "MTTD p95", "MTTR p50"], rows)


def damage_table(trials: List[dict]) -> str:
    dmg = metrics.damage_stats(trials)
    rows = []
    for family in KNOWN_FAMILIES:
        d = dmg.get(family)
        if d is None:
            rows.append([family + "  ⚠ MISSING", "0", "n/a", "n/a", "n/a"])
        else:
            rows.append([family, str(d["n"]), _fmt(d["p50"]), _fmt(d["p95"]), _fmt(d["max"])])
    return _table("[EFFICIENCY] Damage — files touched before freeze (count)",
                  ["Family", "n", "p50", "p95", "max"], rows)


def render(trials: List[dict]) -> str:
    return "\n\n".join([
        completeness_banner(_load_completeness()),
        stage_table(trials),
        mttd_mttr_table(trials),
        per_family_table(trials),
        damage_table(trials),
    ])


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else EFFICIENCY_RAW
    trials = read_trials(src)
    if not trials:
        print(f"No trials found at {src}. Run the efficiency sweep first.")
        return 1
    print(f"# Efficiency report — source: {src} ({len(trials)} raw trial records)\n")
    print(render(trials))
    return 0


if __name__ == "__main__":
    sys.exit(main())
