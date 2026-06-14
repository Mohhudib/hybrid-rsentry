#!/usr/bin/env python3
"""
tests/evaluation/corpus/manifest.py — combine the malicious + benign plans into a
single labeled manifest and persist it. [NO ROOT]

The manifest is the ground-truth trial plan the axis tests consume: a flat map of
sample_id -> {label, family_or_class, params, ...}. It is JSON-serializable (no
runtime callables); the harness builds runnable Workloads separately via each
corpus module's build_workload().
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from tests.evaluation.corpus import benign_workloads, malicious_samples

_RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
MANIFEST_PATH = _RESULTS_DIR / "manifest.json"


def build_manifest(n_per_family: int = 30, n_per_class: int = 30) -> Dict[str, dict]:
    """Build the combined labeled manifest keyed by sample_id."""
    plan: List[dict] = (
        malicious_samples.malicious_plan(n_per_family)
        + benign_workloads.benign_plan(n_per_class)
    )
    manifest: Dict[str, dict] = {}
    for entry in plan:
        sid = entry["sample_id"]
        if sid in manifest:
            raise ValueError(f"duplicate sample_id in plan: {sid!r}")
        manifest[sid] = {
            "label": entry["label"],
            "family_or_class": entry.get("family") or entry.get("benign_class"),
            "params": entry.get("params", {}),
            "expected_primary_layer": entry.get("expected_primary_layer"),
            "expected": entry.get("expected"),
            "tool": entry.get("tool"),
            "sim_module": entry.get("sim_module"),
        }
    return manifest


def write_manifest(n_per_family: int = 30, n_per_class: int = 30,
                   path: Path = MANIFEST_PATH) -> Dict[str, dict]:
    """Build the manifest and write it to results/manifest.json. Returns it."""
    manifest = build_manifest(n_per_family, n_per_class)
    path.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "_meta": {
            "n_per_family": n_per_family,
            "n_per_class": n_per_class,
            "n_total": len(manifest),
            "n_malicious": sum(1 for v in manifest.values() if v["label"] == 1),
            "n_benign": sum(1 for v in manifest.values() if v["label"] == 0),
            "benign_skipped": benign_workloads.skipped_notes(),
        }
    }
    with open(path, "w") as fh:
        json.dump({**meta, **manifest}, fh, indent=2, sort_keys=True)
    return manifest


if __name__ == "__main__":
    m = write_manifest()
    print(f"wrote {MANIFEST_PATH} | {len(m)} samples")
