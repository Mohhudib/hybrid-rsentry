#!/usr/bin/env python3
"""
tests/evaluation/conftest.py — shared pytest fixtures for the evaluation suite.
[NO ROOT to import]

Provides:
  * now_ns        — the CLOCK_MONOTONIC reader used everywhere (design §0.5).
  * results_dir   — tests/evaluation/results (created on demand).
  * append_trial  — a JSON result-writer that appends one TrialResult per line to
                    results/trials_raw.json (JSON-lines, append-safe under repeated
                    runs; read back with read_trials()).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, List

import pytest

from tests.evaluation.harness import TrialResult

RESULTS_DIR = Path(__file__).resolve().parent / "results"
TRIALS_RAW = RESULTS_DIR / "trials_raw.json"


def monotonic_ns() -> int:
    """Single source of truth for the harness/test clock (system-wide MONOTONIC)."""
    return time.monotonic_ns()


def append_trial_record(result: TrialResult, path: Path = TRIALS_RAW) -> None:
    """Append one TrialResult as a JSON object on its own line (JSON-lines)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(result.to_dict(), sort_keys=True) + "\n")


def read_trials(path: Path = TRIALS_RAW) -> List[dict]:
    """Read back all appended TrialResult records (JSON-lines)."""
    if not path.is_file():
        return []
    out: List[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="session")
def now_ns() -> Callable[[], int]:
    """Return the monotonic-ns clock function (call it to timestamp)."""
    return monotonic_ns


@pytest.fixture(scope="session")
def results_dir() -> Path:
    """The results directory, created if absent."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR


@pytest.fixture
def append_trial() -> Callable[[TrialResult], None]:
    """Return a writer that appends a TrialResult to results/trials_raw.json."""
    return append_trial_record
