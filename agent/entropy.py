"""
entropy.py — Rolling Shannon entropy delta engine.
Fires ENTROPY_SPIKE alert when per-file entropy exceeds thresholds.
Uses scipy, numpy, pandas for computation.
"""
import math
import time
import logging
from collections import deque
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from scipy.stats import entropy as scipy_entropy

logger = logging.getLogger(__name__)

# Thresholds (bits, max = 8 bits for byte data)
ENTROPY_SPIKE_THRESHOLD = 3.5   # single-file delta triggers MEDIUM
HIGH_ENTROPY_ABSOLUTE = 7.2     # file entropy > this is suspicious on its own
WINDOW_SIZE = 30                 # rolling window: last N samples per file
SPIKE_WINDOW_SECONDS = 10       # if delta > threshold within this window → alert


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (0–8 bits)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / counts.sum()
    # Use scipy for numerical stability; base=2 gives bits
    return float(scipy_entropy(probs + 1e-12, base=2))


class EntropyRecord:
    """Per-file rolling entropy history."""

    def __init__(self, path: str, window: int = WINDOW_SIZE):
        self.path = path
        self.window = window
        self._samples: deque[tuple[float, float]] = deque(maxlen=window)  # (timestamp, entropy)

    def add(self, entropy_val: float) -> None:
        self._samples.append((time.monotonic(), entropy_val))

    def delta(self) -> float:
        """Return max – min entropy over the rolling window."""
        if len(self._samples) < 2:
            return 0.0
        vals = [s[1] for s in self._samples]
        return max(vals) - min(vals)

    def recent_spike(self, threshold: float = ENTROPY_SPIKE_THRESHOLD,
                     window_sec: float = SPIKE_WINDOW_SECONDS) -> bool:
        """True if delta > threshold occurred within the last window_sec seconds."""
        if len(self._samples) < 2:
            return False
        now = time.monotonic()
        recent = [s[1] for s in self._samples if now - s[0] <= window_sec]
        if len(recent) < 2:
            return False
        return (max(recent) - min(recent)) >= threshold

    def latest(self) -> float:
        if not self._samples:
            return 0.0
        return self._samples[-1][1]

    def as_series(self) -> pd.Series:
        if not self._samples:
            return pd.Series(dtype=float)
        ts, vals = zip(*self._samples)
        return pd.Series(vals, index=pd.to_datetime(ts, unit="s"), dtype=float)


class EntropyEngine:
    """
    Tracks rolling Shannon entropy for every watched file.
    Call .observe(path) whenever a file is modified.
    """

    def __init__(
        self,
        spike_threshold: float = ENTROPY_SPIKE_THRESHOLD,
        abs_threshold: float = HIGH_ENTROPY_ABSOLUTE,
        window: int = WINDOW_SIZE,
        alert_callback=None,
    ):
        self.spike_threshold = spike_threshold
        self.abs_threshold = abs_threshold
        self.window = window
        self._records: dict[str, EntropyRecord] = {}
        self.alert_callback = alert_callback  # callable(path, delta, entropy)

    def _get_record(self, path: str) -> EntropyRecord:
        if path not in self._records:
            self._records[path] = EntropyRecord(path, self.window)
        return self._records[path]

    def observe(self, path: str) -> Optional[dict]:
        """
        Read the file, compute entropy, update rolling record.
        Returns alert dict if spike detected, else None.
        """
        p = Path(path)
        if not p.is_file():
            return None

        try:
            data = p.read_bytes()
        except (PermissionError, OSError):
            return None

        current_entropy = _shannon_entropy(data)
        record = self._get_record(path)
        record.add(current_entropy)
        delta = record.delta()

        alert = None
        if record.recent_spike(self.spike_threshold) or current_entropy >= self.abs_threshold:
            severity = "HIGH" if (delta >= 5.0 or current_entropy >= self.abs_threshold) else "MEDIUM"
            alert = {
                "event_type": "ENTROPY_SPIKE",
                "file_path": path,
                "entropy_delta": round(delta, 4),
                "current_entropy": round(current_entropy, 4),
                "severity": severity,
                "samples": len(record._samples),
            }
            logger.warning(
                "ENTROPY_SPIKE %s | delta=%.3f bits | current=%.3f bits",
                path, delta, current_entropy,
            )
            if self.alert_callback:
                self.alert_callback(alert)

        return alert

    def bulk_scan(self, paths: list[str]) -> list[dict]:
        """Scan multiple files and return any alerts."""
        alerts = []
        for p in paths:
            result = self.observe(p)
            if result:
                alerts.append(result)
        return alerts

    def stats_dataframe(self) -> pd.DataFrame:
        """Return a DataFrame summarising current entropy state for all tracked files."""
        rows = []
        for path, record in self._records.items():
            rows.append({
                "file": path,
                "latest_entropy": record.latest(),
                "delta": record.delta(),
                "samples": len(record._samples),
                "spike": record.recent_spike(self.spike_threshold),
            })
        return pd.DataFrame(rows) if rows else pd.DataFrame(
            columns=["file", "latest_entropy", "delta", "samples", "spike"]
        )

    def flush(self, path: str) -> None:
        """Remove a file's history (e.g. after containment)."""
        self._records.pop(path, None)
