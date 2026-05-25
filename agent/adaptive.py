"""
adaptive.py — Markov chain canary repositioning.
Uses numpy to model directory-access transition probabilities and
moves canaries toward the highest-probability next-access locations.
"""
import logging
import shutil
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

REPOSITION_THRESHOLD = 0.70     # trigger repositioning if any state prob >= this
MIN_OBSERVATIONS = 10           # don't reposition until we have enough data
MAX_STATES = 500                # max directory states to track — prevents memory leak


class MarkovRepositioner:
    """
    Tracks directory access events and builds a first-order Markov transition
    matrix. When a particular directory becomes a high-probability next-access
    state, canaries are repositioned there.
    """

    def __init__(self, canary_paths: list[Path]):
        self.canary_paths = list(canary_paths)
        self._state_index: dict[str, int] = {}
        self._transitions: Optional[np.ndarray] = None
        self._counts: Optional[np.ndarray] = None
        self._last_state: Optional[int] = None
        self._n_observations: int = 0
        self._access_counter: Counter = Counter()  # track access frequency for eviction

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def _ensure_state(self, directory: str) -> int:
        if directory not in self._state_index:
            # Evict least-accessed state if we hit the limit
            if len(self._state_index) >= MAX_STATES:
                least = min(self._access_counter, key=self._access_counter.get)
                evict_idx = self._state_index.pop(least)
                self._access_counter.pop(least, None)
                # Remove evicted state from counts matrix
                if self._counts is not None:
                    self._counts = np.delete(self._counts, evict_idx, axis=0)
                    self._counts = np.delete(self._counts, evict_idx, axis=1)
                # Re-index remaining states
                self._state_index = {
                    k: (v if v < evict_idx else v - 1)
                    for k, v in self._state_index.items()
                }
                self._transitions = None
                logger.debug("Markov: evicted least-accessed state: %s", least)

            idx = len(self._state_index)
            self._state_index[directory] = idx
            n = idx + 1
            new_counts = np.zeros((n, n), dtype=np.float64)
            if self._counts is not None and self._counts.size > 0:
                old_n = self._counts.shape[0]
                new_counts[:old_n, :old_n] = self._counts
            self._counts = new_counts
            self._transitions = None

        self._access_counter[directory] += 1
        return self._state_index[directory]

    def observe(self, directory: str) -> None:
        """Record a directory access event."""
        idx = self._ensure_state(directory)
        if self._last_state is not None:
            self._counts[self._last_state, idx] += 1
            self._transitions = None
            self._n_observations += 1
        self._last_state = idx

    def _compute_transitions(self) -> np.ndarray:
        """Normalise count matrix row-wise to get probability matrix."""
        if self._counts is None or self._counts.size == 0:
            return np.array([])
        row_sums = self._counts.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        return self._counts / row_sums

    def _transition_matrix(self) -> np.ndarray:
        if self._transitions is None:
            self._transitions = self._compute_transitions()
        return self._transitions

    # ------------------------------------------------------------------
    # Hot-spot prediction — faster method using access frequency
    # ------------------------------------------------------------------

    def predicted_hotspots(self, top_n: int = 5) -> list[str]:
        """
        Return top-N most likely next-access directories.
        Uses access frequency as a faster alternative to eigendecomposition.
        """
        if self._n_observations < MIN_OBSERVATIONS:
            return []

        if not self._access_counter:
            return []

        # Use access frequency weighted by transition probability
        T = self._transition_matrix()
        if T.size == 0:
            return []

        # Weighted score = access_count * avg outgoing transition probability
        idx_to_state = {v: k for k, v in self._state_index.items()}
        scores: dict[str, float] = {}
        for state, idx in self._state_index.items():
            freq = self._access_counter.get(state, 0)
            avg_prob = float(T[idx].max()) if idx < T.shape[0] else 0.0
            scores[state] = freq * avg_prob

        ranked = sorted(scores, key=scores.get, reverse=True)
        return ranked[:top_n]

    # ------------------------------------------------------------------
    # Canary repositioning
    # ------------------------------------------------------------------

    def should_reposition(self) -> bool:
        """Only reposition if we have enough observations AND high confidence."""
        if self._n_observations < MIN_OBSERVATIONS:
            return False
        T = self._transition_matrix()
        if T.size == 0:
            return False
        # Require at least 3 rows to have high probability — more reliable
        high_prob_rows = np.sum(T.max(axis=1) >= REPOSITION_THRESHOLD)
        return int(high_prob_rows) >= 3

    def reposition(self, fs_graph=None) -> list[Path]:
        """
        Move canaries to predicted hot-spots with new disguised names.
        Returns new canary paths.
        """
        hotspots = self.predicted_hotspots(top_n=len(self.canary_paths))
        if not hotspots:
            logger.debug("Markov: not enough data to reposition canaries")
            return self.canary_paths

        new_paths: list[Path] = []
        for i, canary in enumerate(self.canary_paths):
            if not canary.exists():
                continue
            target_dir = Path(hotspots[i % len(hotspots)])
            target_dir.mkdir(parents=True, exist_ok=True)

            # Pick a new disguised name suitable for the target directory
            if fs_graph is not None:
                new_name = fs_graph._pick_disguised_name(target_dir, set(new_paths))
            else:
                new_name = canary.name

            new_path = target_dir / new_name
            if new_path == canary:
                new_paths.append(canary)
                continue
            try:
                shutil.move(str(canary), str(new_path))
                new_paths.append(new_path)
                logger.info("Markov reposition: %s -> %s", canary, new_path)
            except (OSError, shutil.Error) as exc:
                logger.warning("Reposition failed for %s: %s", canary, exc)
                new_paths.append(canary)

        self.canary_paths = new_paths
        if fs_graph is not None:
            fs_graph.canary_paths = new_paths

        return new_paths

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        return {
            "n_states": len(self._state_index),
            "n_observations": self._n_observations,
            "should_reposition": self.should_reposition(),
            "top_hotspots": self.predicted_hotspots(3),
        }
