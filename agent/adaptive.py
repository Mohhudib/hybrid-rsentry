"""
adaptive.py — Markov chain canary repositioning.
Uses numpy to model directory-access transition probabilities and
moves canaries toward the highest-probability next-access locations.
"""
import logging
import shutil
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

REPOSITION_THRESHOLD = 0.70     # trigger repositioning if any state prob >= this
MIN_OBSERVATIONS = 10           # don't reposition until we have enough data


class MarkovRepositioner:
    """
    Tracks directory access events and builds a first-order Markov transition
    matrix.  When a particular directory becomes a high-probability next-access
    state, canaries are repositioned there.

    States = known directories.  The matrix M[i][j] = P(next access is j | last access was i).
    """

    def __init__(self, canary_paths: list[Path]):
        self.canary_paths = list(canary_paths)
        self._state_index: dict[str, int] = {}
        self._transitions: Optional[np.ndarray] = None   # square float64 matrix
        self._counts: Optional[np.ndarray] = None
        self._last_state: Optional[int] = None
        self._n_observations: int = 0

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def _ensure_state(self, directory: str) -> int:
        if directory not in self._state_index:
            idx = len(self._state_index)
            self._state_index[directory] = idx
            # Expand matrices
            n = idx + 1
            new_counts = np.zeros((n, n), dtype=np.float64)
            if self._counts is not None and self._counts.size > 0:
                old_n = self._counts.shape[0]
                new_counts[:old_n, :old_n] = self._counts
            self._counts = new_counts
            self._transitions = None  # invalidate
        return self._state_index[directory]

    def observe(self, directory: str) -> None:
        """Record a directory access event."""
        idx = self._ensure_state(directory)
        if self._last_state is not None:
            self._counts[self._last_state, idx] += 1  # type: ignore
            self._transitions = None  # mark dirty
            self._n_observations += 1
        self._last_state = idx

    def _compute_transitions(self) -> np.ndarray:
        """Normalise count matrix row-wise to get probability matrix."""
        if self._counts is None or self._counts.size == 0:
            return np.array([])
        row_sums = self._counts.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1          # avoid division by zero
        return self._counts / row_sums       # type: ignore

    def _transition_matrix(self) -> np.ndarray:
        if self._transitions is None:
            self._transitions = self._compute_transitions()
        return self._transitions

    # ------------------------------------------------------------------
    # Hot-spot prediction
    # ------------------------------------------------------------------

    def predicted_hotspots(self, top_n: int = 5) -> list[str]:
        """
        Return the top-N most likely next-access directories given the
        stationary distribution of the Markov chain.
        """
        if self._n_observations < MIN_OBSERVATIONS:
            return []

        T = self._transition_matrix()
        if T.size == 0:
            return []

        # Stationary distribution: left eigenvector for eigenvalue 1
        # Equivalent to solving π T = π; use numpy eig on T^T
        try:
            eigenvalues, eigenvectors = np.linalg.eig(T.T)
            # Find eigenvector closest to eigenvalue 1
            idx = np.argmin(np.abs(eigenvalues - 1.0))
            stationary = np.real(eigenvectors[:, idx])
            stationary = np.abs(stationary)
            stationary /= stationary.sum()
        except np.linalg.LinAlgError:
            # Fallback: use row sums
            stationary = self._counts.sum(axis=0)  # type: ignore
            total = stationary.sum()
            stationary = stationary / total if total > 0 else stationary

        idx_to_state = {v: k for k, v in self._state_index.items()}
        ranked = np.argsort(stationary)[::-1]
        return [idx_to_state[i] for i in ranked[:top_n] if i in idx_to_state]

    # ------------------------------------------------------------------
    # Canary repositioning
    # ------------------------------------------------------------------

    def should_reposition(self) -> bool:
        if self._n_observations < MIN_OBSERVATIONS:
            return False
        T = self._transition_matrix()
        if T.size == 0:
            return False
        return float(T.max()) >= REPOSITION_THRESHOLD

    def reposition(self, fs_graph=None) -> list[Path]:
        """
        Move canaries to predicted hot-spots.
        Returns new canary paths.
        If fs_graph is provided, delegates the physical move to it.
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
            new_path = target_dir / canary.name
            if new_path == canary:
                new_paths.append(canary)
                continue
            try:
                shutil.move(str(canary), str(new_path))
                new_paths.append(new_path)
                logger.info("Markov reposition: %s → %s", canary, new_path)
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
