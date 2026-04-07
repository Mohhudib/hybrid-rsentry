"""
graph.py — NetworkX filesystem graph with DFS/BFS hot-spot detection.
Places 15 canary files prefixed AAA_ at high-entropy hot-spots.
"""
import os
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Optional

import networkx as nx

logger = logging.getLogger(__name__)

CANARY_PREFIX = "AAA_"
CANARY_COUNT = 15
CANARY_CONTENT = (
    b"RSENTRY_CANARY_DO_NOT_MODIFY\n"
    b"This file is a honeypot used for ransomware detection.\n"
    b"Touching this file triggers a CRITICAL alert.\n"
)


class FilesystemGraph:
    """
    Builds a directed graph of the watched directory tree.
    Nodes = directories/files, edges = parent→child.
    Hot-spots are directories with the highest degree centrality,
    discovered via BFS/DFS traversal.
    """

    def __init__(self, root: str, canary_dir: str = "/tmp/rsentry_canaries"):
        self.root = Path(root)
        self.canary_dir = Path(canary_dir)
        self.graph: nx.DiGraph = nx.DiGraph()
        self.canary_paths: list[Path] = []
        self._canary_hashes: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build(self) -> None:
        """Walk the filesystem and populate the directed graph."""
        self.graph.clear()
        logger.info("Building filesystem graph from %s", self.root)

        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            # Skip hidden dirs and proc-like paths
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".")
                and not d.startswith("AAA_")
            ]
            dp = Path(dirpath)
            self.graph.add_node(str(dp), kind="dir", file_count=len(filenames))
            for fname in filenames:
                fp = str(dp / fname)
                self.graph.add_node(fp, kind="file")
                self.graph.add_edge(str(dp), fp)
            for dname in dirnames:
                child = str(dp / dname)
                self.graph.add_edge(str(dp), child)

        logger.info(
            "Graph built: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

    def hotspots_bfs(self, top_n: int = CANARY_COUNT) -> list[str]:
        """Return top-N directory nodes ranked by BFS discovery order × out-degree."""
        dir_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("kind") == "dir"]
        if not dir_nodes:
            return []

        root_str = str(self.root)
        start = root_str if root_str in self.graph else dir_nodes[0]

        scores: dict[str, float] = {}
        bfs_order = list(nx.bfs_tree(self.graph, start).nodes())
        total = max(len(bfs_order), 1)

        for rank, node in enumerate(bfs_order):
            if node not in dir_nodes:
                continue
            out_deg = self.graph.out_degree(node)
            # Higher rank (visited earlier in BFS) + high branching = hot
            scores[node] = (1 - rank / total) * 0.4 + out_deg * 0.6

        return sorted(scores, key=scores.get, reverse=True)[:top_n]  # type: ignore

    def hotspots_dfs(self, top_n: int = CANARY_COUNT) -> list[str]:
        """Return top-N directory nodes by DFS depth × out-degree product."""
        dir_nodes = {n for n, d in self.graph.nodes(data=True) if d.get("kind") == "dir"}
        if not dir_nodes:
            return []

        root_str = str(self.root)
        start = root_str if root_str in self.graph else next(iter(dir_nodes))

        depths: dict[str, int] = {start: 0}
        for parent, child in nx.dfs_edges(self.graph, start):
            depths[child] = depths.get(parent, 0) + 1

        scores: dict[str, float] = {}
        max_depth = max(depths.values(), default=1)
        for node in dir_nodes:
            depth = depths.get(node, 0)
            out_deg = self.graph.out_degree(node)
            scores[node] = (depth / max_depth) * 0.5 + out_deg * 0.5

        return sorted(scores, key=scores.get, reverse=True)[:top_n]  # type: ignore

    # ------------------------------------------------------------------
    # Canary placement
    # ------------------------------------------------------------------

    def place_canaries(self, strategy: str = "bfs") -> list[Path]:
        """
        Place CANARY_COUNT canary files at hot-spot directories.
        strategy: 'bfs' | 'dfs'
        """
        self.build()
        spots = self.hotspots_bfs() if strategy == "bfs" else self.hotspots_dfs()

        # Fallback: use canary_dir if not enough hot-spots
        self.canary_dir.mkdir(parents=True, exist_ok=True)
        placed: list[Path] = []

        for i in range(CANARY_COUNT):
            target_dir = Path(spots[i]) if i < len(spots) else self.canary_dir
            canary_name = f"{CANARY_PREFIX}canary_{i:02d}.txt"
            canary_path = target_dir / canary_name

            try:
                canary_path.write_bytes(CANARY_CONTENT)
                sha = hashlib.sha256(CANARY_CONTENT).hexdigest()
                self._canary_hashes[str(canary_path)] = sha
                placed.append(canary_path)
                logger.debug("Placed canary: %s", canary_path)
            except PermissionError:
                # Fall back to canary_dir
                fallback = self.canary_dir / canary_name
                fallback.write_bytes(CANARY_CONTENT)
                sha = hashlib.sha256(CANARY_CONTENT).hexdigest()
                self._canary_hashes[str(fallback)] = sha
                placed.append(fallback)
                logger.debug("Placed canary (fallback): %s", fallback)

        self.canary_paths = placed
        logger.info("Placed %d canary files", len(placed))
        return placed

    def reposition_canaries(self, new_paths: list[Path]) -> None:
        """Move existing canaries to new_paths (called by adaptive.py)."""
        for old, new in zip(self.canary_paths, new_paths):
            if old.exists():
                new.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old), str(new))
                # Update hash record
                sha = self._canary_hashes.pop(str(old), None)
                if sha:
                    self._canary_hashes[str(new)] = sha
        self.canary_paths = new_paths
        logger.info("Repositioned %d canaries", len(new_paths))

    def is_canary(self, path: str) -> bool:
        return Path(path).name.startswith(CANARY_PREFIX)

    def verify_canary_integrity(self, path: str) -> bool:
        """Return False if canary has been modified (content hash changed)."""
        expected = self._canary_hashes.get(path)
        if not expected:
            return False
        try:
            actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            return actual == expected
        except OSError:
            return False

    def canary_paths_set(self) -> set[str]:
        return {str(p) for p in self.canary_paths}
