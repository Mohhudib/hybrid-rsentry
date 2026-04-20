import logging
import os
from collections import deque
from pathlib import Path

logger = logging.getLogger(__name__)

CANARY_PREFIX = "AAA_"
CANARY_SUFFIX = ".txt"
CANARY_CONTENT = "RSENTRY_CANARY_DO_NOT_MODIFY"
CANARY_COUNT = int(os.getenv("CANARY_COUNT", "15"))


class FilesystemGraph:
    def __init__(self, root: str):
        self.root = Path(root)
        self.canary_paths: list[Path] = []
        self._cleanup_old_canaries()

    def _cleanup_old_canaries(self):
        """Delete all AAA_ canary files before placing new ones to avoid orphans on restart."""
        try:
            for path in self.root.rglob(f"{CANARY_PREFIX}*{CANARY_SUFFIX}"):
                try:
                    path.unlink()
                    logger.debug("Removed old canary: %s", path)
                except OSError as exc:
                    logger.warning("Could not remove canary %s: %s", path, exc)
        except Exception as exc:
            logger.warning("Canary cleanup failed: %s", exc)

    def _bfs_dirs(self) -> list[Path]:
        """Return directories under root in BFS order, skipping hidden dirs."""
        dirs: list[Path] = []
        queue: deque[Path] = deque([self.root])
        while queue:
            current = queue.popleft()
            try:
                entries = list(current.iterdir())
            except PermissionError:
                continue
            subdirs = [e for e in entries if e.is_dir() and not e.name.startswith(".")]
            dirs.append(current)
            queue.extend(subdirs)
        return dirs

    def place_canaries(self, strategy: str = "bfs") -> list[Path]:
        """Place CANARY_COUNT canary files spread across the directory tree."""
        self._cleanup_old_canaries()
        dirs = self._bfs_dirs() or [self.root]
        canaries: list[Path] = []
        for i in range(CANARY_COUNT):
            target_dir = dirs[i % len(dirs)]
            canary_path = target_dir / f"{CANARY_PREFIX}{i:03d}{CANARY_SUFFIX}"
            try:
                canary_path.write_text(CANARY_CONTENT)
                canaries.append(canary_path)
                logger.debug("Placed canary: %s", canary_path)
            except OSError as exc:
                logger.warning("Could not place canary at %s: %s", canary_path, exc)
        self.canary_paths = canaries
        logger.info("Placed %d canary files under %s", len(canaries), self.root)
        return canaries

    def is_canary(self, path: str) -> bool:
        """Return True if the path matches the canary file naming convention."""
        name = Path(path).name
        return name.startswith(CANARY_PREFIX) and name.endswith(CANARY_SUFFIX)
