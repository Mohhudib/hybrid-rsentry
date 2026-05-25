import logging
import os
import uuid
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
        """Delete all known canary files before placing new ones to avoid orphans on restart."""
        removed = 0
        try:
            # First — remove known canary paths from previous run
            for path in list(self.canary_paths):
                try:
                    if path.exists():
                        path.unlink()
                        removed += 1
                        logger.debug("Removed known canary: %s", path)
                except OSError as exc:
                    logger.warning("Could not remove canary %s: %s", path, exc)

            # Second — fallback scan for AAA_ prefixed files (backward compatibility)
            for path in self.root.rglob(f"{CANARY_PREFIX}*{CANARY_SUFFIX}"):
                try:
                    path.unlink()
                    removed += 1
                    logger.debug("Removed old AAA_ canary: %s", path)
                except OSError as exc:
                    logger.warning("Could not remove canary %s: %s", path, exc)

            # Third — scan all txt files for canary content marker
            for path in self.root.rglob("*.txt"):
                try:
                    if path.is_file() and CANARY_CONTENT in path.read_text(errors="ignore")[:50]:
                        path.unlink()
                        removed += 1
                        logger.debug("Removed content-identified canary: %s", path)
                except OSError:
                    pass

        except Exception as exc:
            logger.warning("Canary cleanup failed: %s", exc)
        logger.info("Cleaned up %d canary files", removed)

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

    def _pick_disguised_name(self, target_dir: Path, used_names: set) -> str:
        """
        Pick a name that blends in with existing files in the directory.
        Uses existing filenames as a pool — falls back to UUID if none available.
        """
        try:
            existing = [
                f.stem for f in target_dir.iterdir()
                if f.is_file() and not f.name.startswith(".")
                and CANARY_CONTENT not in f.read_text(errors="ignore")[:50]
            ]
        except OSError:
            existing = []

        # Try names from existing files first
        for stem in existing:
            candidate = target_dir / f"{stem}.txt"
            if candidate not in used_names and not candidate.exists():
                return candidate.name

        # Fall back to UUID if no suitable name found
        return f"{uuid.uuid4().hex[:8]}.txt"

    def place_canaries(self, strategy: str = "bfs") -> list[Path]:
        """Place CANARY_COUNT canary files spread across the directory tree."""
        self._cleanup_old_canaries()
        dirs = self._bfs_dirs() or [self.root]
        canaries: list[Path] = []
        used_names: set = set()
        for i in range(CANARY_COUNT):
            target_dir = dirs[i % len(dirs)]
            name = self._pick_disguised_name(target_dir, used_names)
            candidate = target_dir / name
            used_names.add(candidate)
            # Store canary marker in content for detection
            try:
                candidate.write_text(f"{CANARY_CONTENT}\nID:{CANARY_PREFIX}{i:03d}")
                canaries.append(candidate)
                logger.debug("Placed canary: %s", candidate)
            except OSError as exc:
                logger.warning("Could not place canary at %s: %s", candidate, exc)
        self.canary_paths = canaries
        logger.info("Placed %d canary files under %s", len(canaries), self.root)
        return canaries

    def is_canary(self, path: str) -> bool:
        """Return True if path is in our known canary list, or contains canary content."""
        p = Path(path)
        # First — check against known canary paths list
        if p in self.canary_paths:
            return True
        # Second — check file content if file exists
        try:
            if p.is_file():
                content = p.read_text(errors="ignore")
                if CANARY_CONTENT in content:
                    return True
        except OSError:
            pass
        # Third — fallback to AAA_ prefix for backward compatibility
        name = p.name
        return name.startswith(CANARY_PREFIX) and name.endswith(CANARY_SUFFIX)
