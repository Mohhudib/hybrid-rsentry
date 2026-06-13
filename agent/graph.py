import logging
import os
import random
import time
from collections import deque
from pathlib import Path

logger = logging.getLogger(__name__)

CANARY_SUFFIX = ".txt"
CANARY_COUNT = int(os.getenv("CANARY_COUNT", "30"))

# Feature 3: realistic decoy headers so ransomware that samples magic bytes /
# file type before encrypting still treats canaries as genuine documents.
_PDF_HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
_DOCX_HEADER = b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00\x21\x00"  # OOXML/zip magic
# Backdated-mtime window: canaries look like long-lived real files (30-400 days).
_CANARY_MIN_AGE_DAYS = 30
_CANARY_MAX_AGE_DAYS = 400
# Realistic body size range (20-100 KB).
_CANARY_MIN_BYTES = 20 * 1024
_CANARY_MAX_BYTES = 100 * 1024


def _canary_content() -> bytes:
    """Return 20-100 KB of realistic-looking document bytes (PDF or DOCX header
    followed by a high-entropy body, so size/type sampling sees a real file)."""
    header = random.choice([_PDF_HEADER, _DOCX_HEADER])
    size = random.randint(_CANARY_MIN_BYTES, _CANARY_MAX_BYTES)
    body = os.urandom(max(0, size - len(header)))
    return header + body


def _backdate(path: Path) -> None:
    """Backdate atime/mtime to a random point 30-400 days in the past so the
    decoy looks like an aged real document rather than a freshly planted file."""
    try:
        age = (random.randint(_CANARY_MIN_AGE_DAYS, _CANARY_MAX_AGE_DAYS) * 86400
               + random.randint(0, 86400))
        past = time.time() - age
        os.utime(path, (past, past))
    except OSError as exc:
        logger.debug("Could not backdate canary %s: %s", path, exc)


class FilesystemGraph:
    def __init__(self, root: str):
        self.root = Path(root)
        self.canary_paths: list[Path] = []
        self._cleanup_old_canaries()

    def _cleanup_old_canaries(self):
        """Delete all canary files before placing new ones to avoid orphans on restart."""
        try:
            for prefix in ["AAA_", "aaa_", "ZZZ_", "zzz_"]:
                for path in self.root.rglob(f"{prefix}*{CANARY_SUFFIX}"):
                    try:
                        path.unlink()
                        logger.debug("Removed old canary: %s", path)
                    except OSError as exc:
                        logger.warning("Could not remove canary %s: %s", path, exc)
        except Exception as exc:
            logger.warning("Canary cleanup error: %s", exc)

    def _bfs_dirs(self) -> list[Path]:
        """Return directories under root in BFS order, skipping hidden dirs and symlinks."""
        dirs: list[Path] = []
        seen: set[Path] = set()
        queue: deque[Path] = deque([self.root])
        seen.add(self.root.resolve())
        while queue:
            current = queue.popleft()
            dirs.append(current)
            try:
                entries = list(current.iterdir())
            except PermissionError:
                continue
            for e in entries:
                if e.is_dir() and not e.is_symlink() and not e.name.startswith("."):
                    resolved = e.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        queue.append(e)
        return dirs

    def place_canaries(self, strategy: str = "bfs") -> list[Path]:
        """Place CANARY_COUNT canary files spread across the directory tree."""
        self._cleanup_old_canaries()
        dirs = self._bfs_dirs() or [self.root]
        canaries: list[Path] = []
        for i in range(CANARY_COUNT):
            target_dir = dirs[i % len(dirs)]
            prefixes = ["AAA_", "aaa_", "ZZZ_", "zzz_"]
            prefix = prefixes[i % len(prefixes)]
            canary_path = target_dir / f"{prefix}{i:03d}{CANARY_SUFFIX}"
            try:
                canary_path.write_bytes(_canary_content())
                _backdate(canary_path)
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
        return name.startswith(("AAA_", "aaa_", "ZZZ_", "zzz_"))
