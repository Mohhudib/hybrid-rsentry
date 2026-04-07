"""
sim_depth.py — Safe ransomware simulator: depth-prioritised access pattern.
Targets the deepest directories first (mimics ransomware that buries important files).
Useful for testing DFS hot-spot detection and Markov repositioning.
"""
import argparse
import os
import random
import time
from pathlib import Path


def _high_entropy_bytes(n: int) -> bytes:
    return random.randbytes(n)


def _collect_by_depth(root: Path) -> list[tuple[int, Path]]:
    """Return (depth, filepath) tuples, deepest first."""
    entries: list[tuple[int, Path]] = []
    root_depth = len(root.parts)
    for dirpath, _, filenames in os.walk(root):
        dp = Path(dirpath)
        depth = len(dp.parts) - root_depth
        for fname in filenames:
            entries.append((depth, dp / fname))
    # Sort descending by depth, shuffle within same depth
    entries.sort(key=lambda x: x[0], reverse=True)
    return entries


def _sim_depth(root: Path, delay: float, max_files: int, dry_run: bool):
    entries = _collect_by_depth(root)[:max_files]
    print(f"[sim_depth] Starting depth-first simulation | {len(entries)} files")

    for depth, fp in entries:
        if fp.name.startswith("AAA_"):
            print(f"[sim_depth]   CANARY HIT (depth={depth}): {fp}")
            if not dry_run:
                fp.write_bytes(_high_entropy_bytes(512))
            time.sleep(delay)
            continue

        if fp.suffix not in {".txt", ".doc", ".pdf", ".jpg", ".png", ".csv"}:
            continue

        payload = _high_entropy_bytes(random.randint(256, 4096))
        if dry_run:
            print(f"[sim_depth]   [DRY] depth={depth} → {fp}")
        else:
            try:
                fp.write_bytes(payload)
                print(f"[sim_depth]   depth={depth} → {fp}")
            except PermissionError:
                print(f"[sim_depth]   SKIP: {fp}")
        time.sleep(delay)

    print("[sim_depth] Done.")


def main():
    parser = argparse.ArgumentParser(description="Safe depth-prioritised ransomware simulator")
    parser.add_argument("root", nargs="?", default="/tmp/rsentry_test")
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--max-files", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        root.mkdir(parents=True)
        # Create deep nested structure for depth testing
        current = root
        for i in range(6):
            current = current / f"level_{i}"
            current.mkdir(parents=True, exist_ok=True)
            for j in range(3):
                (current / f"file_{j}.txt").write_text(f"Depth {i} file {j}\n")

    _sim_depth(root, args.delay, args.max_files, args.dry_run)


if __name__ == "__main__":
    main()
