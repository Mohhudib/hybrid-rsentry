"""
sim_dfs.py — Safe ransomware simulator: DFS file access pattern.
Walks a directory tree depth-first and writes high-entropy data to files.
No real encryption. No real malware. Safe for testing only.
"""
import argparse
import os
import random
import sys
import time
from pathlib import Path


def _high_entropy_bytes(n: int) -> bytes:
    """Generate n random bytes (high Shannon entropy, mimics ciphertext)."""
    return random.randbytes(n)


def _sim_dfs(root: Path, delay: float, max_files: int, dry_run: bool):
    """Walk root DFS, overwrite text files with high-entropy content."""
    count = 0
    print(f"[sim_dfs] Starting DFS simulation on {root} | delay={delay}s | dry_run={dry_run}")

    for dirpath, dirnames, filenames in os.walk(root):
        # DFS order — don't shuffle dirnames so os.walk uses natural DFS
        for fname in filenames:
            if count >= max_files:
                print(f"[sim_dfs] Reached max_files={max_files}. Stopping.")
                return

            fp = Path(dirpath) / fname

            # Skip canary files — they will trigger alerts naturally
            if fname.startswith("AAA_"):
                print(f"[sim_dfs]   CANARY HIT: {fp}")
                if not dry_run:
                    fp.write_bytes(_high_entropy_bytes(512))
                count += 1
                time.sleep(delay)
                continue

            # Skip non-user files
            if not fp.suffix in {".txt", ".doc", ".pdf", ".jpg", ".png", ".csv", ".xlsx"}:
                continue

            payload = _high_entropy_bytes(random.randint(256, 4096))
            if dry_run:
                print(f"[sim_dfs]   [DRY] Would overwrite: {fp} ({len(payload)} bytes)")
            else:
                try:
                    fp.write_bytes(payload)
                    print(f"[sim_dfs]   Overwrote: {fp} ({len(payload)} bytes)")
                except PermissionError:
                    print(f"[sim_dfs]   SKIP (permission): {fp}")
                    continue

            count += 1
            time.sleep(delay)

    print(f"[sim_dfs] Done. Files touched: {count}")


def main():
    parser = argparse.ArgumentParser(description="Safe DFS ransomware simulator")
    parser.add_argument("root", nargs="?", default="/tmp/rsentry_test",
                        help="Directory to simulate on (default: /tmp/rsentry_test)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Seconds between file writes (default: 0.1)")
    parser.add_argument("--max-files", type=int, default=50,
                        help="Max files to touch (default: 50)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Don't actually write files, just print what would happen")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        print(f"[sim_dfs] Creating test directory: {root}")
        root.mkdir(parents=True)
        # Seed with dummy files
        for i in range(5):
            subdir = root / f"subdir_{i}"
            subdir.mkdir()
            for j in range(5):
                (subdir / f"document_{j}.txt").write_text(f"Sample document {i}-{j}\n")

    _sim_dfs(root, args.delay, args.max_files, args.dry_run)


if __name__ == "__main__":
    main()
