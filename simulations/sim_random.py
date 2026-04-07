"""
sim_random.py — Safe ransomware simulator: random file access pattern.
Randomly selects files across the tree and writes high-entropy data.
Mimics ransomware that randomises access order to evade sequential detectors.
"""
import argparse
import os
import random
import time
from pathlib import Path


def _high_entropy_bytes(n: int) -> bytes:
    return random.randbytes(n)


def _collect_files(root: Path) -> list[Path]:
    files = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            files.append(Path(dirpath) / fname)
    return files


def _sim_random(root: Path, delay: float, max_files: int, dry_run: bool):
    all_files = _collect_files(root)
    random.shuffle(all_files)
    targets = all_files[:max_files]

    print(f"[sim_random] Starting random simulation | {len(targets)} files | delay={delay}s")

    for fp in targets:
        if fp.name.startswith("AAA_"):
            print(f"[sim_random]   CANARY HIT: {fp}")
            if not dry_run:
                fp.write_bytes(_high_entropy_bytes(512))
            time.sleep(delay)
            continue

        if fp.suffix not in {".txt", ".doc", ".pdf", ".jpg", ".png", ".csv", ".xlsx"}:
            continue

        payload = _high_entropy_bytes(random.randint(256, 4096))
        if dry_run:
            print(f"[sim_random]   [DRY] Would overwrite: {fp}")
        else:
            try:
                fp.write_bytes(payload)
                print(f"[sim_random]   Overwrote: {fp}")
            except PermissionError:
                print(f"[sim_random]   SKIP: {fp}")
        time.sleep(delay)

    print("[sim_random] Done.")


def main():
    parser = argparse.ArgumentParser(description="Safe random-order ransomware simulator")
    parser.add_argument("root", nargs="?", default="/tmp/rsentry_test")
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--max-files", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        root.mkdir(parents=True)
        for i in range(5):
            subdir = root / f"subdir_{i}"
            subdir.mkdir()
            for j in range(5):
                (subdir / f"file_{j}.txt").write_text(f"Content {i}-{j}\n")

    _sim_random(root, args.delay, args.max_files, args.dry_run)


if __name__ == "__main__":
    main()
