"""
sim_common.py — shared simulation engine for Hybrid R-Sentry behavioural sims.
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import string
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple


@dataclass
class Profile:
    name: str
    ext_fn: Callable[[], str]
    mode: str                        # full | intermittent | percent | two_pass
    delay: float = 0.05
    block: int = 4096
    step: int = 2                    # intermittent: encrypt every N blocks
    percent: int = 40                # percent-mode: encrypt first N% of file
    note_name: str = "RANSOM_NOTE.txt"
    note_text: bytes = b"[SIMULATION]\n"
    priority_exts: Tuple[str, ...] = ()


def rand_ext(length: int) -> Callable[[], str]:
    def _fn():
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return _fn


# ---------------------------------------------------------------------------
# Corpus helpers
# ---------------------------------------------------------------------------

CORPUS_EXTS = [".docx", ".xlsx", ".pdf", ".txt", ".jpg", ".db", ".vmdk", ".vmx"]


def populate_corpus(root: str, dirs: int = 8, depth: int = 4,
                    files_per_dir: int = 6) -> List[str]:
    """Create a synthetic file tree under root. Returns list of created files."""
    created = []
    root_p = Path(root)

    def _make_dir(parent: Path, cur_depth: int) -> None:
        if cur_depth > depth:
            return
        for i in range(max(1, dirs // max(1, cur_depth))):
            d = parent / f"dir_{cur_depth}_{i}"
            d.mkdir(exist_ok=True)
            for j in range(files_per_dir):
                ext = CORPUS_EXTS[j % len(CORPUS_EXTS)]
                f = d / f"file_{cur_depth}_{i}_{j}{ext}"
                f.write_bytes(os.urandom(random.randint(512, 4096)))
                created.append(str(f))
            _make_dir(d, cur_depth + 1)

    _make_dir(root_p, 1)
    return created


def enumerate_targets(root: str, traversal: str,
                      skip_aaa: bool = False) -> List[str]:
    """Return files in the order the given traversal strategy would visit them."""
    all_files = []

    if traversal == "dfs":
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for fn in sorted(filenames):
                fp = os.path.join(dirpath, fn)
                if skip_aaa and os.path.basename(fp).startswith(("AAA_", "zzz_")):
                    continue
                all_files.append(fp)

    elif traversal == "random":
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                if skip_aaa and os.path.basename(fp).startswith(("AAA_", "zzz_")):
                    continue
                all_files.append(fp)
        random.shuffle(all_files)

    elif traversal == "depth":
        # deepest files first
        with_depth = []
        for dirpath, _, filenames in os.walk(root):
            depth = dirpath.count(os.sep)
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                if skip_aaa and os.path.basename(fp).startswith(("AAA_", "zzz_")):
                    continue
                with_depth.append((depth, fp))
        with_depth.sort(key=lambda x: -x[0])
        all_files = [fp for _, fp in with_depth]

    return all_files


def _prioritise(files: List[str], priority_exts: Tuple[str, ...]) -> List[str]:
    if not priority_exts:
        return files
    hi = [f for f in files if Path(f).suffix.lstrip(".") in priority_exts]
    lo = [f for f in files if Path(f).suffix.lstrip(".") not in priority_exts]
    return hi + lo


# ---------------------------------------------------------------------------
# Encryption simulators
# ---------------------------------------------------------------------------

def _encrypt_full(data: bytes) -> bytes:
    return bytes(b ^ 0xAA for b in data)


def _encrypt_intermittent(data: bytes, block: int, step: int) -> bytes:
    out = bytearray(data)
    for i in range(0, len(data), block * step):
        chunk_end = min(i + block, len(data))
        for j in range(i, chunk_end):
            out[j] ^= 0xAA
    return bytes(out)


def _encrypt_percent(data: bytes, pct: int) -> bytes:
    cut = max(1, int(len(data) * pct / 100))
    return bytes(b ^ 0xAA for b in data[:cut]) + data[cut:]


def _simulate_file(path: str, profile: Profile) -> Optional[str]:
    """
    Simulate encryption of one file according to profile.mode.
    Returns new path on success, None on error.
    """
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = p.read_bytes()
    except OSError:
        return None

    if profile.mode == "full":
        enc = _encrypt_full(data)
    elif profile.mode == "intermittent":
        enc = _encrypt_intermittent(data, profile.block, profile.step)
    elif profile.mode == "percent":
        enc = _encrypt_percent(data, profile.percent)
    elif profile.mode == "two_pass":
        # quick partial pass then thorough
        partial = _encrypt_percent(data, 30)
        enc = _encrypt_full(partial)
    else:
        enc = _encrypt_full(data)

    new_path = str(p) + "." + profile.ext_fn()
    try:
        Path(new_path).write_bytes(enc)
        p.unlink()
    except OSError:
        return None
    return new_path


# ---------------------------------------------------------------------------
# Backup / restore
# ---------------------------------------------------------------------------

def _backup_corpus(root: str) -> str:
    backup = tempfile.mkdtemp(prefix="rsentry_backup_")
    shutil.copytree(root, os.path.join(backup, "corpus"))
    return backup


def _restore_corpus(root: str, backup: str) -> None:
    corpus_backup = os.path.join(backup, "corpus")
    if os.path.exists(root):
        shutil.rmtree(root)
    shutil.copytree(corpus_backup, root)
    shutil.rmtree(backup, ignore_errors=True)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

class Manifest:
    def __init__(self):
        self.encrypted: List[str] = []
        self.skipped: List[str] = []
        self.errors: List[str] = []
        self.note_paths: List[str] = []
        self.t_start: float = 0.0
        self.t_end: float = 0.0

    def summary(self) -> dict:
        return {
            "encrypted": len(self.encrypted),
            "skipped":   len(self.skipped),
            "errors":    len(self.errors),
            "elapsed_s": round(self.t_end - self.t_start, 3),
        }


# ---------------------------------------------------------------------------
# Main attack runner
# ---------------------------------------------------------------------------

def run_attack(root: str, profile: Profile, traversal: str = "dfs",
               skip_aaa: bool = False) -> Manifest:
    manifest = Manifest()
    manifest.t_start = time.perf_counter()

    targets = enumerate_targets(root, traversal, skip_aaa=skip_aaa)
    targets = _prioritise(targets, profile.priority_exts)

    for path in targets:
        new_path = _simulate_file(path, profile)
        if new_path:
            manifest.encrypted.append(new_path)
        else:
            manifest.errors.append(path)
        if profile.delay > 0:
            time.sleep(profile.delay)

    # Drop ransom note in root
    note = os.path.join(root, profile.note_name)
    try:
        Path(note).write_bytes(profile.note_text)
        manifest.note_paths.append(note)
    except OSError:
        pass

    manifest.t_end = time.perf_counter()
    return manifest


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def add_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--target",    default="/tmp/rsentry_lab",
                    help="directory to simulate on")
    ap.add_argument("--traversal", choices=["dfs", "random", "depth"],
                    default="dfs")
    ap.add_argument("--no-restore", action="store_true",
                    help="keep encrypted files after run (default: restore)")
    ap.add_argument("--skip-aaa",   action="store_true",
                    help="skip AAA_/zzz_ canary files")


def main_for(profile: Profile, ap: argparse.ArgumentParser) -> int:
    args = ap.parse_args()
    root = args.target

    if not os.path.isdir(root):
        print(f"[{profile.name}] creating target dir: {root}")
        os.makedirs(root, exist_ok=True)
        populate_corpus(root)

    # Validate not inside git repo
    check = Path(root).resolve()
    for _ in range(10):
        if (check / ".git").is_dir():
            print(f"[{profile.name}] ERROR: target {root} is inside a git repo — aborting")
            return 1
        parent = check.parent
        if parent == check:
            break
        check = parent

    backup = _backup_corpus(root)
    print(f"[{profile.name}] backup at {backup}")
    print(f"[{profile.name}] starting simulation | traversal={args.traversal}")

    try:
        manifest = run_attack(root, profile,
                              traversal=args.traversal,
                              skip_aaa=args.skip_aaa)
    finally:
        if not args.no_restore:
            _restore_corpus(root, backup)
            print(f"[{profile.name}] corpus restored")
        else:
            print(f"[{profile.name}] --no-restore: files left encrypted")

    s = manifest.summary()
    print(f"[{profile.name}] done | encrypted={s['encrypted']} "
          f"errors={s['errors']} elapsed={s['elapsed_s']}s")
    return 0
