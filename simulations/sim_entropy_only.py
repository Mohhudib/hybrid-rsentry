#!/usr/bin/env python3
"""
sim_entropy_only.py — the ONE workload whose detection uniquely depends on the
entropy layer (`_handle_behavior` → `layer=entropy`, monitor_ebpf.py:1560).

WHY THIS SIM EXISTS (eval design §3.2.1 / §7-Q11)
  The four-layer ablation can only prove entropy is a *necessary detection*
  layer if some sample is caught ONLY by entropy. LockBit/Qilin/Akira are all
  caught by rename and/or the entropy-free write-offset/canary layers, so the
  `−entropy` ablation row against them is a severity-grade change, not a
  recall drop. This sim is shaped to fall through every other layer and land
  solely on the behavioral-score + entropy path.

THE FOUR THRESHOLDS IT THREADS (see the module-level analysis below each):

  A. STAY UNDER observe_write_offset  (write-offset layer must stay silent)
     - kernel NONSEQ_THRESH = 5 and userspace _NONSEQ_THRESHOLD = 5: a run of 5
       NON-sequential writes to one inode → SILENT_ENCRYPTION. A sequential
       write (offset == previous end) RESETS the counter.
       → We overwrite each file IN ONE SEQUENTIAL PASS from offset 0 (r+b,
         seek(0), single write of the whole buffer). nonseq reaches at most 1
         per inode (the offset-0 write vs. the seed's last_end), never 5. No
         backward seeks. No re-overwrites in the keep-alive phase.
     - observe_write burst→entropy: needs ≥10 writes / ≥3 inodes in 2s AND
       entropy ≥ 7.0. We keep total writes < 50 (so the kernel velocity gate
       WRITE_BURST_THRESH=50 never ships a write_event to userspace, so
       observe_write is never invoked on that path) AND entropy < 7.0.

  B. FIRE behavior_events  (the ONLY trigger _handle_behavior can ride)
     behavior_events.perf_submit lives at exactly ONE site — __handle_unlink,
     gated on proc score >= SCORE_ALERT(50) && !alerted. __calc_score has NO
     writes-only signal; it needs DELETES. We therefore rapidly delete scratch
     files:
        S1 (del+write, del_per_sec>=2)               = +35 (+10 if del>5)
        S3 (total_file_ops>15 && deleted>3)          = +15
     ~8 in-place doc overwrites + ~14 fast scratch deletes → score = 60:
        >= SCORE_ALERT(50)  → behavior_events fires on ~the 4th unlink
        <  SCORE_BLOCK(70)  → the kernel score-based inline block does NOT arm,
                              so _handle_behavior stays the sole container.
     (We issue 0 renames [S2] and spawn 0 children [S5], so 60 is the ceiling.)

  C. PASS the entropy >= 6.5 gate  (the subtle one)
     _handle_behavior checks entropy_fn(sample_path) >= 6.5. entropy_fn
     (monitor._make_entropy_fn) returns the rolling DELTA when EntropyEngine
     .observe() raises an alert, and only the ABSOLUTE latest otherwise. On the
     FIRST observation of a file delta() == 0.0, and observe() alerts whenever
     current_entropy >= HIGH_ENTROPY_ABSOLUTE(7.2). So raw os.urandom (~7.99)
     would make entropy_fn return delta = 0.0 → the gate FAILS (this is the
     `delta=0.000` artifact seen in the manual logs).
       → We write content with absolute Shannon entropy in [6.5, 7.2),
         targeting ~6.8. observe() does NOT alert (abs < 7.2, single-sample → no
         spike), so entropy_fn returns latest ≈ 6.8 >= 6.5 → the gate PASSES.
         Staying < 7.0 also keeps the burst-entropy detector (A) silent. Each
         buffer is self-verified in-band before it is written.

  D. EVERYTHING ELSE STAYS SILENT
     No renames (rename/extension + velocity idle). No canary inode touched
     (skip AAA_/aaa_/ZZZ_/zzz_). No backup-destruction execve. Rate limiter
     (500/ms) never approached. After triggering, the high-entropy docs are kept
     OPEN (so /proc/<pid>/fd sampling lands on a 6.8-entropy file) and the sim
     SLEEPS (no further writes → no nonseq buildup) to stay alive for the
     SIGSTOP → evidence → cgroup-isolate → SIGKILL pipeline.

SAFETY (benign sim — no cipher, no key)
  * Content is os.urandom mapped to a reduced byte alphabet — high entropy, but
    NOTHING is encrypted and no original bytes are derivable from it.
  * Live mode backs the corpus up and restores it (unless --no-restore); the
    scratch files are created under the target and removed by restore.
  * --validate-defense runs inside a sentinel-guarded Sandbox with a
    byte-for-byte integrity audit on exit.

USAGE
    # Live (root + running eBPF sensor) — operate on a pre-seeded corpus dir:
    sudo -E python3 -m simulations.sim_entropy_only \
         --target /tmp/rsentry_agent_watch/entropy_zone --no-restore \
         --max-files 8 --delay 0.1

    # Offline negative-space validation (no root, no BCC): proves the competing
    # layers stay silent and the entropy band holds, so live detection can only
    # come from layer=entropy:
    python3 -m simulations.sim_entropy_only --validate-defense \
         --target /tmp/rsentry_sandbox
"""
from __future__ import annotations

import argparse
import os
import shutil
import time
from math import log2
from pathlib import Path
from typing import List, Optional, Tuple

from simulations.sim_common import (
    ATTACKER_PID, ATTACKER_PPID, DefenseResult, EvalTimestampWriter, Sandbox,
    add_common_args, build_validation_engine, file_entropy, populate_corpus,
    _backup_corpus, _restore_corpus, _set_comm,
)

NAME = "ENTROPY_ONLY"

# Content tuning — see analysis C. The band floor is the _handle_behavior gate
# (6.5); the ceiling is the EntropyEngine absolute-alert line (7.2) that would
# flip entropy_fn to its zero-delta return. We aim mid-band and stay < 7.0 so
# the observe_write burst-entropy detector (threshold 7.0) is silent too.
ENTROPY_TARGET_LO = 6.60
ENTROPY_TARGET_HI = 6.95
FILE_SIZE = 32768                 # <= the 64 KB observe() read window
DEFAULT_MAX_FILES = 8
DEFAULT_SCRATCH_DELETES = 14      # > 5 (S1+10) and enough for del_per_sec >= 2
DEFAULT_KEEPALIVE_S = 20.0        # stay alive for the live pipeline
CANARY_PREFIXES = ("AAA_", "aaa_", "ZZZ_", "zzz_")
SCRATCH_DIRNAME = "._entropy_scratch"


# --------------------------------------------------------------------------- #
# Banded high-entropy content generator (no cipher)
# --------------------------------------------------------------------------- #

def _shannon_bytes(buf: bytes) -> float:
    """Absolute Shannon entropy (bits/byte) of a buffer — the same quantity
    EntropyEngine.observe() computes on the first 64 KB of the file."""
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    return -sum((c / n) * log2(c / n) for c in counts if c)


def make_banded_content(size: int = FILE_SIZE,
                        lo: float = ENTROPY_TARGET_LO,
                        hi: float = ENTROPY_TARGET_HI) -> Tuple[bytes, float]:
    """Return (buffer, entropy) whose absolute Shannon entropy is in [lo, hi].

    High entropy is produced by drawing os.urandom and folding it onto a reduced
    byte alphabet of size M; the entropy of a uniform draw over M symbols is
    ~log2(M), so M is binary-searched until the measured entropy lands in band.
    NO encryption is performed — this is structured randomness, not ciphertext.
    """
    lo_m, hi_m = 2, 256
    best: Optional[Tuple[bytes, float]] = None
    raw = os.urandom(size)
    for _ in range(14):
        m = max(2, min(256, (lo_m + hi_m) // 2))
        buf = bytes(b % m for b in raw)
        e = _shannon_bytes(buf)
        if best is None or abs(e - (lo + hi) / 2) < abs(best[1] - (lo + hi) / 2):
            best = (buf, e)
        if e < lo:
            lo_m = m + 1
        elif e > hi:
            hi_m = m - 1
        else:
            return buf, e
        if lo_m > hi_m:
            break
        raw = os.urandom(size)   # fresh draw each step so the search isn't stuck
    assert best is not None
    return best


# --------------------------------------------------------------------------- #
# Live attack
# --------------------------------------------------------------------------- #

def _select_documents(root: str, max_files: int) -> List[Path]:
    """Existing corpus files under root, skipping canaries, the sentinel and the
    scratch dir. Populates a synthetic corpus if the dir is empty."""
    def _is_doc(p: Path) -> bool:
        if not p.is_file():
            return False
        if p.name.startswith(CANARY_PREFIXES):
            return False
        if p.name == ".rsentry_sandbox":
            return False
        if SCRATCH_DIRNAME in p.parts:
            return False
        return True

    docs = sorted(p for p in Path(root).rglob("*") if _is_doc(p))
    if not docs:
        populate_corpus(root)
        docs = sorted(p for p in Path(root).rglob("*") if _is_doc(p))
    return docs[:max_files]


def run_entropy_attack(root: str,
                       max_files: int = DEFAULT_MAX_FILES,
                       delay: float = 0.1,
                       scratch_deletes: int = DEFAULT_SCRATCH_DELETES,
                       keepalive_s: float = DEFAULT_KEEPALIVE_S,
                       ts_writer: Optional["EvalTimestampWriter"] = None) -> dict:
    """Drive the running eBPF sensor toward layer=entropy ONLY.

    Phase A: overwrite documents in place with banded high-entropy content
             (sequential, no rename) and keep their fds OPEN.
    Phase B: create + rapidly DELETE scratch files → push the proc score across
             SCORE_ALERT(50) so behavior_events fires on an unlink.
    Phase C: sleep (no writes) so the PID is alive for the containment pipeline.
    """
    docs = _select_documents(root, max_files)
    open_fds: List[int] = []
    stats = {"overwritten": 0, "scratch_deleted": 0, "entropies": [],
             "documents": [str(d) for d in docs]}

    try:
        # ---- Phase A: in-place high-entropy sequential overwrites -----------
        for doc in docs:
            if doc.name.startswith(CANARY_PREFIXES):   # defense in depth
                continue
            buf, ent = make_banded_content()
            stats["entropies"].append(round(ent, 3))
            # Side-channel: the first in-place overwrite is t0 (§0.3).
            if ts_writer is not None:
                ts_writer.touch(str(doc), "write")
            # r+b keeps the SAME inode (true in-place); single write from 0 is
            # sequential, so the write-offset nonseq counter never climbs past 1.
            fd = os.open(str(doc), os.O_RDWR)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, buf)
            os.ftruncate(fd, len(buf))
            os.fsync(fd)                 # flush so observe() reads high entropy
            open_fds.append(fd)          # keep OPEN → /proc/fd sampling target
            stats["overwritten"] += 1
            if delay > 0:
                time.sleep(delay)

        # ---- Phase B: rapid scratch deletes → fire behavior_events ----------
        # Fast and tight so del_per_sec >= 2 holds when the score crosses 50.
        scratch_dir = Path(root) / SCRATCH_DIRNAME
        scratch_dir.mkdir(parents=True, exist_ok=True)
        scratch_paths: List[Path] = []
        for i in range(scratch_deletes):
            sp = scratch_dir / f"scratch_{i:03d}.tmp"
            # Low-entropy junk, written sequentially to a fresh inode, then
            # CLOSED before the delete burst so the only open regular fds during
            # the unlinks are the high-entropy docs.
            with open(sp, "wb") as fh:
                fh.write(b"scratch-data " * 64)
            scratch_paths.append(sp)
        for sp in scratch_paths:         # the delete burst (no per-op delay)
            try:
                if ts_writer is not None:
                    ts_writer.touch(str(sp), "delete")
                os.unlink(sp)
                stats["scratch_deleted"] += 1
            except OSError:
                pass

        # ---- Phase C: stay alive for SIGSTOP→isolate→SIGKILL ----------------
        # No further writes (avoids any nonseq buildup); just hold the docs open
        # until the agent contains us or the keep-alive budget elapses.
        deadline = time.time() + keepalive_s
        while time.time() < deadline:
            time.sleep(0.2)
    finally:
        for fd in open_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    return stats


# --------------------------------------------------------------------------- #
# Offline negative-space validation (no root): prove the OTHER layers stay
# silent and the entropy band holds, so live detection can only be layer=entropy.
# --------------------------------------------------------------------------- #

def validate_defense(target: str) -> int:
    with Sandbox(target) as sb:
        sb.arm()
        engine = build_validation_engine(sb.root_real)
        doc = sb.corpus_files()[0]
        p = sb.assert_inside(doc)
        inode = p.stat().st_ino

        buf, ent = make_banded_content()
        # Single sequential in-place write from offset 0.
        with open(p, "r+b") as fh:
            fh.seek(0)
            fh.write(buf)
            fh.truncate()
            fh.flush()
            os.fsync(fh.fileno())

        # (1) write-offset layer must NOT fire on a sequential write. First write
        #     to the inode is the baseline; offset == prev end keeps nonseq at 0.
        wo_evt = engine.observe_write_offset(
            ATTACKER_PID, ATTACKER_PPID, "entropy-sim",
            inode, 0, len(buf), str(p), ts=1.0,
        )
        write_offset_silent = wo_evt is None

        # (2) entropy band: gate floor 6.5 <= E, AND E < 7.2 (else live entropy_fn
        #     returns delta=0 and the gate fails), AND E < 7.0 (burst-entropy off).
        measured = file_entropy(str(p))
        in_band = 6.5 <= measured < 7.0

        # (3) no rename issued; target is not a canary.
        no_canary = not p.name.startswith(CANARY_PREFIXES)

        ok = write_offset_silent and in_band and no_canary
        result = DefenseResult(
            family=NAME,
            defense="entropy layer necessity (negative space)",
            signal="layer=entropy (live-only via _handle_behavior)",
            fired=ok,
            files_harmed=0,                      # audited on Sandbox __exit__
            detail={
                "content_entropy_target": f"[{ENTROPY_TARGET_LO},{ENTROPY_TARGET_HI})",
                "content_entropy_generated": round(ent, 3),
                "on_disk_entropy_measured": round(measured, 3),
                "entropy_in_band[6.5,7.0)": in_band,
                "write_offset_layer_silent": write_offset_silent,
                "renames_issued": 0,
                "canary_touched": False,
                "note": "live containment (layer=entropy) is observable only "
                        "under the running eBPF sensor via behavior_events + "
                        "_handle_behavior; this offline check proves the "
                        "competing layers stay silent so it is the sole path.",
            },
        )
    print(result.banner())
    return 0 if result.fired else 1


# --------------------------------------------------------------------------- #
# Live main (mirrors sim_common.main_for: git guard + backup/restore)
# --------------------------------------------------------------------------- #

def live_main(ap: argparse.ArgumentParser) -> int:
    args = ap.parse_args()
    root = args.target

    if not os.path.isdir(root):
        print(f"[{NAME}] creating target dir: {root}")
        os.makedirs(root, exist_ok=True)
        populate_corpus(root)

    # Refuse to operate inside a git repo (canaries/scratch could corrupt refs).
    check = Path(root).resolve()
    for _ in range(10):
        if (check / ".git").is_dir():
            print(f"[{NAME}] ERROR: target {root} is inside a git repo — aborting")
            return 1
        if check.parent == check:
            break
        check = check.parent

    backup = _backup_corpus(root)
    print(f"[{NAME}] backup at {backup}")
    print(f"[{NAME}] starting entropy-only simulation | max_files={args.max_files} "
          f"delay={args.delay}")

    ts_writer = None
    if getattr(args, "eval_timestamps", None):
        ts_writer = EvalTimestampWriter(args.eval_timestamps)
        ts_writer.start(os.getpid())

    try:
        stats = run_entropy_attack(
            root,
            max_files=args.max_files if args.max_files is not None else DEFAULT_MAX_FILES,
            delay=args.delay if args.delay is not None else 0.1,
            ts_writer=ts_writer,
        )
    finally:
        if ts_writer is not None:
            ts_writer.close()
        # Remove scratch dir before restore (it post-dates the backup anyway).
        shutil.rmtree(Path(root) / SCRATCH_DIRNAME, ignore_errors=True)
        if not args.no_restore:
            _restore_corpus(root, backup)
            print(f"[{NAME}] corpus restored")
        else:
            print(f"[{NAME}] --no-restore: high-entropy overwrites left in place")
            shutil.rmtree(backup, ignore_errors=True)

    print(f"[{NAME}] done | overwritten={stats['overwritten']} "
          f"scratch_deleted={stats['scratch_deleted']} "
          f"entropies={stats['entropies']}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Entropy-only behavioural simulator (safe) — caught ONLY by "
                    "the entropy layer (_handle_behavior, layer=entropy)")
    add_common_args(ap)
    ap.add_argument("--validate-defense", action="store_true",
                    help="offline negative-space validation: prove the "
                         "write-offset/rename/canary layers stay silent and the "
                         "content entropy is in [6.5,7.0) (no root/BCC needed)")
    args, _ = ap.parse_known_args()
    if args.validate_defense:
        raise SystemExit(validate_defense(args.target))
    _set_comm("entropy-sim")
    raise SystemExit(live_main(ap))
