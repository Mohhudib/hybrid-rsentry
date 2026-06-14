"""
sim_common.py — shared simulation engine for Hybrid R-Sentry behavioural sims.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import string
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


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


def _set_comm(name: str) -> None:
    """Set the kernel process comm (PR_SET_NAME) so eBPF sees a sim-specific name,
    not 'python3', which is filtered from alerts by the monitor's IGNORE_COMMS."""
    try:
        import ctypes
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(
            15, name.encode()[:15], 0, 0, 0)
    except Exception:
        pass


class EvalTimestampWriter:
    """Evaluation side-channel (docs/evaluation-design.md §0.3 / §0.5).

    Writes JSONL on the CLOCK_MONOTONIC clock (``time.monotonic_ns``) — the SAME
    clock the harness reads, and which is system-wide on Linux, so the sim's t0 /
    per-touch timestamps are directly comparable with the harness's stage
    timestamps across processes. Opt-in: created only when --eval-timestamps is
    given, so default sim behaviour is unchanged. Emits one record per line:
        {"event":"start","ts_ns":..,"pid":..}
        {"event":"touch","ts_ns":..,"op":"encrypt","path":".."}   # first == t0
    Never raises into the attack path — a side-channel failure must not perturb
    what the sensor observes.
    """

    def __init__(self, path: str) -> None:
        # The side-channel is best-effort enrichment and MUST NOT perturb the
        # attack path. If the file cannot be opened (e.g. a permission issue on
        # the harness-provided path), degrade to a no-op writer rather than
        # raising — a raising __init__ here would abort the sim before any file
        # op and make the sensor observe silence.
        try:
            self._fh = open(path, "a", buffering=1)        # line-buffered
        except OSError:
            self._fh = None

    def start(self, pid: int) -> None:
        self._emit("start", pid=pid)

    def touch(self, path: str, op: str) -> None:
        """Record one malicious file-touch. The FIRST touch is t0 (§0.3)."""
        self._emit("touch", path=path, op=op)

    def _emit(self, event: str, **kw) -> None:
        if self._fh is None:
            return
        try:
            self._fh.write(json.dumps({"event": event,
                                       "ts_ns": time.monotonic_ns(), **kw}) + "\n")
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Corpus helpers
# ---------------------------------------------------------------------------

CORPUS_EXTS = [".docx", ".xlsx", ".pdf", ".txt", ".jpg", ".db", ".vmdk", ".vmx"]


def populate_corpus(root: str, dirs: int = 8, depth: int = 4,
                    files_per_dir: int = 6) -> List[str]:
    """Create a synthetic file tree under root. Returns list of created files."""
    root_p = Path(root)
    root_p.mkdir(parents=True, exist_ok=True)
    if any(p for p in root_p.iterdir() if not p.name.startswith(".")):
        raise ValueError(
            f"populate_corpus: target directory {root!r} is non-empty — "
            "pass an empty or non-existent directory to avoid overwriting real files."
        )
    created = []

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
                if skip_aaa and os.path.basename(fp).startswith(("AAA_", "aaa_", "ZZZ_", "zzz_")):
                    continue
                all_files.append(fp)

    elif traversal == "random":
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                if skip_aaa and os.path.basename(fp).startswith(("AAA_", "aaa_", "ZZZ_", "zzz_")):
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
                if skip_aaa and os.path.basename(fp).startswith(("AAA_", "aaa_", "ZZZ_", "zzz_")):
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

    Write geometry: every mode overwrites the file IN PLACE (same inode) and
    then issues a real ``os.rename()`` to append the family extension. The rename
    is what real Linux ransomware does to "claim" an encrypted file, and it is
    the syscall the eBPF ``kprobe__vfs_rename`` probe captures. The earlier
    ``write_bytes(new_file) + unlink(original)`` pattern created a FRESH inode
    written sequentially and emitted NO rename, so neither the rename/extension
    detector nor the write-offset detector ever fired on the live kernel.
    """
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = p.read_bytes()
    except OSError:
        return None

    if profile.mode == "two_pass":
        # LockBit 5.0 two-pass write: a quick partial pass then a thorough pass,
        # BOTH overwriting the original in place (same inode). The original file
        # MUST survive until the final os.rename — never unlink before the rename
        # or the rename has nothing to move.
        partial = _encrypt_percent(data, 30)
        full = _encrypt_full(partial)
        new_path = str(p) + "." + profile.ext_fn()
        try:
            p.write_bytes(partial)            # pass 1 — in-place overwrite
            p.write_bytes(full)               # pass 2 — in-place overwrite
            os.rename(str(p), new_path)       # rename → vfs_rename, 16-char ext
        except OSError:
            return None
        return new_path

    if profile.mode == "full":
        enc = _encrypt_full(data)
    elif profile.mode == "intermittent":
        enc = _encrypt_intermittent(data, profile.block, profile.step)
    elif profile.mode == "percent":
        enc = _encrypt_percent(data, profile.percent)
    else:
        enc = _encrypt_full(data)

    new_path = str(p) + "." + profile.ext_fn()
    try:
        p.write_bytes(enc)                    # in-place overwrite (same inode)
        os.rename(str(p), new_path)           # rename → vfs_rename fires
    except OSError:
        return None
    return new_path


# ---------------------------------------------------------------------------
# Backup / restore
# ---------------------------------------------------------------------------

def _backup_corpus(root: str) -> str:
    backup = tempfile.mkdtemp(prefix="rsentry_backup_")
    dest = os.path.join(backup, "corpus")
    shutil.copytree(root, dest)
    src_count = sum(1 for p in Path(root).rglob("*") if p.is_file())
    dst_count = sum(1 for p in Path(dest).rglob("*") if p.is_file())
    if dst_count < src_count:
        shutil.rmtree(backup, ignore_errors=True)
        raise RuntimeError(
            f"Corpus backup incomplete: {dst_count}/{src_count} files copied to {dest}"
        )
    return backup


def _restore_corpus(root: str, backup: str) -> None:
    corpus_backup = os.path.join(backup, "corpus")
    if not os.path.exists(corpus_backup) or not any(Path(corpus_backup).iterdir()):
        raise RuntimeError(
            f"Corpus backup at {corpus_backup!r} is empty or missing — "
            f"refusing to overwrite {root!r}"
        )
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
               skip_aaa: bool = False, max_files: Optional[int] = None,
               delay: Optional[float] = None,
               ts_writer: Optional["EvalTimestampWriter"] = None) -> Manifest:
    manifest = Manifest()
    manifest.t_start = time.perf_counter()

    targets = enumerate_targets(root, traversal, skip_aaa=skip_aaa)
    targets = _prioritise(targets, profile.priority_exts)
    # Safety cap: bound the number of files touched per run (avoids the VM hang a
    # very large write/rename storm caused). None == no cap (legacy behaviour).
    if max_files is not None:
        targets = targets[:max_files]

    # Per-file pacing: --delay overrides the profile default. Used by the live
    # detection test to keep the sim alive long enough for the audit-mode
    # SIGSTOP response to land on a running PID.
    eff_delay = profile.delay if delay is None else delay

    for path in targets:
        # Side-channel: record the first file-touch (t0) and every subsequent
        # touch, immediately BEFORE the mutation, so the timestamp precedes the
        # syscall the sensor sees.
        if ts_writer is not None:
            ts_writer.touch(path, "encrypt")
        new_path = _simulate_file(path, profile)
        if new_path:
            manifest.encrypted.append(new_path)
        else:
            manifest.errors.append(path)
        if eff_delay > 0:
            time.sleep(eff_delay)

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
    ap.add_argument("--max-files",  type=int, default=None,
                    help="cap the number of files touched per run (safety bound; "
                         "keep <=50 on a VM to avoid a write/rename-storm hang)")
    ap.add_argument("--delay",      type=float, default=None,
                    help="per-file delay in seconds (overrides the profile "
                         "default; lets a live sensor act on a running PID)")
    ap.add_argument("--eval-timestamps", default=None, metavar="PATH",
                    help="evaluation side-channel: write t0 + per-file-touch "
                         "monotonic_ns timestamps as JSONL to PATH (harness use)")


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

    ts_writer = None
    if getattr(args, "eval_timestamps", None):
        ts_writer = EvalTimestampWriter(args.eval_timestamps)
        ts_writer.start(os.getpid())

    try:
        manifest = run_attack(root, profile,
                              traversal=args.traversal,
                              skip_aaa=args.skip_aaa,
                              max_files=args.max_files,
                              delay=args.delay,
                              ts_writer=ts_writer)
    finally:
        if ts_writer is not None:
            ts_writer.close()
        if not args.no_restore:
            _restore_corpus(root, backup)
            print(f"[{profile.name}] corpus restored")
        else:
            print(f"[{profile.name}] --no-restore: files left encrypted")

    s = manifest.summary()
    print(f"[{profile.name}] done | encrypted={s['encrypted']} "
          f"errors={s['errors']} elapsed={s['elapsed_s']}s")
    return 0


# ===========================================================================
# Session 09 — sandbox-guarded defense validation harness
# ---------------------------------------------------------------------------
# The legacy run_attack() path (above) drives the *running* eBPF sensor by
# manipulating files on disk. The validation harness below is for environments
# without root/BCC: each family performs the SAME safe, non-destructive file
# operations inside a sentinel-guarded sandbox AND feeds the equivalent events
# into the userspace DetectionEngine (the unit-testable "source of truth" per
# session_08), so we can assert the matching defense fires without loading any
# kernel program.
#
# Safety invariants enforced here, not left to the caller:
#   * The directory must carry a .rsentry_sandbox sentinel — we refuse to touch
#     any directory that is not an R-Sentry sandbox.
#   * Every path operated on is asserted (via realpath) to live inside the
#     sandbox; an out-of-sandbox path raises SandboxViolation and aborts.
#   * The whole tree is hashed + backed up before the run and restored after,
#     then a byte-for-byte integrity audit confirms zero real files were harmed.
# ===========================================================================

SANDBOX_SENTINEL = ".rsentry_sandbox"

# A synthetic attacker PID used when feeding the DetectionEngine. It must differ
# from the engine's self_pid (we pass os.getpid() as self_pid) so the sim is not
# mistaken for the monitor itself and suppressed.
ATTACKER_PID = 0xA77AC      # 686508
ATTACKER_PPID = 0xA77AB     # 686507


class SandboxViolation(RuntimeError):
    """Raised when an operation targets a path outside the sandbox."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Sandbox:
    """Guarded scratch directory for safe ransomware-behaviour simulation.

    Usage::

        with Sandbox("/tmp/rsentry_sandbox") as sb:
            sb.arm()                     # snapshot + backup before any mutation
            p = sb.assert_inside(target) # raises if target escapes the sandbox
            ...                          # safe, non-destructive operations
        # on exit: corpus restored from backup + integrity audited

    The context manager creates the directory (if absent), writes the
    .rsentry_sandbox sentinel, and populates a synthetic corpus. It refuses to
    adopt a pre-existing non-empty directory that lacks the sentinel, so it can
    never be pointed at real user data by accident.
    """

    def __init__(self, root: str, files: int = 24):
        self.root = Path(root)
        self.root_real = ""               # set in __enter__
        self._n_files = files
        self._armed = False
        self._backup = ""                 # tempdir holding the pristine copy
        self._baseline: Dict[str, str] = {}   # relpath -> sha256 snapshot
        self.corpus: List[Path] = []

    # -- lifecycle ------------------------------------------------------
    def __enter__(self) -> "Sandbox":
        sentinel = self.root / SANDBOX_SENTINEL
        if self.root.exists():
            non_hidden = [p for p in self.root.iterdir()
                          if not p.name.startswith(".")]
            if non_hidden and not sentinel.exists():
                raise SandboxViolation(
                    f"{self.root} is non-empty and has no {SANDBOX_SENTINEL} "
                    "sentinel — refusing to use it as a sandbox."
                )
        self.root.mkdir(parents=True, exist_ok=True)
        # Refuse to operate inside a git repo (canaries/renames corrupt refs).
        check = self.root.resolve()
        for _ in range(12):
            if (check / ".git").is_dir():
                raise SandboxViolation(
                    f"{self.root} is inside a git repo ({check}) — aborting."
                )
            if check.parent == check:
                break
            check = check.parent
        sentinel.write_text(
            f"R-Sentry simulation sandbox\npid={os.getpid()}\n"
            f"created={time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
        )
        self.root_real = os.path.realpath(self.root)
        self._populate()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            if self._armed:
                self._restore()
                self.audit()
        finally:
            if self._backup and os.path.isdir(self._backup):
                shutil.rmtree(self._backup, ignore_errors=True)
        return False  # never swallow exceptions

    # -- setup ----------------------------------------------------------
    def _populate(self) -> None:
        """Create fresh synthetic corpus files (only if the sandbox is empty of
        corpus). Each file gets non-trivial size so entropy/offset writes are
        meaningful. These are throwaway generated files — never real data."""
        existing = [p for p in self.root.rglob("*")
                    if p.is_file() and p.name != SANDBOX_SENTINEL]
        if existing:
            self.corpus = sorted(existing)
            return
        sub = self.root / "documents"
        sub.mkdir(exist_ok=True)
        exts = [".docx", ".xlsx", ".pdf", ".db", ".jpg", ".vmdk"]
        created = []
        for i in range(self._n_files):
            ext = exts[i % len(exts)]
            f = sub / f"corpus_{i:03d}{ext}"
            # Low-entropy, compressible body so a later high-entropy in-place
            # rewrite is a clear entropy *jump* (mirrors a real document).
            f.write_bytes((f"document-{i} ".encode() * 4096)[:32768])
            created.append(f)
        self.corpus = sorted(created)

    def arm(self) -> None:
        """Snapshot (sha256) every file under root and back the tree up. Must be
        called after all setup (incl. canary placement) and before any mutation;
        restore + integrity audit on exit depend on it."""
        if self._armed:
            return
        self._baseline = {
            os.path.relpath(p, self.root): _sha256(p)
            for p in self.root.rglob("*") if p.is_file()
        }
        self._backup = tempfile.mkdtemp(prefix="rsentry_sandbox_bk_")
        dest = os.path.join(self._backup, "tree")
        shutil.copytree(self.root, dest)
        self._armed = True

    # -- guards ---------------------------------------------------------
    def assert_inside(self, path) -> Path:
        """Resolve path and assert it lives inside the sandbox. Returns the Path.
        Raises SandboxViolation otherwise — the hard guard required for every
        file operation in every simulation step."""
        rp = os.path.realpath(path)
        if rp != self.root_real and not rp.startswith(self.root_real + os.sep):
            raise SandboxViolation(
                f"path {path!r} (-> {rp}) is OUTSIDE sandbox {self.root_real}"
            )
        return Path(path)

    def corpus_files(self) -> List[Path]:
        """Current non-canary, non-sentinel corpus files under the sandbox."""
        out = []
        for p in sorted(self.root.rglob("*")):
            if not p.is_file():
                continue
            if p.name == SANDBOX_SENTINEL:
                continue
            if p.name.startswith(("AAA_", "aaa_", "ZZZ_", "zzz_")):
                continue
            out.append(self.assert_inside(p))
        return out

    # -- teardown -------------------------------------------------------
    def _restore(self) -> None:
        src = os.path.join(self._backup, "tree")
        if not os.path.isdir(src) or not os.listdir(src):
            raise SandboxViolation(
                f"backup at {src!r} is empty/missing — refusing to wipe {self.root}"
            )
        # Only ever remove our own (sentinel-bearing) sandbox.
        self.assert_inside(self.root)
        shutil.rmtree(self.root)
        shutil.copytree(src, self.root)

    def audit(self) -> int:
        """Re-hash every baseline file after restore and confirm it matches.
        Returns the number of harmed files (0 == success). Raises if anything
        differs, so a botched restore can never pass silently."""
        harmed = 0
        for rel, digest in self._baseline.items():
            p = self.root / rel
            if not p.is_file() or _sha256(p) != digest:
                harmed += 1
        if harmed:
            raise SandboxViolation(
                f"integrity audit FAILED: {harmed} file(s) not byte-for-byte "
                f"restored under {self.root}"
            )
        return harmed


# ---------------------------------------------------------------------------
# DetectionEngine validation helpers
# ---------------------------------------------------------------------------

def file_entropy(path: str) -> float:
    """Shannon entropy (bits/byte) of a file's first 64 KB — used as the
    engine's entropy_fn so emitted events carry a realistic entropy_delta."""
    try:
        data = Path(path).read_bytes()[:65536]
    except OSError:
        return 0.0
    if not data:
        return 0.0
    from math import log2
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * log2(c / n) for c in counts if c)


def build_validation_engine(sandbox_root: str,
                            canary_paths: Optional[List[str]] = None):
    """Construct a DetectionEngine wired to the sandbox for offline validation.
    self_pid is this process so the synthetic ATTACKER_PID is never suppressed
    as 'the monitor itself'."""
    from agent.monitor_ebpf import DetectionEngine
    return DetectionEngine(
        host_id="SIM09",
        watch_dirs=[os.path.realpath(sandbox_root)],
        canary_paths=canary_paths or [],
        velocity_threshold=2,
        self_pid=os.getpid(),
        entropy_fn=file_entropy,
    )


@dataclass
class DefenseResult:
    family: str
    defense: str
    signal: str
    fired: bool
    files_harmed: int
    detail: Dict[str, object] = field(default_factory=dict)

    def banner(self) -> str:
        status = "TRIGGERED" if self.fired else "NOT DETECTED"
        mark = "✓" if self.fired and self.files_harmed == 0 else "✗"
        lines = [
            f"[{self.family}] {mark} defense={self.defense} "
            f"signal={self.signal} -> {status}",
            f"[{self.family}]   files_harmed={self.files_harmed}",
        ]
        for k, v in self.detail.items():
            lines.append(f"[{self.family}]   {k}={v}")
        return "\n".join(lines)
