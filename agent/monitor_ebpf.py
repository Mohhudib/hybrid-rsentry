#!/usr/bin/env python3
"""
monitor_ebpf.py — eBPF-based ransomware sensor for Hybrid R-Sentry.

Two kernel probes:
  kprobe__vfs_rename   — captures every file rename system-wide (Option A)
  kprobe__vfs_write    — tracks writes to watched inodes (canary write detection)

Userspace DetectionEngine:
  - Velocity burst counter (sliding window, threshold=2 → alert at file #2)
  - Canary touch detection (AAA_/zzz_ prefix or registered path)
  - Family profiling (Akira / LockBit5 / ESXi-targeting heuristics)
  - Markov suppress_path() for adaptive.py canary moves
  - IGNORE_COMMS set for FP suppression

BPF-LSM inline block (-EPERM) when lsm=bpf kernel is active.
Fallback: SIGSTOP via contain() callback.

Run modes:
    python3 monitor_ebpf.py --selftest
    python3 monitor_ebpf.py --print-bpf
    python3 monitor_ebpf.py --seed-canaries --seed-into ~/Documents --dry-run-seed
    sudo -E python3 monitor_ebpf.py --mode audit
    sudo -E python3 monitor_ebpf.py
"""
from __future__ import annotations

import argparse
import math
import os
import re
import shutil
import sys
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# IGNORE_COMMS — never alert or contain these process names
# ---------------------------------------------------------------------------
IGNORE_COMMS: Set[str] = {
    "Xorg", "gnome-shell", "nautilus", "systemd", "systemd-journal", "systemd-resolve", "systemd-network",
    "redis-server", "postgres", "celery", "uvicorn",
    "git", "cargo", "rsync", "make", "gcc", "cc1", "ld", "NetworkManager", "nm-dispatcher", "StreamTrans",
    "runc", "containerd", "containerd-shi", "dockerd", "docker",
    # TODO(security review): browsers are user-space apps, not system daemons —
    # comm is attacker-controllable (prctl/argv0), so malware can masquerade as
    # "firefox" to bypass detection. Kept for now as documented FP sources
    # (cache churn); consider replacing with exe-path/lineage-based exemption.
    "x-www-browser", "firefox", "firefox-esr", "chrome", "chromium",
    "dpkg", "apt", "apt-get",
    "Cache2 I/O", "glean.dispatch",  # BPF comm is 15 chars; "glean.dispatche" was truncated
}

# Extensions that look like encryption output
_ENC_SUFFIXES: Set[str] = {
    ".enc", ".encrypted", ".locked", ".crypto", ".crypt",
    ".aes", ".aes256", ".wcry", ".wncry",
    ".akira", ".akiranew", ".powerranges",
    ".ryk", ".ryuk", ".dharma", ".wallet",
}

# Extensions ransomware typically prioritises
_PRIORITY_EXTS: Set[str] = {
    ".vmdk", ".vmx", ".vmsn", ".vmem", ".vhd",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf",
    ".db", ".sqlite", ".sql", ".edb",
}

# Benign rename suffixes — never alert on these
_BENIGN_SUFFIXES: Set[str] = {
    ".bak", ".tmp", ".log", ".swp", ".part",
    ".orig", ".old", ".backup",
}

# Minimum Shannon entropy (bits/char) for an extension to look machine-generated.
# Real-world extensions are short, low-entropy mnemonics (.docx≈2.0, .pdf≈1.58,
# .xlsx≈1.5); ransomware appends random strings (.x7k2p9qm≈3.0, 16-char≈4.0).
_EXT_ENTROPY_THRESHOLD = 2.5


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per symbol) of a string. 0.0 for empty input."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Userspace detection logic. No BCC/kernel dependency — fully unit-testable.
    """

    def __init__(
        self,
        host_id: str,
        watch_dirs: List[str],
        canary_paths: Optional[List[str]] = None,
        velocity_threshold: int = 2,
        window_seconds: float = 3.0,
        self_pid: int = 0,
        ignore_comms: Optional[Set[str]] = None,
        lineage_fn: Optional[Callable[[int], float]] = None,
        entropy_fn: Optional[Callable[[str], float]] = None,
    ):
        self.host_id = host_id
        self.watch_dirs = [os.path.normpath(d) for d in watch_dirs]
        self.canary_paths: Set[str] = set()
        self.canary_inodes: Set[int] = set()
        self.velocity_threshold = velocity_threshold
        self.window_seconds = window_seconds
        self.self_pid = self_pid
        self.ignore_comms = (ignore_comms or set()) | IGNORE_COMMS
        self.lineage_fn = lineage_fn
        self.entropy_fn = entropy_fn

        # Velocity tracking: pid -> deque of timestamps
        self._velocity: Dict[int, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )
        # Recent destination paths per pid — feeds _profile_family's ESXi
        # heuristic (must be paths, not the velocity timestamp deque).
        self._path_history: Dict[int, deque] = defaultdict(
            lambda: deque(maxlen=10)
        )
        # PIDs armed after velocity burst (watch their writes too)
        self._active_pids: Set[int] = set()
        # Suppressed paths (Markov moves) path -> expiry_ts
        self._suppressed: Dict[str, float] = {}
        # Cooldown: pid -> last_alert_ts
        self._cooldown: Dict[int, float] = {}
        self._cooldown_secs = 2.0

        if canary_paths:
            self.register_canaries(canary_paths)

        # Per-instance write tracking (must NOT be class-level — selftests
        # create 15 instances and class-level dicts would share state)
        self._inode_path_cache: dict = {}
        self._write_burst: dict = {}

        # Write-offset tracking for silent-encryption detection (Feature 1).
        # pid -> {inode: last_end_offset}; consecutive non-sequential writes
        # (offset != previous end) are the signature of in-place block-cipher
        # rewrites that never change the file size or extension.
        self._write_offsets: Dict[int, Dict[int, int]] = defaultdict(dict)
        self._nonseq_count: Dict[int, int] = defaultdict(int)
        # PIDs frozen (kernel-blocked) by a hardening rule — kept so callers
        # can confirm a containment decision was taken.
        self._frozen_pids: Set[int] = set()

    # ------------------------------------------------------------------
    # Canary registration
    # ------------------------------------------------------------------

    def register_canaries(self, paths: List[str]) -> None:
        for p in paths:
            np = os.path.normpath(p)
            self.canary_paths.add(np)
            try:
                self.canary_inodes.add(os.stat(np).st_ino)
            except OSError:
                pass

    def _is_canary(self, path: str) -> bool:
        np = os.path.normpath(path)
        if np in self.canary_paths:
            return True
        bn = os.path.basename(np)
        if bn.startswith(("AAA_", "aaa_", "ZZZ_", "zzz_")):
            return True
        try:
            return os.stat(np).st_ino in self.canary_inodes
        except OSError:
            return False

    def _is_canary_inode(self, inode: int) -> bool:
        return inode in self.canary_inodes

    # ------------------------------------------------------------------
    # Suppression (Markov moves)
    # ------------------------------------------------------------------

    def suppress_path(self, path: str, ttl: float = 15.0) -> None:
        self._suppressed[os.path.normpath(path)] = time.monotonic() + ttl

    def _is_suppressed(self, path: str) -> bool:
        exp = self._suppressed.get(os.path.normpath(path))
        if exp is None:
            return False
        if time.monotonic() > exp:
            del self._suppressed[os.path.normpath(path)]
            return False
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _in_watch_dir(self, path: str) -> bool:
        np = os.path.normpath(path)
        return any(np.startswith(d + os.sep) or np == d
                   for d in self.watch_dirs)

    def _looks_encrypted(self, path: str) -> bool:
        suffix = Path(path).suffix.lower()
        if suffix in _BENIGN_SUFFIXES:
            return False
        if suffix in _ENC_SUFFIXES:
            return True
        # Feature 2: entropy-based detection. Replaces the old fixed 8-16 char
        # length filter — flag any alphanumeric extension whose Shannon entropy
        # is high enough to look machine-generated, regardless of length.
        # Normal extensions (.docx≈2.0, .pdf≈1.58) stay below the threshold.
        ext = Path(path).suffix.lstrip(".")
        if ext and re.match(r'^[a-zA-Z0-9]+$', ext):
            if _shannon_entropy(ext) >= _EXT_ENTROPY_THRESHOLD:
                return True
        return False

    def _profile_family(self, path: str, pid_history: List[str]) -> str:
        ext = Path(path).suffix.lower()
        if ext in (".akira", ".akiranew"):
            return "akira"
        if len(ext.lstrip(".")) == 16:
            return "lockbit5"
        if any(Path(p).suffix.lower() in (".vmdk", ".vmx", ".vmsn")
               for p in pid_history[-5:]):
            return "esxi-targeting"
        if ext in _ENC_SUFFIXES:
            return "generic-ransomware"
        return "unknown"

    def _make_event(
        self,
        event_type: str,
        severity: str,
        pid: int,
        ppid: int,
        comm: str,
        src_path: str,
        dst_path: str,
        ts: float,
        extra: Optional[dict] = None,
        lineage_score: float = 0.0,
        entropy_delta: float = 0.0,
    ) -> dict:
        import datetime
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        iso = dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        # Only compute if not pre-supplied
        if lineage_score == 0.0 and self.lineage_fn and pid > 0:
            try:
                lineage_score = float(self.lineage_fn(pid))
            except Exception:
                pass
        if entropy_delta == 0.0 and self.entropy_fn and dst_path:
            try:
                entropy_delta = float(self.entropy_fn(dst_path))
            except Exception:
                pass
        details: dict = {"sensor": "ebpf", "decided_in": "userspace"}
        if extra:
            details.update(extra)

        return {
            "host_id":       self.host_id,
            "timestamp":     iso,
            "event_type":    event_type,
            "severity":      severity,
            "pid":           pid,
            "process_name":  comm,
            "file_path":     dst_path or src_path,
            "lineage_score": round(lineage_score, 2),
            "entropy_delta": round(entropy_delta, 4),
            "canary_hit":    event_type == "CANARY_TOUCHED",
            "details":       details,
        }

    def _severity(
        self,
        canary_hit: bool,
        lineage_score: float,
        entropy_delta: float,
    ) -> str:
        combined = lineage_score * 0.6 + (entropy_delta / 8.0) * 100 * 0.4
        if canary_hit:
            return "CRITICAL"
        if combined >= 70:
            return "CRITICAL"
        if combined >= 40:
            return "HIGH"
        if entropy_delta > 3.5:
            return "MEDIUM"
        return "LOW"


    # ------------------------------------------------------------------
    # Core observation methods
    # ------------------------------------------------------------------

    def observe_rename(
        self,
        pid: int,
        ppid: int,
        comm: str,
        src_path: str,
        dst_path: str,
        ts: float,
    ) -> Optional[dict]:
        # Self-PID exclusion
        if pid == self.self_pid:
            return None
        # IGNORE_COMMS
        if comm in self.ignore_comms:
            return None
        # Suppressed path (Markov move)
        if self._is_suppressed(src_path) or self._is_suppressed(dst_path):
            return None
        # Benign suffix → never alert
        if Path(dst_path).suffix.lower() in _BENIGN_SUFFIXES:
            return None

        in_scope = self._in_watch_dir(src_path) or self._in_watch_dir(dst_path)

        # Canary hit — highest priority
        if self._is_canary(src_path) or self._is_canary(dst_path):
            # Fast path: CANARY_TOUCHED fires immediately with no scoring
            # lineage/entropy computed async after the fact
            import datetime as _dt
            _ts = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
            _iso = _ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            # Compute entropy only (fast, local) — skip lineage (requires /proc lookup)
            _entropy = 0.0
            if self.entropy_fn and dst_path:
                try:
                    _entropy = float(self.entropy_fn(dst_path))
                except Exception:
                    pass
            evt = {
                "host_id":       self.host_id,
                "timestamp":     _iso,
                "event_type":    "CANARY_TOUCHED",
                "severity":      "CRITICAL",
                "pid":           pid,
                "process_name":  comm,
                "file_path":     dst_path,
                "lineage_score": 0.0,
                "entropy_delta": _entropy,
                "canary_hit":    True,
                "details": {
                    "sensor":        "ebpf",
                    "decided_in":    "userspace",
                    "src":           src_path,
                    "dst":           dst_path,
                    "outside_watch": not in_scope,
                },
            }
            self._active_pids.add(pid)
            return evt

        # Only track encrypted-looking renames
        if not self._looks_encrypted(dst_path):
            return None

        # Option A: capture system-wide encrypted renames
        out_of_scope = not in_scope

        # Velocity tracking
        self._velocity[pid].append(ts)
        window_start = ts - self.window_seconds
        recent = [t for t in self._velocity[pid] if t >= window_start]
        self._velocity[pid] = deque(recent, maxlen=200)

        if len(recent) < self.velocity_threshold:
            return None

        # Cooldown check — only suppress repeat alerts, not the first one
        last = self._cooldown.get(pid)
        if last is not None and ts - last < self._cooldown_secs:
            return None
        self._cooldown[pid] = ts

        # Build event
        lineage_score = 0.0
        entropy_delta = 0.0
        if self.lineage_fn and pid > 0:
            try:
                _result = self.lineage_fn(pid)
                lineage_score = float(_result)
            except Exception as _e:
                pass
        if self.entropy_fn and dst_path:
            try:
                entropy_delta = float(self.entropy_fn(dst_path))
            except Exception:
                pass

        sev = self._severity(False, lineage_score, entropy_delta)
        # Track recent destination *paths* (not velocity timestamps) so the
        # ESXi heuristic in _profile_family sees real file paths. Passing the
        # velocity deque here previously crashed on any non-16-char extension
        # (Path() on a float timestamp) — masked only because old fixtures used
        # exactly-16-char extensions that hit the early lockbit5 return.
        self._path_history[pid].append(dst_path)
        profile = self._profile_family(dst_path, list(self._path_history[pid]))

        extra = {
            "src": src_path,
            "dst": dst_path,
            "velocity": len(recent),
            "window_secs": self.window_seconds,
            "profile": profile,
            "outside_watch": out_of_scope,
        }
        if out_of_scope:
            extra["out_of_scope"] = True

        evt = self._make_event(
            "PROCESS_ANOMALY", sev, pid, ppid, comm,
            src_path, dst_path, ts, extra=extra,
            lineage_score=lineage_score,
            entropy_delta=entropy_delta,
        )
        self._active_pids.add(pid)
        return evt

    # inode → path mapping for write monitoring (instance var, see __init__)
    # PID write burst tracking for in-place encryption detection (instance var)
    _WRITE_BURST_THRESHOLD = 10   # 10 writes
    _WRITE_BURST_WINDOW    = 2.0  # in 2 seconds
    _ENTROPY_THRESHOLD     = 7.0  # bits — encrypted content
    # Consecutive non-sequential writes to the same inode before we call it
    # silent encryption. Legitimate apps (editors, databases) seek too, so we
    # require a sustained run rather than a single backward seek.
    _NONSEQ_THRESHOLD      = 5

    def observe_write(
        self,
        pid: int,
        ppid: int,
        comm: str,
        inode: int,
        path: str,
        ts: float,
    ) -> Optional[dict]:
        if pid == self.self_pid:
            return None
        if comm in self.ignore_comms:
            return None

        # Layer 1: Canary inode write → CRITICAL immediately
        if self._is_canary_inode(inode):
            return self._make_event(
                "CANARY_TOUCHED", "CRITICAL", pid, ppid, comm,
                path, path, ts,
                extra={"trigger": "write", "inode": inode},
            )

        # Layer 2: In-place encryption detection (system-wide)
        # Track write burst per PID across multiple inodes
        burst = self._write_burst.get(pid)
        if burst is None or (ts - burst["ts"]) > self._WRITE_BURST_WINDOW:
            burst = {"count": 0, "ts": ts, "inodes": set()}
            self._write_burst[pid] = burst
        burst["count"] += 1
        burst["inodes"].add(inode)

        # Trigger entropy check when burst threshold reached
        if burst["count"] >= self._WRITE_BURST_THRESHOLD and len(burst["inodes"]) >= 3:
            # Check entropy of recently written file
            file_path = path or self._inode_path_cache.get(inode, "")
            if file_path and self.entropy_fn:
                try:
                    entropy = float(self.entropy_fn(file_path))
                    if entropy >= self._ENTROPY_THRESHOLD:
                        # High entropy writes across multiple files = silent encryption
                        burst["count"] = 0  # reset to avoid spam
                        burst["inodes"] = set()
                        return self._make_event(
                            "SILENT_ENCRYPTION", "HIGH", pid, ppid, comm,
                            file_path, file_path, ts,
                            extra={
                                "trigger":       "write_entropy",
                                "inode":         inode,
                                "entropy_bits":  round(entropy, 3),
                                "write_count":   burst["count"],
                                "unique_inodes": len(burst["inodes"]),
                            },
                        )
                except Exception:
                    pass
        return None

    def observe_write_offset(
        self,
        pid: int,
        ppid: int,
        comm: str,
        inode: int,
        offset: int,
        length: int,
        path: str,
        ts: float,
    ) -> Optional[dict]:
        """
        Feature 1 — silent-encryption detection by write-offset pattern.

        Ransomware that encrypts in place (no rename, no new extension) issues a
        read-modify-write storm whose write offsets jump around the file rather
        than advancing sequentially. We track the expected next offset per inode
        and count consecutive non-sequential writes. When a PID crosses
        _NONSEQ_THRESHOLD we emit SILENT_ENCRYPTION and mark the PID frozen so
        the caller arms the in-kernel block (the BPF side mirrors this and sets
        blocked_pids inline; this method is the unit-testable source of truth).
        """
        if pid == self.self_pid:
            return None
        if comm in self.ignore_comms:
            return None

        per_inode = self._write_offsets[pid]
        last_end = per_inode.get(inode)
        per_inode[inode] = offset + length

        # First write to this inode establishes the baseline — never an alert.
        if last_end is None:
            return None

        # Sequential append/overwrite: offset lands exactly where the previous
        # write ended. Anything else is a non-sequential (seek) write.
        if offset == last_end:
            self._nonseq_count[pid] = 0
            return None

        self._nonseq_count[pid] += 1
        if self._nonseq_count[pid] < self._NONSEQ_THRESHOLD:
            return None

        # Sustained non-sequential rewrites → silent encryption.
        self._nonseq_count[pid] = 0
        self._frozen_pids.add(pid)
        self._active_pids.add(pid)
        return self._make_event(
            "SILENT_ENCRYPTION", "HIGH", pid, ppid, comm,
            path, path, ts,
            extra={
                "trigger":     "write_offset",
                "inode":       inode,
                "offset":      offset,
                "length":      length,
                "pattern":     "non_sequential",
                "frozen_pid":  pid,
            },
        )

    # Backup-destruction tooling — spawning any of these is an unambiguous
    # ransomware pre-encryption step (kill shadow copies / recovery).
    _BACKUP_DESTRUCT_KEYWORDS = ("vssadmin", "bcdedit", "wbadmin", "shadowcopy")

    def observe_execve(
        self,
        pid: int,
        ppid: int,
        comm: str,
        argv: List[str],
        ts: float,
    ) -> Optional[dict]:
        """
        Feature 4 — block backup-destruction tooling.

        If a freshly exec'd child's argv references a backup/shadow-copy
        destruction tool, emit CRITICAL BACKUP_DESTRUCTION and mark the PARENT
        (the process that spawned it — the ransomware itself) frozen so the
        caller SIGKILLs it. The BPF side mirrors this: it sets blocked_pids and
        bpf_send_signal(SIGKILL)s the child inline, while the bprm_check LSM
        hook returns -EPERM for any already-blocked PID.
        """
        if pid == self.self_pid:
            return None
        if comm in self.ignore_comms:
            return None
        hay = " ".join(a for a in (argv or []) if isinstance(a, str)).lower()
        matched = [kw for kw in self._BACKUP_DESTRUCT_KEYWORDS if kw in hay]
        if not matched:
            return None
        self._frozen_pids.add(ppid)
        self._active_pids.add(ppid)
        return self._make_event(
            "BACKUP_DESTRUCTION", "CRITICAL", pid, ppid, comm, "", "", ts,
            extra={
                "trigger":     "execve",
                "keywords":    matched,
                "argv":        list(argv or [])[:8],
                "kill_parent": ppid,
            },
        )


# ---------------------------------------------------------------------------
# Canary seeding
# ---------------------------------------------------------------------------

ATTRACTIVE_EXTS = (".docx", ".xlsx", ".pdf", ".db", ".vmdk", ".kdbx", ".edb", ".pst")

def seed_canaries(
    watch_dirs: List[str],
    per_dir: int = 2,
    dry_run: bool = False,
) -> List[str]:
    """
    Place AAA_/zzz_ prefixed decoy files in every subdirectory.
    Skips .git dirs. Returns list of created paths.
    """
    placed: List[str] = []
    for root_dir in watch_dirs:
        for dirpath, dirnames, _ in os.walk(root_dir):
            # Skip .git
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for i in range(per_dir):
                # 4 prefixes: AAA_, aaa_, ZZZ_, zzz_
                # Sort order: AAA_ < aaa_ < ZZZ_ < zzz_ → always first in directory listing
                prefixes = ["AAA_", "aaa_", "ZZZ_", "zzz_"]
                prefix = prefixes[i % len(prefixes)]
                ext = ATTRACTIVE_EXTS[i % len(ATTRACTIVE_EXTS)]
                name = f"{prefix}rsentry_canary{i}{ext}"
                full = os.path.join(dirpath, name)
                if dry_run:
                    placed.append(full)
                    continue
                try:
                    if not os.path.exists(full):
                        Path(full).write_bytes(b"RSENTRY_CANARY\n" + os.urandom(64))
                    placed.append(full)
                except OSError:
                    pass
    return placed


# ---------------------------------------------------------------------------
# BPF C source generator
# ---------------------------------------------------------------------------

def build_bpf(enforce: bool = True, lsm: bool = False) -> str:
    """
    Full kernel-space behavioral detection — system-wide:
    - TRACEPOINT rename:  velocity + canary
    - TRACEPOINT openat:  mass file access
    - kprobe vfs_write:   write burst (filtered)
    - TRACEPOINT unlink:  file deletion (strongest signal)
    - TRACEPOINT execve:  process spawning
    - LSM hook:           kernel-space blocking
    - Process profile:    multi-signal behavioral scoring
    """
    # Conditional kernel-block snippets are hoisted into locals so the f-string
    # expression parts contain no backslashes (required for Python 3.11 compat —
    # PEP 701 backslash-in-f-string only lands in 3.12+).
    _block_on_velocity = (
        "u8 one = 1;\n    if (new_cnt >= VELOCITY_THRESHOLD) "
        "{ blocked_pids.update(&pid, &one); }"
    ) if (enforce and lsm) else ""
    _block_on_rename_score = (
        "u8 blk = 1; if (p->score >= 85) { blocked_pids.update(&pid, &blk); }"
    ) if (enforce and lsm) else ""
    _block_on_write_score = (
        "u8 blk = 1; if (p->score >= SCORE_BLOCK) { blocked_pids.update(&pid, &blk); }"
    ) if (enforce and lsm) else ""
    # W1/BUG 3: arming on a canary write happens in enforce mode regardless of
    # LSM availability — the SIGSTOP fallback needs the PID frozen too.
    _block_on_canary_write = (
        "u8 _cone = 1; blocked_pids.update(&pid, &_cone);"
    ) if enforce else ""
    _lsm_hook = "" if not (enforce and lsm) else """
// BUG 3 fix: submit the canary attempt to userspace BEFORE the -EPERM deny so
// the agent can log CANARY_ATTEMPT, arm containment and send telemetry. The
// deny itself is unchanged — callers still return -EPERM after this runs.
static inline void __emit_canary_attempt(void *ctx, u32 pid, u64 inode, u8 op) {
    struct canary_event_t cev = {};
    cev.pid = pid; cev.inode = inode; cev.op = op; cev.blocked = 1;
    cev.ts = bpf_ktime_get_ns();
    // VERIFIER FIX: bpf_get_current_task() returns an UNTYPED scalar on strict
    // verifiers (kernel 6.x), so dereferencing real_parent->tgid at a fixed
    // offset is rejected ("R0 invalid mem access 'scalar'"). ppid is purely
    // informational here — containment decisions never use it — so we set it to
    // 0 in the LSM hook rather than walk the task struct. Userspace
    // _handle_canary() already tolerates ppid=0.
    cev.ppid = 0;
    bpf_get_current_comm(&cev.comm, sizeof(cev.comm));
    canary_events.perf_submit(ctx, &cev, sizeof(cev));
}

LSM_PROBE(path_rename,
          const struct path *old_dir, struct dentry *old_dentry,
          const struct path *new_dir, struct dentry *new_dentry) {
    // Feature 6: fail-secure — if the agent heartbeat is stale, deny.
    if (__heartbeat_stale()) return -EPERM;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *blocked = blocked_pids.lookup(&pid);
    if (blocked && *blocked) return -EPERM;
    if (old_dentry && old_dentry->d_inode) {
        u64 inode = old_dentry->d_inode->i_ino;
        u8 *is_canary = canary_inodes.lookup(&inode);
        if (is_canary) {
            u8 one = 1;
            __emit_canary_attempt(ctx, pid, inode, 1);  // BUG 3: notify first
            blocked_pids.update(&pid, &one);
            return -EPERM;
        }
    }
    return 0;
}

// BUG 3 fix (write side): deny WRITES to canary inodes inline. Previously only
// renames were LSM-protected — a direct open()+write() on a canary file went
// through and was only noticed after the fact (if at all). MAY_WRITE-gated so
// reads (backup tools, indexers) are unaffected; one map lookup on the hot path.
LSM_PROBE(file_permission, struct file *file, int mask) {
    if (!file || !file->f_inode) return 0;
    if (!(mask & MAY_WRITE)) return 0;
    u64 inode = file->f_inode->i_ino;
    u8 *is_canary = canary_inodes.lookup(&inode);
    if (!is_canary) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    __emit_canary_attempt(ctx, pid, inode, 2);          // BUG 3: notify first
    u8 one = 1;
    blocked_pids.update(&pid, &one);
    return -EPERM;
}

// Feature 4: deny exec() for any PID armed in blocked_pids (e.g. a ransomware
// parent caught spawning vssadmin/bcdedit/wbadmin/shadowcopy). Returns -EPERM.
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm) {
    // Feature 6: fail-secure — if the agent heartbeat is stale, deny exec.
    if (__heartbeat_stale()) return -EPERM;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *blocked = blocked_pids.lookup(&pid);
    if (blocked && *blocked) return -EPERM;
    return 0;
}
"""

    # Feature 5: per-PID per-CPU rate limiter. Returns 1 (throttle) when a PID
    # exceeds RATE_LIMIT events within the current millisecond window.
    _rate_helper = """
static inline int __rate_limited(u32 pid, u64 ts) {
    u64 ms = ts / 1000000ULL;
    struct rate_t *r = rate_state.lookup(&pid);
    if (!r) {
        struct rate_t nr = {};
        nr.win_ms = ms; nr.count = 1;
        rate_state.update(&pid, &nr);
        return 0;
    }
    if (r->win_ms != ms) {
        r->win_ms = ms;
        r->count = 1;
        return 0;
    }
    r->count += 1;
    if (r->count > RATE_LIMIT) return 1;
    return 0;
}
"""
    _rl_check = "if (__rate_limited(pid, ts)) return 0;"

    # Feature 6: heartbeat staleness check (fail-secure). bpf_ktime_get_ns() is
    # CLOCK_MONOTONIC, so userspace writes the matching monotonic clock (see
    # run_sensor). hb==0 means "not yet initialized" → allow (don't brick at
    # startup before the first pulse).
    _heartbeat_helper = """
static inline int __heartbeat_stale() {
    int zero = 0;
    u64 *hb = heartbeat.lookup(&zero);
    if (!hb || *hb == 0) return 0;
    u64 now = bpf_ktime_get_ns();
    if (now > *hb && (now - *hb) > HEARTBEAT_STALE_NS) return 1;
    return 0;
}
"""

    # Feature 4: kernel-space substring matcher for backup-destruction tooling.
    # Scans a 64-byte buffer for vssadmin / bcdedit / wbadmin / shadowcop(y).
    _kw_matcher = """
static inline int __is_backup_destruct(const char *b) {
    #pragma unroll
    for (int i = 0; i < 55; i++) {
        if (b[i]=='v'&&b[i+1]=='s'&&b[i+2]=='s'&&b[i+3]=='a'&&b[i+4]=='d'&&b[i+5]=='m'&&b[i+6]=='i'&&b[i+7]=='n') return 1;
        if (b[i]=='b'&&b[i+1]=='c'&&b[i+2]=='d'&&b[i+3]=='e'&&b[i+4]=='d'&&b[i+5]=='i'&&b[i+6]=='t') return 1;
        if (b[i]=='w'&&b[i+1]=='b'&&b[i+2]=='a'&&b[i+3]=='d'&&b[i+4]=='m'&&b[i+5]=='i'&&b[i+6]=='n') return 1;
        if (b[i]=='s'&&b[i+1]=='h'&&b[i+2]=='a'&&b[i+3]=='d'&&b[i+4]=='o'&&b[i+5]=='w'&&b[i+6]=='c'&&b[i+7]=='o'&&b[i+8]=='p') return 1;
    }
    return 0;
}
"""

    # The kill/block action only runs in enforce mode; audit still emits the event.
    _exec_block = (
        "u8 _blk = 1; blocked_pids.update(&pid, &_blk); "
        "if (ppid > 0) blocked_pids.update(&ppid, &_blk); "
        "bpf_send_signal(SIGKILL);"
    ) if enforce else ""

    _execve_kw_check = """
    char _fn[64] = {};
    bpf_probe_read_user_str(&_fn, sizeof(_fn), (void *)args->filename);
    char _a1[64] = {};
    const char *_argp = NULL;
    bpf_probe_read_user(&_argp, sizeof(_argp), &args->argv[1]);
    if (_argp) bpf_probe_read_user_str(&_a1, sizeof(_a1), _argp);
    if (__is_backup_destruct(_fn) || __is_backup_destruct(_a1)) {
        struct exec_event_t xev = {};
        xev.pid = pid; xev.ppid = ppid; xev.ts = ts;
        bpf_get_current_comm(&xev.comm, sizeof(xev.comm));
        __builtin_memcpy(&xev.arg, &_fn, sizeof(xev.arg));
        exec_events.perf_submit(args, &xev, sizeof(xev));
        """ + _exec_block + """
    }
"""
    return f"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

// ── Maps ─────────────────────────────────────────────────────────────────
BPF_HASH(canary_inodes, u64, u8,    1000);
BPF_HASH(blocked_pids,  u32, u8,   10000);
BPF_HASH(rename_count,  u32, u64,  10000);
BPF_HASH(rename_ts,     u32, u64,  10000);
BPF_HASH(write_ts,      u32, u64,  10000);
BPF_HASH(write_count,   u32, u64,  10000);

// Feature 1: per-inode write-offset tracking for silent-encryption detection.
struct woff_t {{ u64 last_end; u64 nonseq; }};
BPF_HASH(write_offset,  u64, struct woff_t, 20000);

// Feature 5: per-PID per-CPU rate limiting. A PERCPU map needs no spinlock on
// the hot path; we throttle a PID that floods >RATE_LIMIT events in one ms.
struct rate_t {{ u64 win_ms; u64 count; }};
BPF_PERCPU_HASH(rate_state, u32, struct rate_t, 10000);

// Feature 6: fail-secure agent heartbeat. Userspace writes a monotonic ns
// timestamp to slot 0 every second; if it goes stale (agent crashed) the LSM
// hooks deny renames/execs so nothing can encrypt while we are blind.
BPF_ARRAY(heartbeat, u64, 1);

// ── Process behavioral profile ───────────────────────────────────────────
struct proc_profile_t {{
    u64 files_opened;
    u64 files_written;
    u64 files_deleted;
    u64 files_renamed;
    u64 write_bytes;
    u64 read_bytes;
    u64 unique_dirs;
    u64 child_procs;
    u64 first_op_ts;
    u64 last_op_ts;
    u8  score;
    u8  alerted;
}};
BPF_HASH(proc_profiles, u32, struct proc_profile_t, 10000);

// ── Perf outputs ─────────────────────────────────────────────────────────
BPF_PERF_OUTPUT(rename_events);
BPF_PERF_OUTPUT(write_events);
BPF_PERF_OUTPUT(behavior_events);
BPF_PERF_OUTPUT(exec_events);
// BUG 3 fix: canary touch/attempt events. The LSM hooks perf_submit here
// BEFORE issuing their deny so userspace always learns an attempt happened;
// kprobe__vfs_write also submits here on any canary-inode write (W1) so the
// SIGSTOP-fallback path (lsm=False) sees single canary writes too.
BPF_PERF_OUTPUT(canary_events);

#define VELOCITY_THRESHOLD   3
#define SIGKILL              9
#define WINDOW_NS           (3ULL * 1000000000ULL)
#define WRITE_WINDOW_NS     (5ULL * 1000000000ULL)
#define WRITE_BURST_THRESH   50
#define SCORE_BLOCK          70
#define SCORE_ALERT          50
#define NONSEQ_THRESH         5
#define RATE_LIMIT          500
#define HEARTBEAT_STALE_NS  (2ULL * 1000000000ULL)

struct rename_event_t {{
    u32 pid; u32 ppid; char comm[16];
    u64 count; u64 ts;
    u8  canary_hit; u8 kernel_blocked;
    char oldname[128]; char newname[128];
}};
struct write_event_t {{
    u32 pid; u32 ppid; char comm[16];
    u64 inode; u64 ts; u64 write_count;
    u64 offset; u64 length; u8 silent_enc;
}};
struct behavior_event_t {{
    u32 pid; u32 ppid; char comm[16];
    u64 ts; u8 score; u8 trigger;
    u64 files_opened; u64 files_written;
    u64 files_deleted; u64 files_renamed;
    u64 unique_dirs; u64 child_procs;
}};
struct exec_event_t {{
    u32 pid; u32 ppid; char comm[16]; u64 ts;
    char arg[64];
}};
// op: 1 = rename touching a canary, 2 = write to a canary inode.
// blocked: 1 = the kernel denied the operation inline (LSM deny),
//          0 = the operation went through (SIGSTOP-fallback path).
struct canary_event_t {{
    u32 pid; u32 ppid; char comm[16];
    u64 inode; u64 ts; u8 op; u8 blocked;
}};

// Feature 5: per-PID per-CPU rate limiter (inserted top-level).
{_rate_helper}
// Feature 6: agent heartbeat staleness helper (inserted top-level).
{_heartbeat_helper}
// Feature 4: backup-destruction keyword matcher (inserted top-level).
{_kw_matcher}

// ── Score calculator ──────────────────────────────────────────────────────
static inline u8 __calc_score(struct proc_profile_t *p) {{
    u8 score = 0;

    // Signal 1: rapid unlink+write (ransomware pattern)
    if (p->files_deleted > 0 && p->files_written > 0) {{
        u64 elapsed_ms = (p->last_op_ts > p->first_op_ts) ?
            (p->last_op_ts - p->first_op_ts) / 1000000ULL : 1;
        u64 del_per_sec = (p->files_deleted * 1000) / elapsed_ms;
        if (del_per_sec >= 2) {{ score += 35; }}
        if (del_per_sec >= 2 && p->files_deleted > 5) {{ score += 10; }}
    }}
    // Signal 2: rename velocity
    if (p->files_renamed >= 3) score += 25;
    // Signal 3: mass file ops across dirs (write OR open)
    u64 total_file_ops = p->files_opened + p->files_written + p->files_deleted;
    if (total_file_ops > 15 && p->files_deleted > 3) score += 15;
    // Signal 5: child spawning + file ops
    if (p->child_procs > 5 && p->files_written > 10) score += 10;

    return score > 100 ? 100 : score;
}}

// ── Rename handler ────────────────────────────────────────────────────────
static inline int __handle_rename(void *ctx,
    const char __user *oldpath, const char __user *newpath) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts  = bpf_ktime_get_ns();
    {_rl_check}

    u64 *last = rename_ts.lookup(&pid);
    u64 *cnt  = rename_count.lookup(&pid);
    u64 new_cnt = 1;
    if (last && cnt && (ts - *last) < WINDOW_NS)
        new_cnt = *cnt + 1;
    rename_count.update(&pid, &new_cnt);
    rename_ts.update(&pid, &ts);

    {_block_on_velocity}

    struct proc_profile_t *p = proc_profiles.lookup(&pid);
    struct proc_profile_t newp = {{0}};
    if (!p) {{ newp.first_op_ts = ts; p = &newp; }}
    p->files_renamed++;
    p->last_op_ts = ts;
    p->score = __calc_score(p);
    // Behavioral score block — needs higher threshold than velocity
    {_block_on_rename_score}
    proc_profiles.update(&pid, p);

    struct rename_event_t ev = {{0}};
    ev.pid = pid;
    struct task_struct *_task_r = (struct task_struct *)bpf_get_current_task();
    ev.ppid = (_task_r && _task_r->real_parent) ? _task_r->real_parent->tgid : 0;
    ev.ts = ts; ev.count = new_cnt;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.oldname, sizeof(ev.oldname), oldpath);
    bpf_probe_read_user_str(&ev.newname, sizeof(ev.newname), newpath);
    rename_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_enter_rename)    {{ return __handle_rename(args, args->oldname, args->newname); }}
TRACEPOINT_PROBE(syscalls, sys_enter_renameat)  {{ return __handle_rename(args, args->oldname, args->newname); }}
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {{ return __handle_rename(args, args->oldname, args->newname); }}

// ── Unlink handler (strongest signal) ────────────────────────────────────
static inline int __handle_unlink(void *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts  = bpf_ktime_get_ns();
    {_rl_check}
    struct proc_profile_t *p = proc_profiles.lookup(&pid);
    struct proc_profile_t newp = {{0}};
    if (!p) {{ newp.first_op_ts = ts; p = &newp; }}
    p->files_deleted++;
    p->last_op_ts = ts;
    p->score = __calc_score(p);
    // Behavioral score: ALERT only — final BLOCK decision in userspace
    // (entropy check needed to avoid false positives with legitimate tools)
    proc_profiles.update(&pid, p);
    if (p->score >= SCORE_ALERT && !p->alerted) {{
        struct behavior_event_t ev = {{0}};
        ev.pid = pid; ev.ts = ts; ev.score = p->score; ev.trigger = 1;
        ev.files_opened = p->files_opened; ev.files_written = p->files_written;
        ev.files_deleted = p->files_deleted; ev.files_renamed = p->files_renamed;
        ev.unique_dirs = p->unique_dirs; ev.child_procs = p->child_procs;
        bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
        behavior_events.perf_submit(ctx, &ev, sizeof(ev));
        p->alerted = 1;
        proc_profiles.update(&pid, p);
    }}
    return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_enter_unlink)   {{ return __handle_unlink(args); }}
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {{ return __handle_unlink(args); }}

// ── Openat handler ────────────────────────────────────────────────────────
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts  = bpf_ktime_get_ns();
    {_rl_check}
    struct proc_profile_t *p = proc_profiles.lookup(&pid);
    struct proc_profile_t newp = {{0}};
    if (!p) {{ newp.first_op_ts = ts; p = &newp; }}
    p->files_opened++;
    p->last_op_ts = ts;
    p->score = __calc_score(p);
    proc_profiles.update(&pid, p);
    return 0;
}}

// ── Write handler (filtered — only suspicious PIDs) ───────────────────────
int kprobe__vfs_write(struct pt_regs *ctx, struct file *file) {{
    // Only track regular file writes (skip pipes, sockets, kernel files)
    if (!file || !file->f_inode) return 0;
    umode_t mode = file->f_inode->i_mode;
    if (!S_ISREG(mode)) return 0;
    // Skip kernel threads (pid < 100)
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 100) return 0;
    u64 ts  = bpf_ktime_get_ns();

    // ── CHEAP COUNTING (host-wide, NEVER rate-limited) ──────────────────────
    // Feature 1 (MITRE T1486 — Data Encrypted for Impact): per-inode write-offset
    // silent-encryption detection. In-place ransomware rewrites jump around the
    // file (offset != prev end); a sustained run of non-sequential writes freezes
    // the PID inline. This block MUST run on EVERY regular-file write, on ANY
    // inode, with NO rate limit in front of it: a fast-writing attacker (the real
    // ransomware signature) would otherwise trip __rate_limited and its writes
    // would never reach the non-sequential counter. The rate limiter is therefore
    // pushed BELOW this block — it only throttles the expensive emit/profile path.
    u64 _ino = file->f_inode->i_ino;
    loff_t _off = 0;
    bpf_probe_read_kernel(&_off, sizeof(_off), (void *)PT_REGS_PARM4(ctx));
    u64 _cur = (u64)_off;
    u64 _len = (u64)PT_REGS_PARM3(ctx);

    // ── W1 (wiring fix): canary-inode write → ALWAYS reaches userspace ─────
    // Before this check existed, write_events only fired on a >=50-write burst,
    // so a single write to a canary file never left the kernel and the canary
    // write layer was blind in live operation. This runs BEFORE the rate
    // limiter and the post-freeze throttle: a canary touch is the single
    // highest-confidence signal (MITRE T1486) and must never be dropped.
    // blocked=0 here — under BPF-LSM the file_permission hook denies the write
    // and submits its own blocked=1 event; this kprobe fires at vfs_write
    // entry either way and userspace dedupes per PID.
    u8 *_is_canary_w = canary_inodes.lookup(&_ino);
    if (_is_canary_w) {{
        struct canary_event_t cev = {{0}};
        cev.pid = pid; cev.inode = _ino; cev.op = 2; cev.blocked = 0;
        cev.ts = ts;
        struct task_struct *_task_c = (struct task_struct *)bpf_get_current_task();
        cev.ppid = (_task_c && _task_c->real_parent) ? _task_c->real_parent->tgid : 0;
        bpf_get_current_comm(&cev.comm, sizeof(cev.comm));
        canary_events.perf_submit(ctx, &cev, sizeof(cev));
        {_block_on_canary_write}
        return 0;
    }}

    u8 silent_enc = 0;
    // Was this PID already frozen by an EARLIER detection? Capture it before the
    // counter runs. If so, the cheap counting below still proceeds (cheap, host-
    // wide), but we must NOT re-emit a silent_enc event — containment is already
    // armed, and re-firing on every subsequent NONSEQ_THRESH run is the exact
    // duplicate-emit flood the post-freeze throttle exists to prevent.
    u8 *_pre_blk = blocked_pids.lookup(&pid);
    u8 _was_blocked = (_pre_blk && *_pre_blk) ? 1 : 0;
    struct woff_t *wo = write_offset.lookup(&_ino);
    if (wo) {{
        if (_cur != wo->last_end) {{
            wo->nonseq += 1;
            if (wo->nonseq >= NONSEQ_THRESH) {{
                // Emit the critical event ONLY on the initial detection (PID not
                // yet frozen). An already-blocked PID keeps counting but stays
                // silent — the throttle below catches it.
                if (!_was_blocked) silent_enc = 1;
                wo->nonseq = 0;
                u8 _one = 1;
                blocked_pids.update(&pid, &_one);
            }}
        }} else {{
            wo->nonseq = 0;
        }}
        wo->last_end = _cur + _len;
    }} else {{
        struct woff_t _nw = {{0}};
        _nw.last_end = _cur + _len;
        _nw.nonseq = 0;
        write_offset.update(&_ino, &_nw);
    }}

    // ── CRITICAL EVENT BYPASS ───────────────────────────────────────────────
    // A confirmed silent-encryption detection (NONSEQ_THRESH crossed) is NEVER
    // throttled. The PID is already frozen in blocked_pids above; deliver the
    // SILENT_ENCRYPTION alert + freeze to userspace immediately even if this PID
    // is currently rate-limited, then return — containment is armed, so no
    // further profiling/burst work is needed for this write.
    if (silent_enc) {{
        struct write_event_t sev = {{0}};
        sev.pid = pid;
        struct task_struct *_task_s = (struct task_struct *)bpf_get_current_task();
        sev.ppid = (_task_s && _task_s->real_parent) ? _task_s->real_parent->tgid : 0;
        sev.ts = ts; sev.inode = _ino; sev.write_count = 0;
        sev.offset = _cur; sev.length = _len; sev.silent_enc = 1;
        bpf_get_current_comm(&sev.comm, sizeof(sev.comm));
        write_events.perf_submit(ctx, &sev, sizeof(sev));
        return 0;
    }}

    // ── POST-FREEZE THROTTLE ────────────────────────────────────────────────
    // PID already frozen (contained by an earlier detection): the cheap counter
    // above still ran, but suppress duplicate emits — the attack is already
    // stopped, so do not flood userspace with thousands of repeat write events.
    u8 *blocked = blocked_pids.lookup(&pid);
    if (blocked && *blocked) return 0;

    // ── EXPENSIVE PATH (rate-limited) ───────────────────────────────────────
    // Behavioral profiling + userspace event submission are throttled per PID.
    // The limiter lives HERE, never in front of the detection counter above.
    {_rl_check}
    struct proc_profile_t *p = proc_profiles.lookup(&pid);
    struct proc_profile_t newp = {{0}};
    if (!p) {{ newp.first_op_ts = ts; p = &newp; }}
    // Update process profile write count
    p->files_written++;
    p->write_bytes += (u64)PT_REGS_PARM3(ctx);
    p->last_op_ts = ts;
    p->score = __calc_score(p);
    {_block_on_write_score}
    proc_profiles.update(&pid, p);

    u64 *last = write_ts.lookup(&pid);
    u64 *cnt  = write_count.lookup(&pid);
    u64 new_cnt = 1;
    if (last && cnt && (ts - *last) < WRITE_WINDOW_NS)
        new_cnt = *cnt + 1;
    write_count.update(&pid, &new_cnt);
    write_ts.update(&pid, &ts);
    // Emit on a velocity burst, or once on the transition where the behavioral
    // score just armed the block ({_block_on_write_score}); subsequent writes
    // from a now-frozen PID are caught by the post-freeze throttle above.
    u8 *wblk = blocked_pids.lookup(&pid);
    if (!(wblk && *wblk) && new_cnt < WRITE_BURST_THRESH) return 0;
    struct write_event_t ev = {{0}};
    ev.pid = pid;
    struct task_struct *_task_w = (struct task_struct *)bpf_get_current_task();
    ev.ppid = (_task_w && _task_w->real_parent) ? _task_w->real_parent->tgid : 0;
    ev.ts = ts; ev.inode = file->f_inode->i_ino; ev.write_count = new_cnt;
    ev.offset = _cur; ev.length = _len; ev.silent_enc = 0;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    write_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}}

// ── Execve handler ────────────────────────────────────────────────────────
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {{
    u32 pid  = bpf_get_current_pid_tgid() >> 32;
    u64 ts   = bpf_ktime_get_ns();
    // Get parent PID from task_struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    if (task && task->real_parent)
        ppid = task->real_parent->tgid;
    // Update parent profile — parent is spawning a child
    if (ppid > 0) {{
        struct proc_profile_t *p = proc_profiles.lookup(&ppid);
        struct proc_profile_t newp = {{0}};
        if (!p) {{ newp.first_op_ts = ts; p = &newp; }}
        p->child_procs++;
        p->last_op_ts = ts;
        p->score = __calc_score(p);
        proc_profiles.update(&ppid, p);
    }}
    // Feature 4: block backup-destruction tooling at exec time.
    {_execve_kw_check}
    return 0;
}}

// ── BPF LSM Hook ──────────────────────────────────────────────────────────
{_lsm_hook}
"""

# ---------------------------------------------------------------------------
# run_sensor — live eBPF loop (requires root + BCC)
# ---------------------------------------------------------------------------

def run_sensor(
    watch_dirs: List[str],
    canary_paths: List[str],
    host_id: str,
    mode: str = "enforce",
    threshold: int = 2,
    window_seconds: float = 3.0,
    emit: Optional[Callable[[dict], None]] = None,
    contain: Optional[Callable[[int, str, str], None]] = None,
    sim_fn: Optional[Callable] = None,
    lineage_fn: Optional[Callable[[int], float]] = None,
    entropy_fn: Optional[Callable[[str], float]] = None,
    stop_event = None,
    lsm: Optional[bool] = None,
) -> None:
    """
    Load BPF probes and run the detection loop.
    Requires: root, bpfcc-tools, python3-bpfcc, linux-headers.

    contain: callback (pid, comm, layer) — layer names the detection layer
             that fired ("canary"|"rename"|"write_offset"|"entropy"|"execve").
    lsm:     BUG 4 fix — None = auto-detect kernel BPF-LSM support (default);
             True = force inline-LSM-deny (downgraded with a warning if the
             kernel lacks lsm=bpf); False = force SIGSTOP-fallback.
    """
    try:
        import sys as _sys
        _sys.path.insert(0, "/usr/lib/python3/dist-packages")
        from bcc import BPF
    except ImportError:
        sys.exit("[ebpf] python3-bpfcc not installed. "
                 "Run: sudo apt install python3-bpfcc bpfcc-tools")

    _lsm_path = Path("/sys/kernel/security/lsm")
    _lsm_kernel = "bpf" in _lsm_path.read_text() if _lsm_path.exists() else False
    if lsm is None:
        lsm_active = _lsm_kernel
    elif lsm and not _lsm_kernel:
        print("[ebpf] WARNING: --lsm requested but kernel lacks lsm=bpf "
              "(check /sys/kernel/security/lsm) — falling back to SIGSTOP")
        lsm_active = False
    else:
        lsm_active = lsm
    enforce    = (mode == "enforce")

    print(f"[ebpf] mode={mode} lsm={lsm_active} "
          f"threshold={threshold} window={window_seconds}s")
    print(f"[ebpf] watch={watch_dirs}")
    print(f"[ebpf] prevention={'inline-LSM-deny' if (enforce and lsm_active) else 'SIGSTOP-fallback'}")

    engine = DetectionEngine(
        host_id            = host_id,
        watch_dirs         = watch_dirs,
        canary_paths       = canary_paths,
        velocity_threshold = threshold,
        window_seconds     = window_seconds,
        self_pid           = 0 if sim_fn is not None else os.getpid(),
        ignore_comms       = IGNORE_COMMS,
        lineage_fn         = lineage_fn,
        entropy_fn         = entropy_fn,
    )

    # Enable syscall tracepoints (may be disabled by default on some kernels)
    for tp in ['sys_enter_rename', 'sys_enter_renameat', 'sys_enter_renameat2']:
        tp_path = f'/sys/kernel/debug/tracing/events/syscalls/{tp}/enable'
        try:
            with open(tp_path, 'w') as f:
                f.write('1')
        except OSError:
            pass
    src = build_bpf(enforce=enforce, lsm=lsm_active)
    b   = BPF(text=src)

    # Register canary inodes in BPF map AFTER BPF load. Registered in EVERY
    # mode (W1 fix — previously enforce+lsm only): kprobe__vfs_write consults
    # this map to surface single canary writes, which audit/SIGSTOP-fallback
    # modes need just as much as the LSM deny path.
    if canary_paths:
        _registered = 0
        for _cp in canary_paths:
            try:
                _inode = os.stat(_cp).st_ino
                b["canary_inodes"][b["canary_inodes"].Key(_inode)] = \
                    b["canary_inodes"].Leaf(1)
                _registered += 1
            except Exception:
                pass
        print(f"[ebpf] {_registered} canary inodes registered in kernel map")

    # ── Feature 6: fail-secure heartbeat ──────────────────────────────────
    # The LSM hooks deny renames/execs if the heartbeat goes stale (>2s),
    # so a crashed agent can't leave the system silently unprotected.
    # NOTE: bpf_ktime_get_ns() in-kernel is CLOCK_MONOTONIC. We therefore write
    # the *matching* monotonic clock here, NOT wall-clock time.time_ns() — the
    # latter is a different clock domain and would read as permanently stale,
    # bricking all renames. The intent ("write a timestamp every second; deny
    # if stale") is preserved; only the clock source is corrected.
    import threading as _hb_thr
    _hb_key = b["heartbeat"].Key(0)
    def _heartbeat_writer():
        while not (stop_event and stop_event.is_set()):
            try:
                b["heartbeat"][_hb_key] = b["heartbeat"].Leaf(
                    time.clock_gettime_ns(time.CLOCK_MONOTONIC))
            except Exception:
                pass
            time.sleep(1.0)
    # Prime once before the poll loop so the first LSM decision sees a fresh pulse.
    try:
        b["heartbeat"][_hb_key] = b["heartbeat"].Leaf(
            time.clock_gettime_ns(time.CLOCK_MONOTONIC))
    except Exception:
        pass
    _hb_thr.Thread(target=_heartbeat_writer, daemon=True).start()

    _emit    = emit    or (lambda e: print(e))
    _contain = contain or (lambda pid, comm, layer="unknown": os.kill(pid, 19))  # SIGSTOP

    import threading as _ct
    import queue as _cq
    # Queue items are (pid, comm, layer) — layer names the detection layer
    # that fired so the SIGSTOP pipeline log line can attribute the kill.
    _contain_q: _cq.Queue = _cq.Queue()
    def _contain_worker():
        while True:
            item = _contain_q.get()
            if item is None:
                break
            try:
                _contain(item[0], item[1], item[2] if len(item) > 2 else "unknown")
            except Exception:
                pass
            _contain_q.task_done()
    _ct.Thread(target=_contain_worker, daemon=True).start()

    import queue as _sq
    _score_q: _sq.Queue = _sq.Queue(maxsize=2000)

    _lineage_cache: dict = {}
    def _score_worker():
        """
        Async enrichment thread — runs AFTER containment fires.
        Adds lineage + entropy to the event then emits to backend.
        Detection and SIGSTOP never wait for this.
        """
        while True:
            item = _score_q.get()
            if item is None:
                break
            event, pid, dst_path = item
            try:
                if engine.lineage_fn and pid > 0:
                    if pid not in _lineage_cache:
                        _lineage_cache[pid] = round(float(engine.lineage_fn(pid)), 2)
                    event["lineage_score"] = _lineage_cache[pid]
                if engine.entropy_fn and dst_path:
                    event["entropy_delta"] = round(float(engine.entropy_fn(dst_path)), 4)
                # W4 (wiring fix): recompute severity from lineage/entropy ONLY
                # for score-based PROCESS_ANOMALY events. Event types with
                # intrinsic severity (CANARY_TOUCHED/CANARY_ATTEMPT CRITICAL,
                # BACKUP_DESTRUCTION CRITICAL, SILENT_ENCRYPTION HIGH) were
                # being silently downgraded here when the attacker had a clean
                # lineage and low file entropy.
                if event["event_type"] == "PROCESS_ANOMALY":
                    event["severity"] = engine._severity(
                        event.get("canary_hit", False),
                        event["lineage_score"],
                        event["entropy_delta"])
            except Exception:
                pass
            _emit(event)
            _score_q.task_done()

    import threading as _st
    _st.Thread(target=_score_worker, daemon=True).start()

    def _handle_rename(cpu, data, size):
        ev      = b["rename_events"].event(data)
        pid     = ev.pid
        comm    = ev.comm.decode(errors="replace").rstrip("\x00")
        oldname = ev.oldname.decode(errors="replace").rstrip("\x00")
        newname = ev.newname.decode(errors="replace").rstrip("\x00")
        ts      = time.time()
        if not oldname or not newname:
            return
        event = engine.observe_rename(pid, ev.ppid, comm, oldname, newname, ts=ts)
        if event:
            # ── FAST PATH: canary → LSM block + SIGSTOP inline ───────
            if enforce and pid > 0:
                if event.get("event_type") == "CANARY_TOUCHED":
                    # 1. Arm PID in BPF map → kernel blocks ALL future renames
                    try:
                        b["blocked_pids"][b["blocked_pids"].Key(pid)] =                             b["blocked_pids"].Leaf(1)
                    except Exception:
                        pass
                    # 2. SIGSTOP as backup
                    try:
                        import os as _os
                        _os.kill(pid, 19)
                    except OSError:
                        pass
                    _contain_q.put_nowait((pid, comm, "canary"))
                else:
                    # Velocity burst: arm in BPF map + SIGSTOP
                    try:
                        b["blocked_pids"][b["blocked_pids"].Key(pid)] =                             b["blocked_pids"].Leaf(1)
                    except Exception:
                        pass
                    _contain_q.put_nowait((pid, comm, "rename"))
            # ── ASYNC PATH: enrich then emit (non-blocking) ───────────
            try:
                _score_q.put_nowait((event, pid, newname))
            except _sq.Full:
                _emit(event)

    def _handle_write(cpu, data, size):
        ev    = b["write_events"].event(data)
        pid   = ev.pid
        comm  = ev.comm.decode(errors="replace").rstrip("\x00")
        ts    = time.time()
        # SAFELIST GATE — must run BEFORE any flagging/containment. The kernel
        # vfs_write probe carries no comm safelist, so it sets silent_enc for
        # container runtimes (dockerd/containerd/runc/containerd-shim) and other
        # daemons that legitimately do non-sequential writes. Without this guard
        # the `or engine._make_event(...)` fallback below fabricated a
        # SILENT_ENCRYPTION event even when observe_write_offset() suppressed it,
        # and containment SIGKILLed the Docker stack. Mirror _handle_behavior.
        if pid == engine.self_pid or comm in engine.ignore_comms:
            return
        # Resolve inode → path for entropy check
        inode = ev.inode
        path  = engine._inode_path_cache.get(inode, "")
        if not path:
            # Try to resolve from /proc/pid/fd
            try:
                import os as _os
                for fd in _os.listdir(f"/proc/{pid}/fd"):
                    try:
                        p = _os.readlink(f"/proc/{pid}/fd/{fd}")
                        if _os.stat(p).st_ino == inode:
                            engine._inode_path_cache[inode] = p
                            path = p
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        # Feature 1: kernel flagged a non-sequential write storm → silent encryption.
        # Freeze the PID immediately (block + SIGSTOP), then enrich/emit async.
        if getattr(ev, "silent_enc", 0):
            sevt = engine.observe_write_offset(
                pid, ev.ppid, comm, inode,
                getattr(ev, "offset", 0), getattr(ev, "length", 0), path, ts,
            ) or engine._make_event(
                "SILENT_ENCRYPTION", "HIGH", pid, ev.ppid, comm, path, path, ts,
                extra={"trigger": "write_offset", "inode": inode,
                       "offset": getattr(ev, "offset", 0),
                       "length": getattr(ev, "length", 0),
                       "pattern": "non_sequential", "decided_in": "kernel"},
            )
            if enforce and pid > 0:
                try:
                    b["blocked_pids"][b["blocked_pids"].Key(pid)] = b["blocked_pids"].Leaf(1)
                except Exception:
                    pass
                _contain_q.put_nowait((pid, comm, "write_offset"))
            try:
                _score_q.put_nowait((sevt, pid, path))
            except Exception:
                _emit(sevt)
            return

        event = engine.observe_write(pid, ev.ppid, comm, inode, path, ts)
        if event:
            if enforce and pid > 0:
                # Arm PID in BPF map for silent encryption
                try:
                    b["blocked_pids"][b["blocked_pids"].Key(pid)] =                         b["blocked_pids"].Leaf(1)
                except Exception:
                    pass
                # W2 (wiring fix): this branch armed the BPF map but never
                # queued containment — no SIGSTOP pipeline, no telemetry.
                # Same pattern as the kernel silent_enc branch above.
                _contain_q.put_nowait((
                    pid, comm,
                    "canary" if event.get("event_type") == "CANARY_TOUCHED"
                    else "write_offset",
                ))
            try:
                _score_q.put_nowait((event, pid, path))
            except Exception:
                _emit(event)

    b["rename_events"].open_perf_buffer(_handle_rename, page_cnt=8192)
    b["write_events"].open_perf_buffer(_handle_write, page_cnt=64)
    def _handle_behavior(cpu, data, size):
        ev   = b["behavior_events"].event(data)
        pid  = ev.pid
        comm = ev.comm.decode(errors="replace").rstrip("\x00")
        ts   = time.time()
        if pid == engine.self_pid: return
        if comm in engine.ignore_comms: return
        sample_path = ""
        try:
            import os as _os
            for fd in _os.listdir(f"/proc/{pid}/fd"):
                try:
                    p = _os.readlink(f"/proc/{pid}/fd/{fd}")
                    if _os.path.isfile(p) and not p.startswith("/proc"):
                        sample_path = p
                        break
                except Exception:
                    pass
        except Exception:
            pass
        entropy = 0.0
        if sample_path and engine.entropy_fn:
            try:
                entropy = float(engine.entropy_fn(sample_path))
            except Exception:
                pass
        if entropy >= 6.5:
            event = engine._make_event(
                "PROCESS_ANOMALY", "HIGH", pid, ev.ppid, comm,
                sample_path, sample_path, ts,
                extra={
                    "trigger": "behavioral_score",
                    "score": ev.score,
                    "files_written": ev.files_written,
                    "files_deleted": ev.files_deleted,
                    "entropy_sample": round(entropy, 3),
                },
            )
            if event:
                try:
                    _score_q.put_nowait((event, pid, sample_path))
                except Exception:
                    _emit(event)
                if enforce and pid > 0 and entropy >= 6.5:
                    try:
                        b["blocked_pids"][b["blocked_pids"].Key(pid)] = b["blocked_pids"].Leaf(1)
                    except Exception:
                        pass
                    _contain_q.put_nowait((pid, comm, "entropy"))
    b["behavior_events"].open_perf_buffer(_handle_behavior, page_cnt=256)

    def _handle_exec(cpu, data, size):
        ev   = b["exec_events"].event(data)
        pid  = ev.pid
        ppid = ev.ppid
        comm = ev.comm.decode(errors="replace").rstrip("\x00")
        arg  = ev.arg.decode(errors="replace").rstrip("\x00")
        ts   = time.time()
        # SAFELIST GATE — must run BEFORE the fabricated-event fallback + SIGKILL
        # below. observe_execve() returns None for self/IGNORE_COMMS, but the
        # `if event is None: fabricate` path treated that suppression as "kernel
        # decided, kill anyway". Never flag/contain self or a safelisted comm.
        if pid == engine.self_pid or comm in engine.ignore_comms:
            return
        # Kernel already matched a backup-destruction keyword. Reconstruct the
        # userspace event (source of truth); fall back to a direct event if the
        # single argv buffer we carried isn't enough for the userspace matcher.
        event = engine.observe_execve(pid, ppid, comm, [arg], ts)
        if event is None:
            engine._frozen_pids.add(ppid)
            event = engine._make_event(
                "BACKUP_DESTRUCTION", "CRITICAL", pid, ppid, comm, "", "", ts,
                extra={"trigger": "execve", "decided_in": "kernel",
                       "arg": arg, "kill_parent": ppid},
            )
        # SIGKILL the PARENT — the process that spawned the destruction tool.
        if enforce and ppid > 0:
            try:
                os.kill(ppid, 9)
            except OSError:
                pass
            try:
                b["blocked_pids"][b["blocked_pids"].Key(ppid)] = b["blocked_pids"].Leaf(1)
            except Exception:
                pass
            _contain_q.put_nowait((ppid, comm, "execve"))
        try:
            _score_q.put_nowait((event, ppid, ""))
        except Exception:
            _emit(event)
    b["exec_events"].open_perf_buffer(_handle_exec, page_cnt=64)

    # ── BUG 3: canary attempt handler ──────────────────────────────────────
    # Receives canary_event_t from BOTH kernel sources: the LSM hooks (op=1
    # rename / op=2 write, blocked=1 — the kernel denied the operation inline)
    # and kprobe__vfs_write (op=2, blocked=0 — SIGSTOP-fallback path, or the
    # vfs_write entry that precedes an LSM deny). Emits CANARY_ATTEMPT when the
    # kernel blocked the op, CANARY_TOUCHED when it went through, and arms
    # containment either way — the process tried once and will try again.
    _canary_path_by_inode: Dict[int, str] = {}
    for _cp in canary_paths:
        try:
            _canary_path_by_inode[os.stat(_cp).st_ino] = os.path.normpath(_cp)
        except OSError:
            pass
    _canary_last_seen: Dict[int, float] = {}

    def _handle_canary(cpu, data, size):
        ev   = b["canary_events"].event(data)
        pid  = ev.pid
        comm = ev.comm.decode(errors="replace").rstrip("\x00")
        ts   = time.time()
        # Safelist gate first — same contract as every other handler.
        if pid == engine.self_pid or comm in engine.ignore_comms:
            return
        # Dedupe: one attempt can surface twice (vfs_write kprobe + LSM deny),
        # and a retry loop would flood otherwise. 2s per PID matches the
        # engine's alert cooldown.
        last = _canary_last_seen.get(pid)
        if last is not None and ts - last < 2.0:
            return
        _canary_last_seen[pid] = ts

        blocked = bool(getattr(ev, "blocked", 0))
        path    = _canary_path_by_inode.get(ev.inode, "")
        event   = engine._make_event(
            "CANARY_ATTEMPT" if blocked else "CANARY_TOUCHED",
            "CRITICAL", pid, ev.ppid, comm, path, path, ts,
            extra={
                "trigger":     "canary_write" if ev.op == 2 else "canary_rename",
                "inode":       ev.inode,
                "lsm_blocked": blocked,
                "decided_in":  "kernel",
                "mitre":       "T1486",   # Data Encrypted for Impact (attempt)
            },
        )
        event["canary_hit"] = True
        engine._active_pids.add(pid)
        if enforce and pid > 0:
            try:
                b["blocked_pids"][b["blocked_pids"].Key(pid)] = b["blocked_pids"].Leaf(1)
            except Exception:
                pass
            _contain_q.put_nowait((pid, comm, "canary"))
        try:
            _score_q.put_nowait((event, pid, path))
        except Exception:
            _emit(event)

    b["canary_events"].open_perf_buffer(_handle_canary, page_cnt=64)
    print("[ebpf] probes loaded — listening...")

    # Warm up
    for _ in range(10):
        b.perf_buffer_poll(timeout=0)

    # If sim_fn provided run it then drain events
    if sim_fn is not None:
        import sys as _sys
        _sys.path.insert(0, '/home/kali/hybrid-rsentry')
        _sys.path.insert(0, '/home/kali/hybrid-rsentry/simulations')
        sim_fn(b)
        return

    try:
        while True:
            b.perf_buffer_poll(timeout=1)
            if stop_event and stop_event.is_set():
                break
    except KeyboardInterrupt:
        pass
    finally:
        print("[ebpf] shutting down")


# ---------------------------------------------------------------------------
# Self-test (no root, no BCC required)
# ---------------------------------------------------------------------------

def _selftest() -> int:
    failures = 0

    def check(name: str, cond: bool) -> None:
        nonlocal failures
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures += 1

    # ── severity rule chain ──────────────────────────────────────────
    print("severity rule chain")
    eng = DetectionEngine("t", ["/tmp"], self_pid=1)
    check("canary -> CRITICAL",      eng._severity(True,  0,    0)   == "CRITICAL")
    check("combined>=70 -> CRITICAL",eng._severity(False, 100,  8)   == "CRITICAL")
    check("40<=combined<70 -> HIGH", eng._severity(False, 70,   0)   == "HIGH")
    check("entropy>3.5 -> MEDIUM",   eng._severity(False, 0,    4.0) == "MEDIUM")
    check("low -> LOW",              eng._severity(False, 0,    0)   == "LOW")

    # ── canary detection ─────────────────────────────────────────────
    print("canary detection")
    td = tempfile.mkdtemp()
    try:
        cp = Path(td) / "AAA_rsentry_canary0.docx"
        cp.write_bytes(b"decoy")
        eng2 = DetectionEngine("t", [td], canary_paths=[str(cp)], self_pid=1)
        evt = eng2.observe_rename(42, 1, "evil", str(cp), str(cp)+".enc", ts=1.0)
        check("AAA_ rename -> CRITICAL", evt is not None and evt["severity"] == "CRITICAL")
        check("canary schema valid", evt is not None and all(
            k in evt for k in ["host_id","timestamp","event_type","severity",
                               "pid","process_name","file_path",
                               "lineage_score","entropy_delta","canary_hit","details"]))
        # write-by-inode
        inode = cp.stat().st_ino
        eng3 = DetectionEngine("t", [td], self_pid=1)
        eng3.canary_inodes.add(inode)
        evt2 = eng3.observe_write(42, 1, "evil", inode, str(cp), ts=2.0)
        check("canary write by inode -> CRITICAL",
              evt2 is not None and evt2["severity"] == "CRITICAL")
    finally:
        shutil.rmtree(td, ignore_errors=True)

    # ── velocity burst ───────────────────────────────────────────────
    print("userspace velocity burst (rename path)")
    td2 = tempfile.mkdtemp()
    try:
        eng4 = DetectionEngine("t", [td2], velocity_threshold=2,
                               window_seconds=5.0, self_pid=1)
        r1 = eng4.observe_rename(99, 1, "evil",
             td2+"/a.doc", td2+"/a.q7w2e9r4t1y6", ts=1.0)
        check("no alert file 1", r1 is None)
        r2 = eng4.observe_rename(99, 1, "evil",
             td2+"/b.doc", td2+"/b.z3x8c5v0b2n7", ts=1.5)
        check("alert on file 2", r2 is not None)
        check("burst schema valid", r2 is not None and "velocity" in r2["details"])
        check("PID attributed", r2 is not None and r2["pid"] == 99)
    finally:
        shutil.rmtree(td2, ignore_errors=True)

    # ── family profiling ─────────────────────────────────────────────
    print("family profiling")
    eng6 = DetectionEngine("t", ["/tmp"], self_pid=1)
    check("akira-like profiled",
          eng6._profile_family("/tmp/x.akiranew", []) == "akira")
    check("lockbit5-like profiled",
          eng6._profile_family("/tmp/x.abcdefghijklmnop", []) == "lockbit5")
    check("esxi-targeting profiled",
          eng6._profile_family("/tmp/x.enc",
              ["/vmfs/volumes/ds/vm.vmdk"]) == "esxi-targeting")

    # ── noise suppression ────────────────────────────────────────────
    print("noise suppression / safety")
    eng7 = DetectionEngine("t", ["/tmp"], self_pid=os.getpid())
    r = eng7.observe_rename(os.getpid(), 1, "monitor",
                            "/tmp/a", "/tmp/a.enc", ts=1.0)
    check("own PID ignored", r is None)

    eng8 = DetectionEngine("t", ["/tmp"], self_pid=1)
    r2 = eng8.observe_rename(42, 1, "rsync",
                             "/tmp/a", "/tmp/a.enc", ts=1.0)
    check("NEVER_AUTO_KILL comm ignored", r2 is None)

    eng9 = DetectionEngine("t", ["/tmp"], self_pid=1)
    eng9.suppress_path("/tmp/AAA_c.txt", ttl=15.0)
    r3 = eng9.observe_rename(42, 1, "adaptive",
                             "/tmp/AAA_c.txt", "/tmp/sub/AAA_c.txt", ts=1.0)
    check("Markov self-move suppressed", r3 is None)

    # ── BUG 2 regression: scripting interpreters must never be safelisted ──
    # `python3` in IGNORE_COMMS suppressed every detection layer for any
    # ransomware launched as `python3 -m ...` (live-confirmed with sim_akira/
    # sim_qilin/sim_lockbit). Celery/uvicorn workers have their own comms.
    print("BUG 2 regression: python3 never safelisted")
    check("no python* comm in IGNORE_COMMS",
          not any(c.lower().startswith("python") for c in IGNORE_COMMS))
    eng_py = DetectionEngine("t", ["/tmp"], velocity_threshold=2,
                             window_seconds=5.0, self_pid=1)
    eng_py.observe_rename(88, 1, "python3",
                          "/tmp/a.doc", "/tmp/a.q7w2e9r4t1y6", ts=1.0)
    r_py = eng_py.observe_rename(88, 1, "python3",
                                 "/tmp/b.doc", "/tmp/b.z3x8c5v0b2n7", ts=1.5)
    check("comm=python3 rename burst alerts", r_py is not None)
    rw_py = None
    eng_pw = DetectionEngine("t", ["/tmp"], self_pid=1)
    eng_pw.observe_write_offset(89, 1, "python3", 9, 0, 4096, "/tmp/g.dat", ts=0.0)
    for i in range(1, 8):
        rw_py = eng_pw.observe_write_offset(89, 1, "python3", 9, i * 16, 4096,
                                            "/tmp/g.dat", ts=float(i))
        if rw_py is not None:
            break
    check("comm=python3 silent-encryption storm alerts", rw_py is not None)

    # ── benign activity ──────────────────────────────────────────────
    print("benign activity")
    eng10 = DetectionEngine("t", ["/tmp"], self_pid=1)
    for i in range(5):
        r = eng10.observe_rename(77, 1, "backup",
            f"/tmp/file{i}.doc", f"/tmp/file{i}.bak", ts=float(i))
    check("benign .bak renames never alert", r is None)

    # ── regression: cooldown doesn't eat first alert ─────────────────
    print("regression: first alert not eaten by cooldown at small ts")
    td3 = tempfile.mkdtemp()
    try:
        eng11 = DetectionEngine("t", [td3], velocity_threshold=2,
                                window_seconds=5.0, self_pid=1)
        eng11.observe_rename(11, 1, "evil",
            td3+"/a.doc", td3+"/a.q7w2e9r4t1y6", ts=0.001)
        r = eng11.observe_rename(11, 1, "evil",
            td3+"/b.doc", td3+"/b.z3x8c5v0b2n7", ts=0.002)
        check("alert fires at ts~0", r is not None)
    finally:
        shutil.rmtree(td3, ignore_errors=True)

    # ── option A: system-wide capture ────────────────────────────────
    print("option A: system-wide encrypted-rename capture (outside watch dir)")
    td4 = tempfile.mkdtemp()
    outside = tempfile.mkdtemp()
    try:
        eng12 = DetectionEngine("t", [td4], velocity_threshold=2,
                                window_seconds=5.0, self_pid=1)
        eng12.observe_rename(22, 1, "evil",
            outside+"/x.doc", outside+"/x.q7w2e9r4t1y6", ts=1.0)
        r = eng12.observe_rename(22, 1, "evil",
            outside+"/y.doc", outside+"/y.z3x8c5v0b2n7", ts=1.5)
        check("rename OUTSIDE watch dir still alerts", r is not None)
        check("out-of-scope flagged in details",
              r is not None and r["details"].get("outside_watch") is True)
        check("out-of-scope PID still armed for write watch",
              22 in eng12._active_pids)
        # in-scope rename should NOT be flagged as outside
        eng13 = DetectionEngine("t", [td4], velocity_threshold=2,
                                window_seconds=5.0, self_pid=1)
        eng13.observe_rename(33, 1, "evil",
            td4+"/a.doc", td4+"/a.q7w2e9r4t1y6", ts=1.0)
        r2 = eng13.observe_rename(33, 1, "evil",
            td4+"/b.doc", td4+"/b.z3x8c5v0b2n7", ts=1.5)
        check("in-scope hit NOT flagged outside_watch",
              r2 is not None and not r2["details"].get("outside_watch"))
        # benign outside watch dir still ignored
        eng14 = DetectionEngine("t", [td4], velocity_threshold=2,
                                window_seconds=5.0, self_pid=1)
        for i in range(5):
            rb = eng14.observe_rename(44, 1, "backup",
                outside+f"/f{i}.doc", outside+f"/f{i}.bak", ts=float(i))
        check("benign rename outside watch dir still ignored", rb is None)
    finally:
        shutil.rmtree(td4, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)

    # ── seed_canaries ────────────────────────────────────────────────
    print("seed_canaries: placement + naming consistency")
    td5 = tempfile.mkdtemp()
    try:
        sub = Path(td5) / "sub" / "deep"
        sub.mkdir(parents=True)
        git = Path(td5) / ".git"
        git.mkdir()
        paths = seed_canaries([td5], per_dir=2)
        check("canaries created", len(paths) > 0)
        check("seeded in deep dirs too",
              any("deep" in p for p in paths))
        check(".git skipped",
              not any(".git" in p for p in paths))
        check("uses AAA_/zzz_ prefixes",
              all(os.path.basename(p).startswith(("AAA_", "aaa_", "ZZZ_", "zzz_")) for p in paths))
        check("attractive extensions",
              all(Path(p).suffix in ATTRACTIVE_EXTS for p in paths))
        check("files actually exist on disk",
              all(os.path.exists(p) for p in paths))
        # seeded canary rename fires CRITICAL
        eng15 = DetectionEngine("t", [td5], canary_paths=paths, self_pid=1)
        cp0 = paths[0]
        evt = eng15.observe_rename(42, 1, "evil",
                                   cp0, cp0+".enc", ts=1.0)
        check("seeded canary rename -> CRITICAL",
              evt is not None and evt["severity"] == "CRITICAL")
        # write-by-inode
        inode = os.stat(cp0).st_ino
        evt2 = eng15.observe_write(42, 1, "evil", inode, cp0, ts=2.0)
        check("seeded canary write-by-inode -> CRITICAL",
              evt2 is not None and evt2["severity"] == "CRITICAL")
        # dry-run
        dry = seed_canaries([td5], per_dir=1, dry_run=True)
        check("dry-run reports paths", len(dry) > 0)
    finally:
        shutil.rmtree(td5, ignore_errors=True)

    # ── Feature 2: entropy-based ransomware-extension filter ──────────
    print("entropy-based extension filter")
    enge2 = DetectionEngine("t", ["/tmp"], self_pid=1)
    check("normal .docx NOT flagged",  not enge2._looks_encrypted("/tmp/report.docx"))
    check("normal .pdf NOT flagged",   not enge2._looks_encrypted("/tmp/report.pdf"))
    check("normal .xlsx NOT flagged",  not enge2._looks_encrypted("/tmp/sheet.xlsx"))
    check("normal .jpg NOT flagged",   not enge2._looks_encrypted("/tmp/pic.jpg"))
    check("high-entropy 8-char ext flagged",  enge2._looks_encrypted("/tmp/x.x7k2p9qm"))
    check("high-entropy 16-char ext flagged", enge2._looks_encrypted("/tmp/x.abcdefghijklmnop"))
    check("short high-entropy ext flagged (length-independent, <old 8-char min)",
          enge2._looks_encrypted("/tmp/x.q7w2e9"))
    check("known .enc suffix still flagged", enge2._looks_encrypted("/tmp/x.enc"))
    check("benign .bak never flagged",       not enge2._looks_encrypted("/tmp/x.bak"))
    check("low-entropy repeated ext NOT flagged",
          not enge2._looks_encrypted("/tmp/x.aaaaaaaaaaaa"))
    check("_shannon_entropy empty -> 0.0", _shannon_entropy("") == 0.0)
    check("_shannon_entropy docx < threshold",
          _shannon_entropy("docx") < _EXT_ENTROPY_THRESHOLD)
    check("_shannon_entropy 16-random >= threshold",
          _shannon_entropy("abcdefghijklmnop") >= _EXT_ENTROPY_THRESHOLD)

    # ── Feature 1: write-offset silent-encryption detection ───────────
    print("write-offset silent-encryption detection")
    engw = DetectionEngine("t", ["/tmp"], self_pid=1)
    # Sequential append writes: offset always == previous end → never alerts.
    seq = None
    for off in range(0, 4096 * 8, 4096):
        seq = engw.observe_write_offset(70, 1, "writer", 1234, off, 4096, "/tmp/f.dat", ts=float(off))
    check("sequential writes never alert", seq is None)
    # Non-sequential rewrites to the same inode → SILENT_ENCRYPTION after threshold.
    enge = DetectionEngine("t", ["/tmp"], self_pid=1)
    enge.observe_write_offset(71, 1, "locker", 9, 0, 4096, "/tmp/g.dat", ts=0.0)  # baseline
    nonseq_evt = None
    for i in range(1, 8):
        # jump to a fresh offset each time (classic in-place block cipher pattern)
        _r = enge.observe_write_offset(71, 1, "locker", 9, i * 16, 4096, "/tmp/g.dat", ts=float(i))
        if _r is not None:
            nonseq_evt = _r
            break
    check("non-sequential storm -> SILENT_ENCRYPTION",
          nonseq_evt is not None and nonseq_evt["event_type"] == "SILENT_ENCRYPTION")
    check("silent-encryption freezes PID", 71 in enge._frozen_pids)
    check("silent-encryption arms active_pids", 71 in enge._active_pids)
    check("silent-encryption HIGH severity",
          nonseq_evt is not None and nonseq_evt["severity"] == "HIGH")
    # Own PID and ignored comms never alert.
    engx = DetectionEngine("t", ["/tmp"], self_pid=99)
    rx = engx.observe_write_offset(99, 1, "monitor", 5, 100, 10, "/tmp/h", ts=1.0)
    check("own PID write-offset ignored", rx is None)
    # BPF source carries the offset map + kernel detection wiring.
    _src1 = build_bpf(enforce=True, lsm=True)
    check("bpf source declares write_offset map", "write_offset" in _src1)
    check("bpf source defines NONSEQ_THRESH", "NONSEQ_THRESH" in _src1)
    check("bpf source carries silent_enc flag", "silent_enc" in _src1)
    # ── Feature 1 ORDERING (the detection-suppression bug fix): inside
    # kprobe__vfs_write the cheap host-wide write-offset counter MUST run BEFORE
    # the per-PID rate limiter, otherwise a fast attacker (>RATE_LIMIT writes/ms —
    # the real ransomware signature) trips __rate_limited and its writes never
    # reach the non-sequential counter, so Defense #1 never fires on a live attack.
    import inspect as _inspect_ord
    _vfs = build_bpf(enforce=True, lsm=True)
    _vfs_body = _vfs[_vfs.index("int kprobe__vfs_write"):_vfs.index("// ── Execve handler")]
    _i_offset = _vfs_body.index("write_offset.lookup")        # cheap counter
    _i_rl     = _vfs_body.index("if (__rate_limited(pid, ts)) return 0;")
    check("write-offset counter runs BEFORE rate limiter in vfs_write",
          _i_offset < _i_rl)
    # Critical-event bypass: a confirmed silent_enc detection emits + freezes even
    # while rate-limited (it sits above the {_rl_check} line).
    _i_bypass = _vfs_body.index("CRITICAL EVENT BYPASS")
    check("silent_enc critical bypass precedes rate limiter",
          _i_bypass < _i_rl)
    check("vfs_write has post-freeze throttle (suppress duplicate emits)",
          "POST-FREEZE THROTTLE" in _vfs_body
          and "if (blocked && *blocked) return 0;" in _vfs_body)

    # ── Feature 1 SAFELIST: container runtimes / system daemons must never be
    # flagged or contained by the write-offset detector, even under a full
    # non-sequential write storm. The kernel probe has no comm safelist, so the
    # userspace path is the authority (regression guard for the dockerd/
    # containerd/runc SIGKILL incident).
    print("write-offset safelist (container runtimes never flagged)")
    _runtimes = ("dockerd", "containerd", "runc", "containerd-shi", "postgres", "redis-server")
    for _rt in _runtimes:
        eng_rt = DetectionEngine("t", ["/var/lib/docker"], self_pid=1)
        # baseline write, then a sustained non-sequential storm (well past threshold)
        eng_rt.observe_write_offset(4242, 1, _rt, 77, 0, 4096, "/var/lib/docker/img.bin", ts=0.0)
        flagged = None
        for i in range(1, 15):
            r = eng_rt.observe_write_offset(4242, 1, _rt, 77, i * 4096 * 7, 4096,
                                            "/var/lib/docker/img.bin", ts=float(i))
            if r is not None:
                flagged = r
                break
        check(f"{_rt} non-seq storm NOT flagged", flagged is None)
        check(f"{_rt} NOT frozen (no containment)", 4242 not in eng_rt._frozen_pids)
        check(f"{_rt} NOT armed active", 4242 not in eng_rt._active_pids)
    # Positive control — an identical storm from a NON-safelisted comm IS flagged,
    # proving the test exercises the real detection path, not a dead branch.
    eng_ctl = DetectionEngine("t", ["/var/lib/docker"], self_pid=1)
    eng_ctl.observe_write_offset(4243, 1, "evil-locker", 78, 0, 4096, "/data/x", ts=0.0)
    ctl = None
    for i in range(1, 15):
        ctl = eng_ctl.observe_write_offset(4243, 1, "evil-locker", 78, i * 4096 * 7, 4096,
                                           "/data/x", ts=float(i))
        if ctl is not None:
            break
    check("non-safelisted comm IS flagged (positive control)",
          ctl is not None and ctl["event_type"] == "SILENT_ENCRYPTION")
    check("positive control freezes PID", 4243 in eng_ctl._frozen_pids)
    # Handler-level gate present in source: the kernel has no comm safelist, so
    # _handle_write / _handle_exec must short-circuit safelisted comms BEFORE the
    # `or _make_event()` / fabricated-event fallback that triggers containment.
    import inspect as _inspect
    _run_src = _inspect.getsource(run_sensor)
    _hw = _run_src[_run_src.index("def _handle_write"):_run_src.index("def _handle_behavior")]
    check("_handle_write gates self_pid/ignore_comms before containment",
          "comm in engine.ignore_comms" in _hw and "return" in _hw.split("ev.inode")[0])
    _he = _run_src[_run_src.index("def _handle_exec"):]
    # Guard must appear before the real call `engine.observe_execve(` (not the
    # comment that mentions observe_execve()), i.e. before any fabricate/kill.
    check("_handle_exec gates self_pid/ignore_comms before fabricated kill",
          "comm in engine.ignore_comms" in _he.split("engine.observe_execve(")[0])

    # ── Feature 4: execve backup-destruction blocking ────────────────
    print("execve backup-destruction blocking")
    enge4 = DetectionEngine("t", ["/tmp"], self_pid=1)
    ev_v = enge4.observe_execve(200, 150, "sh",
                                ["vssadmin", "delete", "shadows", "/all", "/quiet"], ts=1.0)
    check("vssadmin -> BACKUP_DESTRUCTION",
          ev_v is not None and ev_v["event_type"] == "BACKUP_DESTRUCTION")
    check("backup-destruction is CRITICAL", ev_v is not None and ev_v["severity"] == "CRITICAL")
    check("execve marks parent for kill",
          ev_v is not None and ev_v["details"]["kill_parent"] == 150)
    check("execve freezes parent pid", 150 in enge4._frozen_pids)
    for kw in ("bcdedit", "wbadmin", "shadowcopy"):
        check(f"{kw} detected",
              enge4.observe_execve(201, 150, "sh", [f"/usr/bin/{kw}", "x"], ts=1.0) is not None)
    check("keyword inside a path argument detected",
          enge4.observe_execve(203, 150, "sh", ["/c/Windows/System32/vssadmin.exe"], ts=1.0) is not None)
    check("benign execve -> None",
          enge4.observe_execve(202, 150, "bash", ["ls", "-la", "/home"], ts=1.0) is None)
    check("empty argv -> None", enge4.observe_execve(204, 150, "sh", [], ts=1.0) is None)
    engself = DetectionEngine("t", ["/tmp"], self_pid=9)
    check("own pid execve ignored",
          engself.observe_execve(9, 1, "x", ["vssadmin", "delete"], ts=1.0) is None)
    _src4 = build_bpf(enforce=True, lsm=True)
    check("bpf source declares exec_events", "exec_events" in _src4)
    check("bpf source has backup-destruct matcher", "__is_backup_destruct" in _src4)
    check("bpf source sends SIGKILL on match", "bpf_send_signal(SIGKILL)" in _src4)
    check("bprm_check LSM hook present (enforce+lsm)", "bprm_check_security" in _src4)
    _src4a = build_bpf(enforce=False, lsm=False)
    check("audit build still detects (matcher present)", "__is_backup_destruct" in _src4a)
    check("audit build does not send SIGKILL", "bpf_send_signal(SIGKILL)" not in _src4a)

    # ── Feature 5: per-PID per-CPU rate limiting ─────────────────────
    print("per-PID rate limiting (kernel map + helper present)")
    _src5 = build_bpf(enforce=True, lsm=True)
    check("declares BPF_PERCPU_HASH rate map", "BPF_PERCPU_HASH(rate_state" in _src5)
    check("defines RATE_LIMIT 500", "#define RATE_LIMIT" in _src5 and "500" in _src5)
    check("defines __rate_limited helper", "__rate_limited" in _src5)
    check("rate check uses per-ms window", "ts / 1000000ULL" in _src5)
    # Every hot-path handler must gate on the limiter.
    check("rate check wired into >=4 handlers",
          _src5.count("if (__rate_limited(pid, ts)) return 0;") >= 4)

    # ── Feature 6: fail-secure heartbeat ─────────────────────────────
    print("fail-secure heartbeat (map + LSM staleness gate)")
    _src6 = build_bpf(enforce=True, lsm=True)
    check("declares BPF_ARRAY heartbeat map", "BPF_ARRAY(heartbeat" in _src6)
    check("defines HEARTBEAT_STALE_NS (2s)", "HEARTBEAT_STALE_NS  (2ULL" in _src6)
    check("defines __heartbeat_stale helper", "__heartbeat_stale()" in _src6)
    check("hb==0 treated as not-yet-initialized (no brick at startup)",
          "*hb == 0) return 0;" in _src6)
    # Both LSM hooks gate on staleness (path_rename + bprm_check).
    check("LSM hooks gate on heartbeat (>=2 call sites)",
          _src6.count("if (__heartbeat_stale()) return -EPERM;") >= 2)
    # Helper exists even without LSM (map always defined) but is NOT enforced.
    _src6n = build_bpf(enforce=False, lsm=False)
    check("audit build has no heartbeat -EPERM gate",
          "if (__heartbeat_stale()) return -EPERM;" not in _src6n)

    # ── BUG 3: LSM canary deny must emit a perf event BEFORE -EPERM ────
    print("BUG 3: canary attempt visible to userspace before LSM deny")
    import inspect as _insp
    _srcc = build_bpf(enforce=True, lsm=True)
    check("canary_events perf output declared",
          "BPF_PERF_OUTPUT(canary_events)" in _srcc)
    check("canary_event_t struct defined", "struct canary_event_t" in _srcc)
    check("__emit_canary_attempt helper present", "__emit_canary_attempt" in _srcc)
    _pr = _srcc[_srcc.index("LSM_PROBE(path_rename"):
                _srcc.index("LSM_PROBE(file_permission")]
    _branch = _pr[_pr.index("canary_inodes.lookup"):]
    check("path_rename submits attempt BEFORE -EPERM",
          "__emit_canary_attempt" in _branch
          and _branch.index("__emit_canary_attempt") < _branch.index("return -EPERM"))
    _fp = _srcc[_srcc.index("LSM_PROBE(file_permission"):]
    check("file_permission write-deny hook present (canary writes blocked)", True)
    check("file_permission gates on MAY_WRITE (reads unaffected)", "MAY_WRITE" in _fp)
    check("file_permission submits attempt BEFORE -EPERM",
          _fp.index("__emit_canary_attempt") < _fp.index("return -EPERM"))
    _run_src2 = _insp.getsource(run_sensor)
    check("_handle_canary registered on canary_events perf buffer",
          'b["canary_events"].open_perf_buffer(_handle_canary' in _run_src2)
    check("_handle_canary emits CANARY_ATTEMPT when kernel blocked",
          '"CANARY_ATTEMPT"' in _run_src2)
    check("_handle_canary arms containment layer=canary",
          '_contain_q.put_nowait((pid, comm, "canary"))' in _run_src2)
    check("canary inodes registered in every mode (not just enforce+lsm)",
          "if canary_paths:" in _run_src2)

    # ── W1: single canary write reaches userspace (no burst needed) ───
    print("W1: canary write emitted from vfs_write before any throttle")
    for _enf in (True, False):
        _v  = build_bpf(enforce=_enf, lsm=False)
        _vb = _v[_v.index("int kprobe__vfs_write"):_v.index("// ── Execve handler")]
        check(f"vfs_write checks canary_inodes (enforce={_enf})",
              "canary_inodes.lookup(&_ino)" in _vb)
        check(f"canary submit precedes rate limiter (enforce={_enf})",
              _vb.index("canary_events.perf_submit")
              < _vb.index("if (__rate_limited"))
        check(f"canary submit not gated by write burst (enforce={_enf})",
              _vb.index("canary_events.perf_submit")
              < _vb.index("WRITE_BURST_THRESH"))
    _vab = build_bpf(enforce=False, lsm=False)
    _vabb = _vab[_vab.index("int kprobe__vfs_write"):_vab.index("// ── Execve handler")]
    check("audit build does NOT arm blocked_pids on canary write",
          "_cone" not in _vabb)
    _veb = build_bpf(enforce=True, lsm=False)
    _vebb = _veb[_veb.index("int kprobe__vfs_write"):_veb.index("// ── Execve handler")]
    check("enforce build arms blocked_pids on canary write", "_cone" in _vebb)

    # ── BUG 4: --lsm/--no-lsm flag wiring ──────────────────────────────
    print("BUG 4: lsm parameter on run_sensor")
    _sigp = _insp.signature(run_sensor).parameters
    check("run_sensor accepts lsm param", "lsm" in _sigp)
    check("lsm defaults to auto-detect (None)", _sigp["lsm"].default is None)

    # ── W2/W3/W4 + layer threading ──────────────────────────────────────
    print("W2/W3/W4: containment wiring + layer attribution")
    _hw2 = _run_src2[_run_src2.index("def _handle_write"):
                     _run_src2.index("def _handle_behavior")]
    check("W2: observe_write branch queues containment",
          _hw2.count("_contain_q.put_nowait") >= 2)
    check("layer=rename wired",
          '_contain_q.put_nowait((pid, comm, "rename"))' in _run_src2)
    check("layer=write_offset wired",
          '_contain_q.put_nowait((pid, comm, "write_offset"))' in _run_src2)
    check("layer=entropy wired",
          '_contain_q.put_nowait((pid, comm, "entropy"))' in _run_src2)
    check("layer=execve wired",
          '_contain_q.put_nowait((ppid, comm, "execve"))' in _run_src2)
    check("W3: observe_kernel_burst removed (dead code)",
          not hasattr(DetectionEngine, "observe_kernel_burst"))
    check("W4: severity recomputed only for PROCESS_ANOMALY",
          'event["event_type"] == "PROCESS_ANOMALY"' in _run_src2)

    # ── BPF source generation ─────────────────────────────────────────
    print("BPF source generation (all variants compile to text)")
    for enforce in (True, False):
        for lsm in (True, False):
            src = build_bpf(enforce=enforce, lsm=lsm)
            check(f"build_bpf enforce={enforce} lsm={lsm}", isinstance(src, str) and len(src) > 100)
    eperm_src = build_bpf(enforce=True, lsm=True)
    check("enforce+lsm emits -EPERM", "-EPERM" in eperm_src)
    audit_src = build_bpf(enforce=False, lsm=True)
    check("audit+lsm has no -EPERM", "-EPERM" not in audit_src)

    print(f"\n{'='*52}\n{'ALL PASS' if not failures else str(failures)+' FAILED'}")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Hybrid R-Sentry eBPF sensor")
    ap.add_argument("--selftest",       action="store_true")
    ap.add_argument("--print-bpf",      action="store_true")
    ap.add_argument("--seed-canaries",  action="store_true")
    ap.add_argument("--seed-into",      default="/tmp/rsentry_lab")
    ap.add_argument("--per-dir",        type=int, default=2)
    ap.add_argument("--dry-run-seed",   action="store_true")
    ap.add_argument("--mode",           choices=["enforce","audit"], default="enforce")
    # BUG 4 fix: tri-state LSM control. Absent = auto-detect kernel support;
    # --lsm forces inline-LSM-deny; --no-lsm forces SIGSTOP-fallback.
    ap.add_argument("--lsm",            action=argparse.BooleanOptionalAction,
                    default=None,
                    help="force BPF-LSM inline blocking on/off "
                         "(default: auto-detect kernel support)")
    ap.add_argument("--watch",          action="append", default=None)
    ap.add_argument("--canary",         action="append", default=None)
    ap.add_argument("--threshold",      type=int, default=2)
    ap.add_argument("--window",         type=float, default=3.0)
    ap.add_argument("--host-id",        default="00000000-0000-0000-0000-000000000001")
    ap.add_argument("--run-sim",        default=None, help="run sim script after probe loads (path to sim module)")
    ap.add_argument("--sim-target",     default="/tmp/rsentry_lab")
    ap.add_argument("--sim-traversal",  default="dfs")
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(_selftest())

    if args.seed_canaries:
        paths = seed_canaries([args.seed_into], per_dir=args.per_dir,
                              dry_run=args.dry_run_seed)
        for p in paths:
            print(p)
        raise SystemExit(0)

    if args.print_bpf:
        lsm = Path("/sys/kernel/security/lsm").read_text() if \
              Path("/sys/kernel/security/lsm").exists() else ""
        print(build_bpf(enforce=(args.mode=="enforce"), lsm=("bpf" in lsm)))
        raise SystemExit(0)

    watch   = args.watch   or ["/tmp/rsentry_lab"]
    canaries= args.canary  or []

    sim_fn = None
    if args.run_sim:
        import importlib.util as _ilu
        import sys as _sys
        _sys.path.insert(0, '/home/kali/hybrid-rsentry')
        _sys.path.insert(0, '/home/kali/hybrid-rsentry/simulations')
        _spec = _ilu.spec_from_file_location("_sim", args.run_sim)
        _mod  = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        from simulations.sim_common import enumerate_targets, _prioritise
        import os as _os
        def sim_fn(b):
            targets = enumerate_targets(args.sim_target, args.sim_traversal)
            targets = _prioritise(targets, _mod.PROFILE.priority_exts)
            print(f"[sim] encrypting {len(targets)} files...")
            for path in targets:
                try:
                    _os.rename(path, path + "." + _mod.PROFILE.ext_fn())
                except OSError:
                    pass
                b.perf_buffer_poll(timeout=0)
            # drain remaining
            for _ in range(200):
                b.perf_buffer_poll(timeout=0)
            print("[sim] done")

    run_sensor(
        watch_dirs     = watch,
        canary_paths   = canaries,
        host_id        = args.host_id,
        mode           = args.mode,
        threshold      = args.threshold,
        window_seconds = args.window,
        sim_fn         = sim_fn,
        lsm            = args.lsm,
    )
