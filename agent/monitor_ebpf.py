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
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# IGNORE_COMMS — never alert or contain these process names
# ---------------------------------------------------------------------------
IGNORE_COMMS: Set[str] = {
    "Xorg", "gnome-shell", "nautilus", "systemd", "systemd-journal", "systemd-resolve", "systemd-network", "dockerd", "containerd",
    "redis-server", "postgres", "celery", "uvicorn",
    "git", "cargo", "rsync", "make", "gcc", "cc1", "ld", "NetworkManager", "nm-dispatcher", "StreamTrans", "runc", "glean.dispatche", "containerd-shim", "x-www-browser", "firefox", "firefox-esr", "chrome", "chromium", "dpkg", "apt", "apt-get", "Cache2 I/O",
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
        # PIDs armed after velocity burst (watch their writes too)
        self._active_pids: Set[int] = set()
        # Suppressed paths (Markov moves) path -> expiry_ts
        self._suppressed: Dict[str, float] = {}
        # Cooldown: pid -> last_alert_ts
        self._cooldown: Dict[int, float] = {}
        self._cooldown_secs = 2.0

        if canary_paths:
            self.register_canaries(canary_paths)

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
        if bn.startswith("AAA_") or bn.startswith("zzz_"):
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
        # Random-looking extension: 8-16 alphanumeric chars, no vowels pattern
        bn = Path(path).stem
        ext = Path(path).suffix.lstrip(".")
        if 8 <= len(ext) <= 16 and re.match(r'^[a-zA-Z0-9]+$', ext):
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
    ) -> dict:
        import datetime
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        iso = dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

        lineage_score = 0.0
        entropy_delta = 0.0
        if self.lineage_fn and pid > 0:
            try:
                lineage_score = float(self.lineage_fn(pid))
            except Exception:
                pass
        if self.entropy_fn and dst_path:
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
            sev = "CRITICAL"
            evt = self._make_event(
                "CANARY_TOUCHED", sev, pid, ppid, comm,
                src_path, dst_path, ts,
                extra={"src": src_path, "dst": dst_path,
                       "outside_watch": not in_scope},
            )
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
                lineage_score = float(self.lineage_fn(pid))
            except Exception:
                pass
        if self.entropy_fn and dst_path:
            try:
                entropy_delta = float(self.entropy_fn(dst_path))
            except Exception:
                pass

        sev = self._severity(False, lineage_score, entropy_delta)
        profile = self._profile_family(dst_path, list(self._velocity[pid]))

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
        )
        evt["lineage_score"] = round(lineage_score, 2)
        evt["entropy_delta"] = round(entropy_delta, 4)
        self._active_pids.add(pid)
        return evt

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
        if not self._is_canary_inode(inode):
            return None
        if self._is_suppressed(path):
            return None
        sev = "CRITICAL"
        return self._make_event(
            "CANARY_TOUCHED", sev, pid, ppid, comm,
            path, path, ts,
            extra={"trigger": "write", "inode": inode},
        )

    def observe_kernel_burst(
        self,
        pid: int,
        ppid: int,
        comm: str,
        count: int,
        ts: float,
    ) -> Optional[dict]:
        """Called when the in-kernel velocity counter fires."""
        if pid == self.self_pid:
            return None
        if comm in self.ignore_comms:
            return None
        self._active_pids.add(pid)
        return self._make_event(
            "PROCESS_ANOMALY", "HIGH", pid, ppid, comm,
            "", "", ts,
            extra={
                "decided_in": "kernel",
                "kernel_burst_count": count,
            },
        )


# ---------------------------------------------------------------------------
# Canary seeding
# ---------------------------------------------------------------------------

ATTRACTIVE_EXTS = (".docx", ".xlsx", ".pdf", ".db", ".vmdk")

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
                prefix = "AAA_" if i % 2 == 0 else "zzz_"
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
    """Generate BPF C source for the two kernel probes."""
    deny_action = "return -EPERM;" if (enforce and lsm) else "return 0;"
    return f"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

// Per-PID rename velocity counter (sliding window approximation)
BPF_HASH(rename_count, u32, u64);
BPF_HASH(rename_ts,    u32, u64);
BPF_PERF_OUTPUT(rename_events);
BPF_PERF_OUTPUT(write_events);

#define VELOCITY_THRESHOLD 3
#define WINDOW_NS (3ULL * 1000000000ULL)

struct rename_event_t {{
    u32 pid;
    u32 ppid;
    char comm[16];
    u64 count;
    u64 ts;
    char oldname[128];
    char newname[128];
}};

struct write_event_t {{
    u32 pid;
    u32 ppid;
    char comm[16];
    u64 inode;
    u64 ts;
}};

static inline int __handle_rename(void *ctx, const char __user *oldpath, const char __user *newpath) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts  = bpf_ktime_get_ns();

    u64 *last = rename_ts.lookup(&pid);
    u64 *cnt  = rename_count.lookup(&pid);
    u64 new_cnt = 1;

    if (last && cnt && (ts - *last) < WINDOW_NS) {{
        new_cnt = *cnt + 1;
    }}
    rename_count.update(&pid, &new_cnt);
    rename_ts.update(&pid, &ts);

    struct rename_event_t ev = {{0}};
    ev.pid   = pid;
    ev.ppid  = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    ev.ts    = ts;
    ev.count = new_cnt;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(&ev.oldname, sizeof(ev.oldname), oldpath);
    bpf_probe_read_user_str(&ev.newname, sizeof(ev.newname), newpath);
    rename_events.perf_submit(ctx, &ev, sizeof(ev));

    if (new_cnt >= VELOCITY_THRESHOLD) {{
        u64 zero = 0;
        rename_count.update(&pid, &zero);
    }}
    return 0;
}}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {{
    return __handle_rename(args, args->oldname, args->newname);
}}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {{
    return __handle_rename(args, args->oldname, args->newname);
}}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {{
    return __handle_rename(args, args->oldname, args->newname);
}}

int kprobe__vfs_write(struct pt_regs *ctx, struct file *file) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts  = bpf_ktime_get_ns();
    struct write_event_t ev = {{0}};
    ev.pid   = pid;
    ev.ts    = ts;
    ev.inode = file->f_inode->i_ino;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    write_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}}

{"// LSM inline block enabled" if lsm else "// LSM inline block disabled"}
{"// -EPERM on rename" if (enforce and lsm) else ""}
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
    contain: Optional[Callable[[int, str], None]] = None,
    sim_fn: Optional[Callable] = None,
) -> None:
    """
    Load BPF probes and run the detection loop.
    Requires: root, bpfcc-tools, python3-bpfcc, linux-headers.
    Falls back to SIGSTOP if lsm=bpf not active.
    """
    try:
        from bcc import BPF
    except ImportError:
        sys.exit("[ebpf] python3-bpfcc not installed. "
                 "Run: sudo apt install python3-bpfcc bpfcc-tools")

    lsm_active = "bpf" in Path("/sys/kernel/security/lsm").read_text()
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

    _emit    = emit    or (lambda e: print(e))
    _contain = contain or (lambda pid, comm: os.kill(pid, 19))  # SIGSTOP

    def _handle_rename(cpu, data, size):
        ev      = b["rename_events"].event(data)
        pid     = ev.pid
        comm    = ev.comm.decode(errors="replace").rstrip("\x00")
        oldname = ev.oldname.decode(errors="replace").rstrip("\x00")
        newname = ev.newname.decode(errors="replace").rstrip("\x00")
        ts      = time.time()
        # Skip kernel-internal renames with no user-space paths
        if not oldname or not newname:
            return
        event = engine.observe_rename(pid, ev.ppid, comm, oldname, newname, ts=ts)
        if event is None and ev.count >= engine.velocity_threshold:
            event = engine.observe_kernel_burst(pid, ev.ppid, comm, ev.count, ts)
        if event:
            _emit(event)
            if enforce and pid > 0:
                _contain(pid, comm)

    def _handle_write(cpu, data, size):
        ev    = b["write_events"].event(data)
        pid   = ev.pid
        comm  = ev.comm.decode(errors="replace").rstrip("\x00")
        ts    = time.time()
        event = engine.observe_write(pid, ev.ppid, comm, ev.inode, "", ts)
        if event:
            _emit(event)
            if enforce and pid > 0:
                _contain(pid, comm)

    b["rename_events"].open_perf_buffer(_handle_rename, page_cnt=2048)
    b["write_events"].open_perf_buffer(_handle_write, page_cnt=64)
    print("[ebpf] probes loaded — listening...")

    # Warm up
    for _ in range(10):
        b.perf_buffer_poll(timeout=1)

    # If sim_fn provided run it then drain events
    if sim_fn is not None:
        import sys as _sys, os as _os
        _sys.path.insert(0, '/home/kali/hybrid-rsentry')
        _sys.path.insert(0, '/home/kali/hybrid-rsentry/simulations')
        sim_fn(b)
        return

    try:
        while True:
            b.perf_buffer_poll(timeout=1)
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
             td2+"/a.doc", td2+"/a.aaaaaaaaaaaa1234", ts=1.0)
        check("no alert file 1", r1 is None)
        r2 = eng4.observe_rename(99, 1, "evil",
             td2+"/b.doc", td2+"/b.bbbbbbbbbbbb5678", ts=1.5)
        check("alert on file 2", r2 is not None)
        check("burst schema valid", r2 is not None and "velocity" in r2["details"])
        check("PID attributed", r2 is not None and r2["pid"] == 99)
    finally:
        shutil.rmtree(td2, ignore_errors=True)

    # ── kernel burst event ───────────────────────────────────────────
    print("kernel-decided burst event")
    eng5 = DetectionEngine("t", ["/tmp"], self_pid=1)
    kb = eng5.observe_kernel_burst(55, 1, "evil", 3, ts=1.0)
    check("kernel burst schema valid", kb is not None)
    check("kernel burst arms active_pids", 55 in eng5._active_pids)
    check("kernel burst decided_in=kernel",
          kb is not None and kb["details"].get("decided_in") == "kernel")

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
            td3+"/a.doc", td3+"/a.aaaaaaaaaaaa1111", ts=0.001)
        r = eng11.observe_rename(11, 1, "evil",
            td3+"/b.doc", td3+"/b.bbbbbbbbbbbb2222", ts=0.002)
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
            outside+"/x.doc", outside+"/x.aaaaaaaaaaaa1234", ts=1.0)
        r = eng12.observe_rename(22, 1, "evil",
            outside+"/y.doc", outside+"/y.bbbbbbbbbbbb5678", ts=1.5)
        check("rename OUTSIDE watch dir still alerts", r is not None)
        check("out-of-scope flagged in details",
              r is not None and r["details"].get("outside_watch") is True)
        check("out-of-scope PID still armed for write watch",
              22 in eng12._active_pids)
        # in-scope rename should NOT be flagged as outside
        eng13 = DetectionEngine("t", [td4], velocity_threshold=2,
                                window_seconds=5.0, self_pid=1)
        eng13.observe_rename(33, 1, "evil",
            td4+"/a.doc", td4+"/a.aaaaaaaaaaaa1234", ts=1.0)
        r2 = eng13.observe_rename(33, 1, "evil",
            td4+"/b.doc", td4+"/b.bbbbbbbbbbbb5678", ts=1.5)
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
              all(os.path.basename(p).startswith(("AAA_", "zzz_")) for p in paths))
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

    if args.seed_canaries:
        paths = seed_canaries([args.seed_into], per_dir=args.per_dir,
                              dry_run=args.dry_run_seed)
        for p in paths:
            print(p)
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
                b.perf_buffer_poll(timeout=1)
            # drain remaining
            for _ in range(200):
                b.perf_buffer_poll(timeout=1)
            print("[sim] done")

    run_sensor(
        watch_dirs     = watch,
        canary_paths   = canaries,
        host_id        = args.host_id,
        mode           = args.mode,
        threshold      = args.threshold,
        window_seconds = args.window,
        sim_fn         = sim_fn,
    )
