"""
containment.py — SIGSTOP → evidence capture → iptables DROP → SIGKILL pipeline.
Requires root for iptables and /proc access.
"""
import logging
import os
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger(__name__)

EVIDENCE_BASE = Path("/tmp/rsentry_evidence")


class ContainmentResult:
    def __init__(self, pid: int):
        self.pid = pid                              # root PID
        self.descendants: list[int] = []            # descendant PIDs found at containment
        self.stopped = False                        # True if root SIGSTOP succeeded
        self.stopped_descendants: list[int] = []    # which descendants got SIGSTOP
        self.evidence_dir: Optional[Path] = None    # root dir; descendants in subdirs/
        self.evidence_files: list[str] = []
        self.iptables_rule: Optional[str] = None
        self.killed = False                         # True if root SIGKILL succeeded
        self.killed_descendants: list[int] = []     # which descendants got SIGKILL
        self.error: Optional[str] = None
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "descendants": self.descendants,
            "stopped": self.stopped,
            "stopped_descendants": self.stopped_descendants,
            "evidence_dir": str(self.evidence_dir) if self.evidence_dir else None,
            "evidence_files": self.evidence_files,
            "iptables_rule": self.iptables_rule,
            "killed": self.killed,
            "killed_descendants": self.killed_descendants,
            "error": self.error,
            "timestamp": self.timestamp,
            "tree_size": 1 + len(self.descendants),
        }


# ---------------------------------------------------------------------------
# Step 1 — SIGSTOP
# ---------------------------------------------------------------------------

def _sigstop(pid: int) -> bool:
    try:
        os.kill(pid, signal.SIGSTOP)
        logger.warning("SIGSTOP sent to PID %d", pid)
        return True
    except ProcessLookupError:
        logger.error("PID %d not found for SIGSTOP", pid)
        return False
    except PermissionError:
        logger.error("Permission denied sending SIGSTOP to PID %d", pid)
        return False


def _get_descendants(pid: int) -> list[int]:
    """Return all descendant PIDs (children, grandchildren, ...) of a process."""
    try:
        proc = psutil.Process(pid)
        return [child.pid for child in proc.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


def _freeze_tree(root_pid: int) -> tuple[bool, list[int], list[int]]:
    """
    SIGSTOP root then all descendants. Two-sweep to catch races where
    grandchildren spawn during first enumeration.

    Returns: (root_stopped, all_descendants_pids, descendants_actually_stopped)
    """
    # Stop root FIRST so it can't spawn new children during enumeration
    root_stopped = _sigstop(root_pid)
    descendants = _get_descendants(root_pid)
    stopped_descendants: list[int] = []
    for cpid in descendants:
        if _sigstop(cpid):
            stopped_descendants.append(cpid)
    # Second sweep — grandchildren may have spawned during first sweep
    second_sweep = _get_descendants(root_pid)
    new_pids = [p for p in second_sweep if p not in descendants]
    for cpid in new_pids:
        if _sigstop(cpid):
            stopped_descendants.append(cpid)
    descendants = sorted(set(descendants + new_pids))
    return root_stopped, descendants, stopped_descendants


# ---------------------------------------------------------------------------
# Step 2 — Evidence capture from /proc/PID/
# ---------------------------------------------------------------------------

def _capture_evidence(pid: int, output_dir: Optional[Path] = None) -> tuple[Optional[Path], list[str]]:
    if output_dir is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        evidence_dir = EVIDENCE_BASE / f"pid_{pid}_{ts}"
    else:
        evidence_dir = output_dir
    evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    captured: list[str] = []
    proc_dir = Path(f"/proc/{pid}")

    if not proc_dir.exists():
        logger.warning("/proc/%d not found; process may have exited", pid)
        return evidence_dir, captured

    # Files to copy from /proc
    proc_artifacts = ["cmdline", "environ", "maps", "status", "stat",
                      "io", "fd", "net/tcp", "net/tcp6", "net/udp"]

    for artifact in proc_artifacts:
        src = proc_dir / artifact
        dst = evidence_dir / artifact.replace("/", "_")
        try:
            if src.is_dir():
                # Capture file descriptor symlinks
                links: dict[str, str] = {}
                for fd_entry in src.iterdir():
                    try:
                        links[fd_entry.name] = str(fd_entry.resolve())
                    except OSError:
                        links[fd_entry.name] = "unresolvable"
                dst.write_text(str(links))
            else:
                content = src.read_bytes()
                dst.write_bytes(content)
            captured.append(str(dst))
        except (PermissionError, OSError) as exc:
            logger.debug("Could not capture %s: %s", src, exc)

    # Try to capture the executable
    try:
        exe_link = (proc_dir / "exe").resolve()
        exe_dst = evidence_dir / "exe_copy"
        shutil.copy2(str(exe_link), str(exe_dst))
        captured.append(str(exe_dst))
    except (OSError, shutil.Error):
        pass

    # psutil supplementary info
    try:
        proc = psutil.Process(pid)
        info = {
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": proc.cmdline(),
            "open_files": [f.path for f in proc.open_files()],
            "connections": [str(c) for c in proc.net_connections()],
            "memory_info": proc.memory_info()._asdict(),
            "cpu_times": proc.cpu_times()._asdict(),
            "create_time": proc.create_time(),
        }
        meta_file = evidence_dir / "psutil_info.txt"
        meta_file.write_text(str(info))
        captured.append(str(meta_file))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    logger.info("Evidence captured to %s (%d files)", evidence_dir, len(captured))
    return evidence_dir, captured


# ---------------------------------------------------------------------------
# Step 3 — iptables DROP (requires root)
# ---------------------------------------------------------------------------

def _iptables_drop(pid: int) -> Optional[str]:
    """Insert an OUTPUT iptables rule to drop traffic from the process owner."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(l for l in status.splitlines() if l.startswith("Uid:"))
        uid = int(uid_line.split()[1])  # real UID is the first field
    except (FileNotFoundError, StopIteration, ValueError, OSError):
        return None

    # Never block uid=0 (root) — would block the agent itself
    if uid == 0:
        logger.warning("Skipping iptables DROP for uid=0 — would block agent")
        return None
    # rule unused — cmd built directly below
    cmd = ["iptables", "-I", "OUTPUT", "1", "-m", "owner",
           "--uid-owner", str(uid), "-j", "DROP"]

    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        logger.warning("iptables DROP applied for uid %d (pid %d)", uid, pid)
        return " ".join(cmd)
    except FileNotFoundError:
        logger.warning("iptables not found — skipping network block")
        return None
    except subprocess.CalledProcessError as exc:
        logger.error("iptables failed: %s", exc.stderr.decode())
        return None
    except subprocess.TimeoutExpired:
        logger.error("iptables timed out")
        return None


# ---------------------------------------------------------------------------
# Step 4 — SIGKILL
# ---------------------------------------------------------------------------

def _sigkill(pid: int) -> bool:
    try:
        os.kill(pid, signal.SIGKILL)
        logger.warning("SIGKILL sent to PID %d", pid)
        # Wait briefly for reaping
        for _ in range(10):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
        return True
    except ProcessLookupError:
        return True   # already dead
    except PermissionError:
        logger.error("Permission denied sending SIGKILL to PID %d", pid)
        return False


def _kill_tree(root_pid: int, descendants: list[int]) -> tuple[bool, list[int]]:
    """SIGKILL descendants first (bottom-up), then root — so parents reap children."""
    killed_descendants: list[int] = []
    for cpid in descendants:
        if _sigkill(cpid):
            killed_descendants.append(cpid)
    root_killed = _sigkill(root_pid)
    return root_killed, killed_descendants


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def contain(pid: int, skip_iptables: bool = False) -> ContainmentResult:
    """
    Tree-aware containment pipeline (handles ransomware fork-workers):
      1. SIGSTOP root then all descendants (two-sweep race protection)
      2. Evidence — /proc artifacts for root + each descendant
      3. iptables --uid-owner DROP — covers whole tree (root required)
      4. SIGKILL descendants bottom-up, then root

    Returns ContainmentResult with full audit trail including tree info.
    """
    result = ContainmentResult(pid)
    logger.warning("=== CONTAINMENT INITIATED for PID %d (tree-aware) ===", pid)

    # 1. SIGSTOP the entire tree
    result.stopped, result.descendants, result.stopped_descendants = _freeze_tree(pid)
    if not result.stopped and not result.stopped_descendants:
        result.error = "SIGSTOP failed for entire tree"
    else:
        time.sleep(0.05)
        logger.warning(
            "Tree frozen: root_stopped=%s descendants_found=%d descendants_stopped=%d",
            result.stopped, len(result.descendants), len(result.stopped_descendants),
        )

    # 2. Evidence — root in main dir, descendants in subdirs
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    main_dir = EVIDENCE_BASE / f"pid_{pid}_{ts}"
    result.evidence_dir, result.evidence_files = _capture_evidence(pid, main_dir)
    if result.descendants:
        descendants_root = main_dir / "descendants"
        for cpid in result.descendants:
            child_dir = descendants_root / f"pid_{cpid}"
            _, child_files = _capture_evidence(cpid, child_dir)
            result.evidence_files.extend(child_files)

    # 3. iptables DROP — uid-based, naturally covers the whole tree
    if not skip_iptables and os.geteuid() == 0:
        result.iptables_rule = _iptables_drop(pid)
    elif os.geteuid() != 0:
        logger.warning("Not root — skipping iptables DROP")

    # 4. SIGKILL the entire tree (descendants first)
    result.killed, result.killed_descendants = _kill_tree(pid, result.descendants)

    logger.warning(
        "=== CONTAINMENT COMPLETE PID %d | tree_size=%d root_killed=%s descendants_killed=%d ===",
        pid, 1 + len(result.descendants),
        result.killed, len(result.killed_descendants),
    )
    return result


def dry_run_contain(pid: int) -> ContainmentResult:
    """Simulate containment without actually killing anything (for testing)."""
    result = ContainmentResult(pid)
    result.stopped = True
    result.evidence_dir, result.evidence_files = _capture_evidence(pid)
    result.iptables_rule = "DRY_RUN"
    result.killed = True
    logger.info("DRY RUN containment for PID %d", pid)
    return result
