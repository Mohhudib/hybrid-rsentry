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
        self.pid = pid
        self.stopped = False
        self.evidence_dir: Optional[Path] = None
        self.evidence_files: list[str] = []
        self.iptables_rule: Optional[str] = None
        self.killed = False
        self.error: Optional[str] = None
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "stopped": self.stopped,
            "evidence_dir": str(self.evidence_dir) if self.evidence_dir else None,
            "evidence_files": self.evidence_files,
            "iptables_rule": self.iptables_rule,
            "killed": self.killed,
            "error": self.error,
            "timestamp": self.timestamp,
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


# ---------------------------------------------------------------------------
# Step 2 — Evidence capture from /proc/PID/
# ---------------------------------------------------------------------------

def _capture_evidence(pid: int) -> tuple[Optional[Path], list[str]]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = EVIDENCE_BASE / f"pid_{pid}_{ts}"
    evidence_dir.mkdir(parents=True, exist_ok=True)

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
        proc = psutil.Process(pid)
        uid = proc.uids().real
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    rule = f"-m owner --uid-owner {uid} -j DROP"
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def contain(pid: int, skip_iptables: bool = False) -> ContainmentResult:
    """
    Execute the full containment pipeline:
    1. SIGSTOP  → freeze the process
    2. Evidence → copy /proc artifacts
    3. iptables → network DROP (root required)
    4. SIGKILL  → terminate

    Returns ContainmentResult with full audit trail.
    """
    result = ContainmentResult(pid)
    logger.warning("=== CONTAINMENT INITIATED for PID %d ===", pid)

    # 1. SIGSTOP
    result.stopped = _sigstop(pid)
    if not result.stopped:
        result.error = "SIGSTOP failed"
        # Still try evidence capture
    else:
        time.sleep(0.05)  # give OS time to freeze the process

    # 2. Evidence capture
    result.evidence_dir, result.evidence_files = _capture_evidence(pid)

    # 3. iptables DROP
    if not skip_iptables and os.geteuid() == 0:
        result.iptables_rule = _iptables_drop(pid)
    else:
        if os.geteuid() != 0:
            logger.warning("Not root — skipping iptables DROP")

    # 4. SIGKILL
    result.killed = _sigkill(pid)

    logger.warning(
        "=== CONTAINMENT COMPLETE PID %d | stopped=%s killed=%s evidence=%s ===",
        pid, result.stopped, result.killed, result.evidence_dir,
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
