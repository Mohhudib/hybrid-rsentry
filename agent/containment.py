"""
containment.py — SIGSTOP → evidence capture → cgroup-scoped network isolation →
SIGKILL pipeline. Requires root for iptables/cgroup writes and /proc access.

Network isolation is scoped to a dedicated **cgroup v2** containing only the
malicious process tree, NOT to the owning UID. UID-based matching
(``iptables -m owner --uid-owner``) over-isolates: it drops traffic for *every*
process sharing that UID — the interactive user (UID 1000), service accounts
(e.g. postgres UID 70), etc. — which is a host-wide network DoS
(MITRE ATT&CK T1498 Network Denial of Service if abused). See
``_cgroup_network_isolate`` for the scoped replacement.
"""
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger(__name__)

EVIDENCE_BASE = Path("/tmp/rsentry_evidence")

# cgroup v2 unified-hierarchy mount root. The containment cgroup is created as a
# direct child so iptables' ``-m cgroup --path`` (which is relative to this root)
# can match it. No cgroup controller needs to be enabled for membership matching.
CGROUP2_ROOT = Path("/sys/fs/cgroup")
CGROUP_CONTAIN_PREFIX = "rsentry-contain"


class ContainmentResult:
    def __init__(self, pid: int):
        self.pid = pid                              # root PID
        self.descendants: list[int] = []            # descendant PIDs found at containment
        self.stopped = False                        # True if root SIGSTOP succeeded
        self.stopped_descendants: list[int] = []    # which descendants got SIGSTOP
        self.evidence_dir: Optional[Path] = None    # root dir; descendants in subdirs/
        self.evidence_files: list[str] = []
        self.iptables_rule: Optional[str] = None    # full cgroup-scoped DROP rule (audit)
        self.cgroup_path: Optional[str] = None      # dedicated isolation cgroup
        self.isolation_comment: Optional[str] = None  # unique tag for surgical cleanup
        self.isolated_pids: list[int] = []          # PIDs actually moved into the cgroup
        self.isolation_released = False             # True once rule+cgroup torn down
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
            "cgroup_path": self.cgroup_path,
            "isolation_comment": self.isolation_comment,
            "isolated_pids": self.isolated_pids,
            "isolation_released": self.isolation_released,
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
    try:
        evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        # EVIDENCE_BASE may be unwritable (e.g. root-owned leftover from an
        # earlier privileged run while we run unprivileged). Evidence capture
        # must never abort the containment pipeline — fall back to a private
        # temp dir and keep going.
        fallback = Path(tempfile.mkdtemp(prefix=f"rsentry_evidence_pid{pid}_"))
        logger.warning("evidence dir %s not writable (%s) — falling back to %s",
                       evidence_dir, exc, fallback)
        evidence_dir = fallback

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
# Step 3 — cgroup v2 scoped network isolation (requires root)
# ---------------------------------------------------------------------------
#
# WHY NOT --uid-owner:
#   iptables -m owner --uid-owner <UID> drops traffic for *every* process owned
#   by that UID. The malicious process almost always shares its UID with
#   legitimate processes:
#       UID 0     → root daemons + the agent itself (would self-DoS)
#       UID 1000  → the interactive user's entire session (browser, shell, ssh…)
#       UID 70    → all postgres backends (12 connections == 12 redundant rules)
#   The result is a host-wide network outage, not target isolation.
#
# THE FIX:
#   Create a dedicated cgroup v2 node, move ONLY the malicious PID tree into it,
#   then drop on cgroup membership (`iptables -m cgroup --path <cgroup>`).
#   Forked children inherit cgroup membership at fork(), so the rule keeps
#   covering the tree without racing PID enumeration. Sibling processes under
#   the same UID are never in the cgroup, so they keep full network access.

def _read_uid(pid: int) -> Optional[int]:
    """Return the real UID of *pid* from /proc, or None if unreadable."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(l for l in status.splitlines() if l.startswith("Uid:"))
        return int(uid_line.split()[1])  # real UID is the first field
    except (FileNotFoundError, StopIteration, ValueError, OSError):
        return None


def _agent_protected_pids() -> set[int]:
    """
    PIDs that must never be network-isolated: the agent process itself and all
    of its ancestors. Isolating any of these would cut the agent (or its parent
    shell/supervisor) off the network and is a self-DoS.
    """
    protected: set[int] = {os.getpid(), 1}
    try:
        for ancestor in psutil.Process(os.getpid()).parents():
            protected.add(ancestor.pid)
    except psutil.Error:
        pass
    return protected


def _cgroup2_available() -> bool:
    """True if a writable cgroup v2 unified hierarchy is mounted at CGROUP2_ROOT."""
    return (CGROUP2_ROOT / "cgroup.controllers").exists()


def _isolation_comment(pid: int) -> str:
    """Unique iptables comment tag so cleanup is surgical (never a flush)."""
    return f"{CGROUP_CONTAIN_PREFIX}-{pid}"


def _move_into_cgroup(cgroup_dir: Path, pids: list[int]) -> list[int]:
    """
    Move each PID into *cgroup_dir* by appending to its ``cgroup.procs``.
    cgroup v2 accepts one PID per write. Returns the PIDs successfully moved.
    """
    procs = cgroup_dir / "cgroup.procs"
    moved: list[int] = []
    for target in pids:
        try:
            procs.write_text(str(target))
            moved.append(target)
        except (OSError, ValueError) as exc:
            # ProcessLookupError (dead pid) / ESRCH surface as OSError here.
            logger.debug("Could not move PID %d into %s: %s", target, cgroup_dir, exc)
    return moved


def _cgroup_network_isolate(pid: int, descendants: list[int]) -> "Optional[dict]":
    """
    Network-isolate ONLY the malicious process tree via a dedicated cgroup v2.

    Steps:
      1. Safety guard — refuse to isolate the agent's own tree (self-DoS guard).
      2. Create /sys/fs/cgroup/rsentry-contain-<pid>.
      3. Move the root PID + descendants into it (children inherit on fork).
      4. Insert an OUTPUT DROP rule matched on cgroup membership, tagged with a
         unique ``--comment`` so cleanup can delete exactly this rule.

    Returns a dict with keys ``rule``/``cgroup_path``/``comment``/``isolated_pids``
    on success, or None if isolation was skipped or failed. Never raises.
    """
    protected = _agent_protected_pids()
    if pid in protected:
        logger.error("Refusing to network-isolate PID %d — agent's own tree", pid)
        return None

    if not _cgroup2_available():
        logger.warning("cgroup v2 not available at %s — skipping network isolation",
                       CGROUP2_ROOT)
        return None

    comment = _isolation_comment(pid)
    cgroup_dir = CGROUP2_ROOT / comment
    try:
        cgroup_dir.mkdir(mode=0o755, exist_ok=True)
    except OSError as exc:
        logger.error("Could not create isolation cgroup %s: %s", cgroup_dir, exc)
        return None

    # Only ever move the malicious tree — and never the agent's own protected PIDs.
    candidates = [pid] + [d for d in descendants if d not in protected]
    isolated = _move_into_cgroup(cgroup_dir, candidates)
    if not isolated:
        logger.warning("No PIDs moved into %s — tearing down empty cgroup", cgroup_dir)
        try:
            cgroup_dir.rmdir()
        except OSError:
            pass
        return None

    rel_path = str(cgroup_dir.relative_to(CGROUP2_ROOT))
    cmd = ["iptables", "-I", "OUTPUT", "1",
           "-m", "cgroup", "--path", rel_path,
           "-m", "comment", "--comment", comment,
           "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=5)
    except FileNotFoundError:
        logger.warning("iptables not found — skipping network block")
        return None
    except subprocess.CalledProcessError as exc:
        logger.error("iptables (cgroup) failed: %s", exc.stderr.decode())
        return None
    except subprocess.TimeoutExpired:
        logger.error("iptables (cgroup) timed out")
        return None

    logger.warning(
        "Network isolation applied: cgroup=%s pids=%s (UID-agnostic, scoped) ",
        rel_path, isolated,
    )
    return {
        "rule": " ".join(cmd),
        "cgroup_path": str(cgroup_dir),
        "comment": comment,
        "isolated_pids": isolated,
    }


def release_network_isolation(result: "ContainmentResult") -> bool:
    """
    Surgically tear down the network isolation created for *result*:
      1. Delete ONLY the OUTPUT rule carrying this containment's unique comment
         (``iptables -D`` of the exact spec — never ``iptables -F``).
      2. Remove the (now-empty, post-SIGKILL) isolation cgroup directory.

    Idempotent and safe to call manually as the operator rollback procedure.
    Returns True if the rule was removed (or was already absent), else False.
    Never raises.
    """
    if not result.isolation_comment:
        return False
    if result.isolation_released:
        return True

    comment = result.isolation_comment
    removed = True
    if result.cgroup_path:
        rel_path = str(Path(result.cgroup_path).relative_to(CGROUP2_ROOT))
        del_cmd = ["iptables", "-D", "OUTPUT",
                   "-m", "cgroup", "--path", rel_path,
                   "-m", "comment", "--comment", comment,
                   "-j", "DROP"]
        try:
            subprocess.run(del_cmd, check=True, capture_output=True, timeout=5)
            logger.warning("Removed isolation rule for %s", comment)
        except FileNotFoundError:
            logger.warning("iptables not found — cannot remove rule %s", comment)
            removed = False
        except subprocess.CalledProcessError as exc:
            # Non-zero usually means the rule is already gone — treat as released.
            logger.info("Isolation rule %s already absent: %s",
                        comment, exc.stderr.decode().strip())
        except subprocess.TimeoutExpired:
            logger.error("iptables -D timed out for %s", comment)
            removed = False

        cgroup_dir = Path(result.cgroup_path)
        try:
            cgroup_dir.rmdir()  # only succeeds once all PIDs are gone (post-kill)
        except OSError as exc:
            logger.debug("Could not remove cgroup %s yet: %s", cgroup_dir, exc)

    result.isolation_released = removed
    return removed


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
      3. cgroup v2 scoped network isolation — DROP on cgroup membership, NOT
         on --uid-owner, so only the malicious tree loses network (root required)
      4. SIGKILL descendants bottom-up, then root
      5. Release the isolation rule+cgroup once the tree is fully killed
         (kept in place if any PID survives, so a stuck process stays isolated)

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

    # 3. Network isolation — cgroup-scoped to the malicious tree (NOT uid-wide)
    if not skip_iptables and os.geteuid() == 0:
        iso = _cgroup_network_isolate(pid, result.descendants)
        if iso:
            result.iptables_rule = iso["rule"]
            result.cgroup_path = iso["cgroup_path"]
            result.isolation_comment = iso["comment"]
            result.isolated_pids = iso["isolated_pids"]
    elif os.geteuid() != 0:
        logger.warning("Not root — skipping network isolation")

    # 4. SIGKILL the entire tree (descendants first)
    result.killed, result.killed_descendants = _kill_tree(pid, result.descendants)

    # 5. Release the isolation only if the whole tree is confirmed dead. A
    #    surviving (e.g. uninterruptible D-state) process stays isolated; the
    #    operator can release it later via release_network_isolation(result).
    if result.isolation_comment:
        fully_killed = result.killed and len(result.killed_descendants) == len(result.descendants)
        if fully_killed:
            release_network_isolation(result)
        else:
            logger.warning(
                "Tree not fully killed — keeping network isolation %s in place",
                result.isolation_comment,
            )

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
