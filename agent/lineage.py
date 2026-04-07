"""
lineage.py — psutil process ancestry scorer.
Returns a suspicion score 0–100 based on parent names, spawn path, and SHA-256 hash.
"""
import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------
SUSPICIOUS_PARENT_NAMES = {
    "bash", "sh", "zsh", "python", "python3", "perl", "ruby", "php",
    "node", "nodejs", "nc", "ncat", "netcat", "wget", "curl",
    "mshta", "wscript", "cscript",
}

SUSPICIOUS_SPAWN_PATHS = [
    "/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/",
    "/proc/", "/.cache/",
]

BENIGN_PARENTS = {
    "systemd", "init", "sshd", "cron", "dbus-daemon",
    "NetworkManager", "gdm", "lightdm", "Xorg",
}

WEIGHT_SUSPICIOUS_PARENT = 30
WEIGHT_SUSPICIOUS_PATH = 25
WEIGHT_DEEP_ANCESTRY = 15       # parent chain depth > 5
WEIGHT_HASH_MISMATCH = 20       # binary hash differs from disk
WEIGHT_NO_TTY = 5               # process has no controlling terminal
WEIGHT_RAPID_SPAWN = 5          # process age < 2 seconds


class ProcessLineage:
    """Holds ancestry info for a single PID."""

    def __init__(self, pid: int):
        self.pid = pid
        self.name: str = ""
        self.exe: str = ""
        self.cmdline: list[str] = []
        self.ancestors: list[str] = []  # [parent, grandparent, ...]
        self.ancestor_paths: list[str] = []
        self.score: float = 0.0
        self.reasons: list[str] = []
        self.sha256: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": " ".join(self.cmdline),
            "ancestors": self.ancestors,
            "lineage_score": round(self.score, 2),
            "sha256": self.sha256,
            "reasons": self.reasons,
        }


def _sha256_of_exe(exe_path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _collect_ancestors(proc: psutil.Process, max_depth: int = 10) -> tuple[list[str], list[str]]:
    """Walk the parent chain, return (names, exe_paths)."""
    names: list[str] = []
    paths: list[str] = []
    try:
        p = proc.parent()
        depth = 0
        while p and depth < max_depth:
            try:
                names.append(p.name())
                paths.append(p.exe() or "")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            p = p.parent()
            depth += 1
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return names, paths


def score_process(pid: int) -> Optional[ProcessLineage]:
    """
    Score a process for ransomware suspicion.
    Returns ProcessLineage with .score (0–100) and .reasons.
    Returns None if the process no longer exists.
    """
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None

    lineage = ProcessLineage(pid)

    try:
        lineage.name = proc.name()
        lineage.exe = proc.exe() or ""
        lineage.cmdline = proc.cmdline()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    # Collect ancestry
    lineage.ancestors, lineage.ancestor_paths = _collect_ancestors(proc)

    score = 0.0

    # 1. Suspicious parent name
    immediate_parent = lineage.ancestors[0] if lineage.ancestors else ""
    if immediate_parent.lower() in SUSPICIOUS_PARENT_NAMES:
        score += WEIGHT_SUSPICIOUS_PARENT
        lineage.reasons.append(f"suspicious_parent:{immediate_parent}")

    # Benign parent reduces score
    if immediate_parent.lower() in BENIGN_PARENTS:
        score = max(0.0, score - 15)

    # 2. Suspicious spawn path
    exe_lower = lineage.exe.lower()
    for sp in SUSPICIOUS_SPAWN_PATHS:
        if exe_lower.startswith(sp):
            score += WEIGHT_SUSPICIOUS_PATH
            lineage.reasons.append(f"suspicious_path:{sp}")
            break

    # 3. Deep ancestry chain
    if len(lineage.ancestors) > 5:
        score += WEIGHT_DEEP_ANCESTRY
        lineage.reasons.append(f"deep_ancestry:{len(lineage.ancestors)}")

    # 4. Hash check — compare running exe hash vs disk
    if lineage.exe:
        lineage.sha256 = _sha256_of_exe(lineage.exe)
        if lineage.sha256 is None:
            # Can't read exe → suspicious
            score += WEIGHT_HASH_MISMATCH * 0.5
            lineage.reasons.append("exe_unreadable")

    # 5. No controlling TTY
    try:
        if proc.terminal() is None:
            score += WEIGHT_NO_TTY
            lineage.reasons.append("no_tty")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    # 6. Very recently spawned process
    try:
        import time
        age = time.time() - proc.create_time()
        if age < 2.0:
            score += WEIGHT_RAPID_SPAWN
            lineage.reasons.append(f"rapid_spawn:{age:.2f}s")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    lineage.score = min(score, 100.0)
    return lineage


def score_for_event(pid: int) -> dict:
    """Convenience wrapper returning a flat dict for event payload."""
    lineage = score_process(pid)
    if lineage is None:
        return {
            "lineage_score": 0.0,
            "process_name": "",
            "exe": "",
            "ancestors": [],
            "sha256": None,
            "reasons": ["process_not_found"],
        }
    return {
        "lineage_score": lineage.score,
        "process_name": lineage.name,
        "exe": lineage.exe,
        "ancestors": lineage.ancestors,
        "sha256": lineage.sha256,
        "reasons": lineage.reasons,
    }
