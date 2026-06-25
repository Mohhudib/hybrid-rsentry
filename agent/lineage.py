"""
lineage.py — psutil process ancestry scorer.
Returns a suspicion score 0–100 based on parent names, spawn path, and SHA-256 hash.
"""
import glob
import hashlib
import logging
import os
import time
from typing import Optional
from functools import lru_cache

import psutil

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------
# NOTE: common shells/interpreters removed — they spawn everything on Linux/Kali
# and produce massive false positives. Only flag genuinely unusual parents.
SUSPICIOUS_PARENT_NAMES = {
    "nc", "ncat", "netcat",
    "mshta", "wscript", "cscript",
    "xterm", "rxvt",
}

# NOTE: /.cache/ removed — matches browser caches legitimately
SUSPICIOUS_SPAWN_PATHS = [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/proc/",
]

BENIGN_PARENTS = {
    "systemd", "init", "sshd", "cron", "dbus-daemon",
    "NetworkManager", "gdm", "lightdm", "Xorg",
    "gnome-shell", "kwin", "xfwm4",
    "bash", "sh", "zsh", "fish",         # shells are normal parents on Linux
    "code", "code-server",               # VS Code terminal
    "nautilus", "dolphin", "thunar",     # file managers
    "firefox", "firefox-esr", "chromium",
}

WEIGHT_SUSPICIOUS_PARENT = 30
WEIGHT_SUSPICIOUS_PATH = 25
WEIGHT_DEEP_ANCESTRY = 15
WEIGHT_EXE_UNREADABLE = 20
WEIGHT_NO_TTY = 2  # lowered this since most background processes have no TTY
WEIGHT_RAPID_SPAWN = 5

# Known-good verification (dpkg integrity database)
WEIGHT_HASH_DPKG_MISMATCH = 35    # exe in dpkg list BUT hash differs → TAMPERED
WEIGHT_UNKNOWN_BINARY = 10        # exe NOT in dpkg list (could be /opt, ransomware)
WEIGHT_KNOWN_GOOD_BONUS = 8       # trust reduction for verified dpkg binaries

# Hash verdict constants
HASH_VERDICT_MATCH = "match"
HASH_VERDICT_MISMATCH = "mismatch"
HASH_VERDICT_UNKNOWN = "unknown"


class ProcessLineage:
    """Holds ancestry info for a single PID."""

    def __init__(self, pid: int):
        self.pid = pid
        self.name: str = ""
        self.exe: str = ""
        self.cmdline: list[str] = []
        self.ancestors: list[str] = []
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


_sha256_cache: dict[str, tuple[float, Optional[str]]] = {}  # path → (mtime, digest)

def _sha256_of_exe(exe_path: str) -> Optional[str]:
    try:
        mtime = os.stat(exe_path).st_mtime
    except OSError:
        return None
    cached = _sha256_cache.get(exe_path)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        h = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
    except (OSError, PermissionError):
        digest = None
    _sha256_cache[exe_path] = (mtime, digest)
    return digest


@lru_cache(maxsize=512)
def _md5_of_file(path: str) -> Optional[str]:
    """Full-file MD5 — used for dpkg comparison."""
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


# ---------------------------------------------------------------------------
# Known-good integrity database (dpkg /var/lib/dpkg/info/*.md5sums)
# ---------------------------------------------------------------------------

_DPKG_HASHES: dict[str, str] = {}
_DPKG_LOADED: bool = False


def _load_dpkg_hashes() -> dict[str, str]:
    """
    Parse all /var/lib/dpkg/info/*.md5sums into {absolute_path: md5}.
    Each line format:  '<md5>  <relative_path>'
    """
    hashes: dict[str, str] = {}
    for md5file in glob.glob("/var/lib/dpkg/info/*.md5sums"):
        try:
            with open(md5file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    md5, rel_path = parts
                    hashes["/" + rel_path] = md5
        except (OSError, PermissionError, UnicodeDecodeError):
            continue
    return hashes


def _ensure_dpkg_loaded() -> None:
    """Lazy load — runs once on first verification call."""
    global _DPKG_LOADED
    if _DPKG_LOADED:
        return
    _DPKG_LOADED = True
    try:
        _DPKG_HASHES.update(_load_dpkg_hashes())
        logger.info("Lineage: loaded %d known-good hashes from dpkg",
                    len(_DPKG_HASHES))
    except Exception as exc:
        logger.warning("Lineage: dpkg hash load failed: %s", exc)


def verify_against_dpkg(exe_path: str) -> str:
    """
    Compare exe against OS package manager integrity database.

    Returns one of:
        HASH_VERDICT_MATCH    — exe registered in dpkg AND md5 matches
        HASH_VERDICT_MISMATCH — exe registered BUT md5 differs (TAMPERED!)
        HASH_VERDICT_UNKNOWN  — exe not tracked by dpkg (3rd-party / /opt / ransomware)
    """
    _ensure_dpkg_loaded()
    if not _DPKG_HASHES:
        return HASH_VERDICT_UNKNOWN
    expected = _DPKG_HASHES.get(exe_path)
    if expected is None:
        return HASH_VERDICT_UNKNOWN
    actual = _md5_of_file(exe_path)
    if actual is None:
        return HASH_VERDICT_UNKNOWN
    return HASH_VERDICT_MATCH if actual == expected else HASH_VERDICT_MISMATCH


def _collect_ancestors(proc: psutil.Process, max_depth: int = 10) -> tuple[list[str], list[str]]:
    names: list[str] = []
    paths: list[str] = []
    try:
        p = proc.parent()
        depth = 0
        while p and depth < max_depth:
            try:
                name = p.name()
                path = p.exe() or ""
                names.append(name)
                paths.append(path)
                # early exit if we've reached a benign root process
                if name.lower() in {"systemd", "init"}:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            p = p.parent()
            depth += 1
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return names, paths


def score_process(pid: int) -> Optional[ProcessLineage]:
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

    lineage.ancestors, lineage.ancestor_paths = _collect_ancestors(proc)

    score = 0.0

    # 1. Suspicious parent name
    immediate_parent = lineage.ancestors[0] if lineage.ancestors else ""
    if immediate_parent.lower() in SUSPICIOUS_PARENT_NAMES:
        score += WEIGHT_SUSPICIOUS_PARENT
        lineage.reasons.append(f"suspicious_parent:{immediate_parent}")

    # Benign parent reduces score — but only if not from a suspicious path
    if immediate_parent.lower() in BENIGN_PARENTS:
        # If python3 or an interpreter ran something from /tmp/, don't reduce the score
        parent_path = lineage.ancestor_paths[0] if lineage.ancestor_paths else ""
        is_from_suspicious_path = any(parent_path.startswith(sp) for sp in SUSPICIOUS_SPAWN_PATHS)
        if not is_from_suspicious_path:
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

    # 4. Hash check + dpkg known-good verification
    if lineage.exe:
        lineage.sha256 = _sha256_of_exe(lineage.exe)
        if lineage.sha256 is None:
            score += WEIGHT_EXE_UNREADABLE * 0.5
            lineage.reasons.append("exe_unreadable")
        else:
            verdict = verify_against_dpkg(lineage.exe)
            lineage.reasons.append(f"dpkg_verdict:{verdict}")
            if verdict == HASH_VERDICT_MISMATCH:
                # Tampered system binary — strongest hash-based signal
                score += WEIGHT_HASH_DPKG_MISMATCH
                lineage.reasons.append("dpkg_hash_mismatch")
            elif verdict == HASH_VERDICT_UNKNOWN:
                # Not in dpkg DB — could be legitimate (/opt, /home) or ransomware
                score += WEIGHT_UNKNOWN_BINARY
            elif verdict == HASH_VERDICT_MATCH:
                # Verified system binary — trust bonus
                score = max(0.0, score - WEIGHT_KNOWN_GOOD_BONUS)

    # 5. No controlling TTY
    try:
        if proc.terminal() is None:
            score += WEIGHT_NO_TTY
            lineage.reasons.append("no_tty")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    # 6. Very recently spawned process
    try:
        age = time.time() - proc.create_time()
        if age < 2.0:
            score += WEIGHT_RAPID_SPAWN
            lineage.reasons.append(f"rapid_spawn:{age:.2f}s")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    lineage.score = min(score, 100.0)
    return lineage


def score_for_event(pid: int) -> dict:
    lineage = score_process(pid)
    if lineage is None:
        # The process died before we could analyze it — this is suspicious on its own
        logger.warning("PID %d not found — process may have exited after event (suspicious)", pid)
        return {
            "lineage_score": 25.0,  # process exited before analysis — suspicious but not definitive
            "process_name": "exited_process",
            "exe": "",
            "ancestors": [],
            "sha256": None,
            "reasons": ["process_exited_rapidly"],
        }
    return {
        "lineage_score": lineage.score,
        "process_name": lineage.name,
        "exe": lineage.exe,
        "ancestors": lineage.ancestors,
        "sha256": lineage.sha256,
        "reasons": lineage.reasons,
    }
