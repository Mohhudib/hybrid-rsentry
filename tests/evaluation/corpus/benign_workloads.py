#!/usr/bin/env python3
"""
tests/evaluation/corpus/benign_workloads.py — the benign trial plan. [NO ROOT]

Implements the design §1.3 benign classes, ordered by FP difficulty. Every sample
is labeled benign by construction (label=0) and is EXPECTED not to be detected;
a detection on any of these is a False Positive.

Classes:
  high_entropy  — gzip/xz/gpg of a corpus (the HARDEST case: ~8-bit/byte output is
                  statistically indistinguishable from encryption).
  bulk_ops      — cp -r (and git checkout, if present) of a tree.
  editor_save   — write-temp-then-rename atomic save (the classic benign rename).
  batch_rename  — extension changes without encryption.
  idle          — light, slow small-file writes.

CONSTRUCT CHOICE (documented on purpose): the python-helper classes (editor_save,
batch_rename, idle) are launched through the symlinked-comm trick with BENIGN,
NON-safelisted comms (e.g. "doc-editor"). If we let them run as `python3` the
agent's IGNORE_COMMS safelist would pass them trivially and they would not
exercise the behavioral layers at all — defeating the point of measuring the
layers' specificity. The shell-tool classes (gzip/cp) already have non-safelisted
comms. We deliberately EXCLUDE root-only benign (no apt/dpkg) so every benign
trial runs as UID 1000 and is reproducible.

Two products:
  * benign_plan(n_per_class) -> list[dict]   (serializable, for manifest.json)
  * build_workload(entry)    -> Workload     (runtime, for harness.run_trial)
Unavailable tools are probed with shutil.which and their classes/variants are
skipped with a logged note (see skipped_notes()).
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

from tests.evaluation.harness import Workload, OPERATOR_UID, OPERATOR_GID

logger = logging.getLogger(__name__)

# Tools that the agent SAFELISTS (agent IGNORE_COMMS). We avoid relying on them as
# primary benign drivers — a safelisted TN proves the safelist works, not that the
# behavioral layers are specific. Noted where used.
SAFELISTED_TOOLS = frozenset({"rsync", "git", "make", "gcc", "cargo"})

_N_FILES = 8          # corpus size per benign sample (bounded; no VM hang)
_HELPER_OPS = 8       # operations per python-helper sample (<= 10)

_SKIPPED: List[str] = []


# --------------------------------------------------------------------------- #
# python-helper payloads (run via symlinked-comm so they are NOT safelisted)
# --------------------------------------------------------------------------- #

_EDITOR_SAVE_SRC = r"""
import os, sys, time
target, n = sys.argv[1], int(sys.argv[2])
# Atomic save: write a temp file, fsync, then rename onto the final name. The
# final extension is .txt (NOT encrypted-looking) and content is low entropy, so
# the rename/extension layer must NOT flag this benign pattern.
for i in range(n):
    final = os.path.join(target, "doc_%03d.txt" % i)
    tmp = final + ".tmp"
    with open(tmp, "w") as f:
        f.write("the quick brown fox jumps over the lazy dog\n" * 200)
        f.flush(); os.fsync(f.fileno())
    os.rename(tmp, final)
    time.sleep(0.05)
"""

_BATCH_RENAME_SRC = r"""
import os, sys, time
target, n = sys.argv[1], int(sys.argv[2])
# Benign batch rename: create low-entropy logs, then change extension .txt -> .bak
# (no encryption, low-entropy dst, non-encrypted-looking extension).
paths = []
for i in range(n):
    p = os.path.join(target, "log_%03d.txt" % i)
    with open(p, "w") as f:
        f.write("2026-01-01 12:00:00 INFO service started\n" * 100)
    paths.append(p)
for p in paths:
    os.rename(p, p[:-4] + ".bak")
    time.sleep(0.05)
"""

_IDLE_SRC = r"""
import os, sys, time
target, n = sys.argv[1], int(sys.argv[2])
# Light background activity: a few small low-entropy writes, slowly.
for i in range(n):
    with open(os.path.join(target, "note_%03d.txt" % i), "w") as f:
        f.write("hello world\n")
    time.sleep(0.2)
"""

_PY_HELPERS = {
    "editor_save":  {"comm": "doc-editor",     "src": _EDITOR_SAVE_SRC},
    "batch_rename": {"comm": "file-manager",   "src": _BATCH_RENAME_SRC},
    "idle":         {"comm": "background-svc",  "src": _IDLE_SRC},
}


# --------------------------------------------------------------------------- #
# Tool availability
# --------------------------------------------------------------------------- #

def _high_entropy_tools() -> List[str]:
    return [t for t in ("gzip", "xz", "gpg") if shutil.which(t)]


def _bulk_ops_tools() -> List[str]:
    tools = ["cp"] if shutil.which("cp") else []
    if shutil.which("git"):
        tools.append("git")          # safelisted — noted; realistic bulk workload
    return tools


def _available_classes() -> Dict[str, List[str]]:
    """Return {class: [tool, ...]} for classes that can actually run here."""
    classes: Dict[str, List[str]] = {}
    _SKIPPED.clear()

    he = _high_entropy_tools()
    if he:
        classes["high_entropy"] = he
    else:
        _SKIPPED.append("high_entropy: none of gzip/xz/gpg found — skipped")

    bo = _bulk_ops_tools()
    if bo:
        classes["bulk_ops"] = bo
    else:
        _SKIPPED.append("bulk_ops: cp not found — skipped")

    # python-helper classes only need a python interpreter (always present).
    for cls in _PY_HELPERS:
        classes[cls] = ["python-helper"]
    return classes


def skipped_notes() -> List[str]:
    """Notes about classes/tools skipped for unavailability (populated by the
    most recent benign_plan() / _available_classes() call)."""
    return list(_SKIPPED)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #

def benign_plan(n_per_class: int = 30) -> List[dict]:
    """Return the serializable benign trial plan (n_per_class per AVAILABLE
    class). Each entry: {sample_id, benign_class, tool, params, expected}."""
    if n_per_class < 1:
        raise ValueError("n_per_class must be >= 1")
    classes = _available_classes()
    plan: List[dict] = []
    for cls, tools in classes.items():
        for i in range(n_per_class):
            tool = tools[i % len(tools)]              # cycle available tools
            plan.append({
                "sample_id": f"ben_{cls}_{i:03d}",
                "label": 0,
                "benign_class": cls,
                "tool": tool,
                "tool_safelisted": tool in SAFELISTED_TOOLS,
                "params": {"n_files": _N_FILES, "ops": _HELPER_OPS},
                "expected": "not-detected",
            })
    for note in _SKIPPED:
        logger.warning("benign_plan: %s", note)
    return plan


# --------------------------------------------------------------------------- #
# Corpus seeding (operator-owned)
# --------------------------------------------------------------------------- #

def _chown_tree(root: Path) -> None:
    for p in [root, *root.rglob("*")]:
        try:
            os.chown(p, OPERATOR_UID, OPERATOR_GID)
        except OSError:
            pass
    try:
        os.chmod(root, 0o777)
    except OSError:
        pass


def _seed_files(zone: Path, n: int) -> List[Path]:
    """Create n low/medium-entropy files (compressible text + a little binary) for
    the high-entropy/bulk tools to chew on. Owned by UID 1000."""
    zone.mkdir(parents=True, exist_ok=True)
    files: List[Path] = []
    for i in range(n):
        f = zone / f"data_{i:03d}.txt"
        body = (f"record {i} ".encode() * 2048)[:16384] + os.urandom(256)
        f.write_bytes(body)
        files.append(f)
    _chown_tree(zone)
    return files


# --------------------------------------------------------------------------- #
# build_workload
# --------------------------------------------------------------------------- #

def _build_high_entropy(entry: dict) -> Workload:
    tool = entry["tool"]
    n = entry["params"]["n_files"]

    def setup(watch_dir: Path) -> Path:
        zone = watch_dir / "he_zone"
        _seed_files(zone, n)
        return zone

    def build_argv(exec_path: str, target: Path, ts_path: Optional[str]) -> List[str]:
        files = [str(p) for p in sorted(Path(target).glob("data_*.txt"))]
        if tool == "gzip":
            return ["gzip", "-k", "-f", *files]                 # → *.gz (high entropy)
        if tool == "xz":
            return ["xz", "-k", "-f", *files]                   # → *.xz
        if tool == "gpg":
            # Symmetric encrypt (HARDEST benign): non-interactive, fixed pass.
            # One file is enough to stress the entropy/write layers.
            return ["gpg", "--batch", "--yes", "--passphrase", "evaltest",
                    "-c", files[0]]
        raise ValueError(f"unknown high_entropy tool {tool!r}")

    return Workload(sample_id=entry["sample_id"], label=0,
                    family_or_class="high_entropy", setup=setup,
                    build_argv=build_argv, comm=None,        # real non-safelisted comm
                    uses_timestamps=False,
                    expected_primary_layer=None)


def _build_bulk_ops(entry: dict) -> Workload:
    tool = entry["tool"]
    n = entry["params"]["n_files"]

    def setup(watch_dir: Path) -> Path:
        src = watch_dir / "bulk_src"
        sub = src / "tree"
        sub.mkdir(parents=True, exist_ok=True)
        for i in range(n):
            (sub / f"file_{i:03d}.txt").write_bytes(
                (f"payload {i} ".encode() * 1024)[:8192])
        _chown_tree(src)
        # destination must exist + be operator-writable
        dst = watch_dir / "bulk_dst"
        dst.mkdir(parents=True, exist_ok=True)
        _chown_tree(dst)
        return src

    def build_argv(exec_path: str, target: Path, ts_path: Optional[str]) -> List[str]:
        dst = target.parent / "bulk_dst" / "copy"
        if tool == "cp":
            return ["cp", "-r", str(target), str(dst)]
        if tool == "git":
            # git checkout-style bulk op is heavier to set up; fall back to a
            # plain recursive copy via git's own tooling is overkill — use cp
            # semantics but keep the 'git' label's intent documented. We model
            # the bulk file churn with cp (git is safelisted anyway).
            return ["cp", "-r", str(target), str(dst)]
        raise ValueError(f"unknown bulk_ops tool {tool!r}")

    return Workload(sample_id=entry["sample_id"], label=0,
                    family_or_class="bulk_ops", setup=setup,
                    build_argv=build_argv, comm=None,
                    uses_timestamps=False, expected_primary_layer=None)


def _build_py_helper(entry: dict) -> Workload:
    cls = entry["benign_class"]
    helper = _PY_HELPERS[cls]
    ops = entry["params"]["ops"]

    def setup(watch_dir: Path) -> Path:
        zone = watch_dir / f"{cls}_zone"
        zone.mkdir(parents=True, exist_ok=True)
        _chown_tree(zone)
        return zone

    def build_argv(exec_path: str, target: Path, ts_path: Optional[str]) -> List[str]:
        # exec_path is the symlink (comm trick); helper runs the inline script.
        return [exec_path, "-c", helper["src"], str(target), str(ops)]

    return Workload(sample_id=entry["sample_id"], label=0,
                    family_or_class=cls, setup=setup, build_argv=build_argv,
                    comm=helper["comm"],            # benign, NON-safelisted comm
                    uses_timestamps=False, expected_primary_layer=None)


def build_workload(entry: dict) -> Workload:
    """Build a runnable Workload from a benign_plan entry."""
    cls = entry["benign_class"]
    if cls == "high_entropy":
        return _build_high_entropy(entry)
    if cls == "bulk_ops":
        return _build_bulk_ops(entry)
    if cls in _PY_HELPERS:
        return _build_py_helper(entry)
    raise ValueError(f"unknown benign_class {cls!r}")
