#!/usr/bin/env python3
"""
sim_all.py — run ALL ransomware simulations in one command.

Each family runs in a separate subprocess so the live eBPF detection engine
treats each one as an independent process (new PID). That means every family
can cross the rename-velocity threshold and generate its own set of dashboard
alerts before being contained by the LSM hook.

Note on "errors":
  After the velocity threshold (default: 2 renames), the eBPF LSM hook adds
  the offending PID to blocked_pids and returns -EPERM for every subsequent
  rename. These show up as "errors" in the sim output — they are NOT failures.
  They are proof that the detection system fired and contained the process.

Usage:
    python3 -m simulations.sim_all
    python3 -m simulations.sim_all --target /tmp/rsentry_all --max-files 20 --delay 0.3
    python3 -m simulations.sim_all --target /tmp/rsentry_lab --traversal random

Options:
    --target      Directory to simulate on (default: /tmp/rsentry_all)
    --traversal   dfs | random | depth  (default: dfs)
    --max-files   Cap files touched per family (keep <=50 on a VM)
    --delay       Per-file delay in seconds (lets the live sensor catch up)
    --skip-aaa    Skip AAA_/zzz_ canary files
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from simulations.sim_common import populate_corpus

_FAMILY_MODULES = [
    ("LockBit 5.0", "simulations.sim_lockbit"),
    ("Akira",       "simulations.sim_akira"),
    ("Qilin",       "simulations.sim_qilin"),
]

_SEP  = "=" * 64
_SEP2 = "-" * 64


def _banner(title: str) -> None:
    print(f"\n{_SEP}")
    print(f"  {title}")
    print(_SEP)


def _check_not_in_git(root: str) -> bool:
    check = Path(root).resolve()
    for _ in range(10):
        if (check / ".git").is_dir():
            print("[sim_all] ERROR: target is inside a git repo — aborting")
            return False
        parent = check.parent
        if parent == check:
            break
        check = parent
    return True


def run_all(args: argparse.Namespace) -> int:
    root = args.target

    if not os.path.isdir(root):
        print(f"[sim_all] creating target dir: {root}")
        os.makedirs(root, exist_ok=True)
        populate_corpus(root)
        print(f"[sim_all] corpus ready at {root}")

    if not _check_not_in_git(root):
        return 1

    results = []
    total_start = time.perf_counter()
    # Resolve python executable from the active venv so the subprocess imports work.
    python = sys.executable

    for i, (label, module) in enumerate(_FAMILY_MODULES):
        _banner(f"[{i+1}/{len(_FAMILY_MODULES)}] {label}")
        print(f"  target    : {root}")
        print(f"  traversal : {args.traversal}")
        print(f"  max_files : {args.max_files or 'unlimited'}")
        print(f"  delay     : {args.delay if args.delay is not None else 'profile default'}s/file")
        print(f"  subprocess: isolated PID — eBPF sees this as a fresh process")
        print(_SEP2)

        cmd = [python, "-m", module,
               "--target", root,
               "--traversal", args.traversal]
        if args.max_files:
            cmd += ["--max-files", str(args.max_files)]
        if args.delay is not None:
            cmd += ["--delay", str(args.delay)]
        if args.skip_aaa:
            cmd += ["--skip-aaa"]

        t0 = time.perf_counter()
        # Output streams directly to terminal so the user sees rename activity live.
        proc = subprocess.run(
            cmd,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        elapsed = round(time.perf_counter() - t0, 2)

        ok = proc.returncode == 0
        results.append({"family": label, "ok": ok, "elapsed": elapsed})

        # Brief pause between families so the sensor can flush pending events.
        if i < len(_FAMILY_MODULES) - 1:
            time.sleep(1.0)

    total_elapsed = round(time.perf_counter() - total_start, 2)

    _banner("SIMULATION COMPLETE — Summary")
    print(f"  {'Family':<14} {'Elapsed':>10}  Status")
    print(f"  {_SEP2}")
    for r in results:
        status = "OK" if r["ok"] else "FAILED"
        print(f"  {r['family']:<14} {r['elapsed']:>9}s  {status}")
    print(f"  {_SEP2}")
    print(f"  Total wall time : {total_elapsed}s")
    print(f"  Families run    : {len(results)}/{len(_FAMILY_MODULES)}")
    print(f"  All passed      : {'YES' if all(r['ok'] for r in results) else 'NO'}")
    print(f"\n  NOTE: 'errors' in per-family output = renames blocked by eBPF LSM")
    print(f"        (EPERM after velocity threshold = detection SUCCESS, not a bug)")
    print(_SEP + "\n")

    return 0 if all(r["ok"] for r in results) else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run all ransomware simulations (LockBit 5.0, Akira, Qilin) in one command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--target",    default="/tmp/rsentry_all",
                    help="directory to simulate on (default: /tmp/rsentry_all)")
    ap.add_argument("--traversal", choices=["dfs", "random", "depth"],
                    default="dfs")
    ap.add_argument("--max-files", type=int, default=None,
                    help="cap files touched per family (keep <=50 on a VM)")
    ap.add_argument("--delay",     type=float, default=None,
                    help="per-file delay in seconds (default: profile default)")
    ap.add_argument("--skip-aaa",  action="store_true",
                    help="skip AAA_/zzz_ canary files")
    return run_all(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
