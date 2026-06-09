#!/usr/bin/env python3
"""
sim_lockbit.py — replicates LockBit 5.0 documented behavioural profile (SAFE).

LockBit 5.0 TTPs reproduced:
  * Randomised 16-character extension (the 5.0 signature).
  * Two-pass write (quick partial pass, then a thorough pass).
  * Targets VM datastore files (.vmdk/.vmx/.vmsn).
  * Drops ReadMeForDecrypt.txt; simulates post-encryption self-delete (logged).

Session 09 addition — backup-destruction + bounded concurrency (Defenses #4/#5):
  * Backup-destruction signal (Defense #4): runs a HARMLESS subprocess whose
    argv carries shadow-copy-destruction keywords —
    `echo vssadmin delete shadows /all /quiet`. echo does nothing destructive
    (no shadow copies are touched), but the argv matcher in observe_execve()
    fires BACKUP_DESTRUCTION on the keywords.
  * Bounded concurrency (Defense #5): a small, bounded (8-12 worker) thread pool
    renames sandbox files to 16-char extensions — a controlled burst that
    exercises the per-PID rate limiter WITHOUT flooding the host (thread count is
    capped; no unbounded spawning). The kernel rate-limit map/helper is the
    enforcement layer; its presence in the generated BPF source is asserted.

NOTE: benign simulation. No real malware, no real shadow-copy/backup deletion,
no unbounded threads. Files are backed up and restored.

    python3 -m simulations.sim_lockbit --target /tmp/rsentry_lab --traversal dfs
    python3 -m simulations.sim_lockbit --validate-defense --target /tmp/rsentry_sandbox
"""
import argparse
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

from simulations.sim_common import (
    ATTACKER_PID, ATTACKER_PPID, DefenseResult, Profile, Sandbox,
    add_common_args, build_validation_engine, main_for, rand_ext, _set_comm,
)

PROFILE = Profile(
    name="LOCKBIT5",
    ext_fn=rand_ext(16),
    mode="two_pass",
    delay=0.0,
    note_name="ReadMeForDecrypt.txt",
    note_text=b"[SIMULATION] LockBit 5.0: your files are locked.\n",
    priority_exts=("vmdk", "vmx", "vmsn"),
)

# Bounded worker count for the rename burst — capped so we never flood the host.
_BURST_WORKERS = 10
assert 8 <= _BURST_WORKERS <= 12
# Harmless argv that carries backup-destruction keywords. `echo` is the program;
# vssadmin/delete/shadows are mere string arguments printed to stdout.
_BACKUP_DESTRUCT_ARGV = ["echo", "vssadmin", "delete", "shadows", "/all", "/quiet"]


def _harmless_backup_destruct() -> dict:
    """Run the harmless echo and prove it had no destructive effect."""
    proc = subprocess.run(_BACKUP_DESTRUCT_ARGV, capture_output=True, text=True)
    return {
        "argv": _BACKUP_DESTRUCT_ARGV,
        "stdout": proc.stdout.strip(),
        "returncode": proc.returncode,
        # echo simply prints its arguments; nothing was deleted.
        "destructive": False,
    }


def _bounded_rename_burst(sb: Sandbox, files):
    """Rename each sandbox file to a 16-char extension using a bounded thread
    pool. Returns the (src, dst) pairs in completion order so the rename stream
    can be replayed into the detector. Every path is asserted in-sandbox."""
    results = []
    ext16 = rand_ext(16)  # factory -> 16-char random extension generator

    def _rename_one(src):
        p = sb.assert_inside(src)
        dst = sb.assert_inside(str(p) + "." + ext16())
        os.rename(p, dst)
        return (str(p), str(dst))

    with ThreadPoolExecutor(max_workers=_BURST_WORKERS) as pool:
        for pair in pool.map(_rename_one, files):
            results.append(pair)
    return results


def validate_defense(target: str) -> int:
    """SAFE, sandbox-guarded reproduction of LockBit backup-destruction +
    bounded burst, validated against Defenses #4 (execve matcher) and #5
    (per-PID rate limiter, kernel enforcement layer)."""
    from agent.monitor_ebpf import build_bpf

    with Sandbox(target) as sb:
        sb.arm()
        engine = build_validation_engine(sb.root_real)

        # --- Defense #4: backup-destruction tooling at execve ----------------
        echo = _harmless_backup_destruct()
        exec_evt = engine.observe_execve(
            ATTACKER_PID, ATTACKER_PPID, "lockbit-sim",
            _BACKUP_DESTRUCT_ARGV, ts=1.0,
        )
        defense4_ok = (exec_evt is not None
                       and exec_evt["event_type"] == "BACKUP_DESTRUCTION")

        # --- Defense #5: bounded concurrent rename burst ---------------------
        burst_files = sb.corpus_files()[:_BURST_WORKERS]
        pairs = _bounded_rename_burst(sb, burst_files)
        # Replay the rename stream into the velocity-gated detector.
        burst_event = None
        for i, (src, dst) in enumerate(pairs):
            evt = engine.observe_rename(
                ATTACKER_PID, ATTACKER_PPID, "lockbit-sim",
                src, dst, ts=float(i) * 0.001,
            )
            if evt is not None and burst_event is None:
                burst_event = evt
        # Rate limiting is a kernel-side enforcement; assert the generated BPF
        # carries the per-CPU rate map + helper wired into the hot-path handlers.
        src_bpf = build_bpf(enforce=True, lsm=True)
        rate_limit_wired = (
            "BPF_PERCPU_HASH(rate_state" in src_bpf
            and "#define RATE_LIMIT" in src_bpf
            and "__rate_limited" in src_bpf
            and src_bpf.count("if (__rate_limited(pid, ts)) return 0;") >= 4
        )
        defense5_ok = (burst_event is not None and rate_limit_wired
                       and len(pairs) <= _BURST_WORKERS)

        result = DefenseResult(
            family="LOCKBIT5",
            defense="#4 backup-destruction + #5 per-PID rate limit",
            signal="BACKUP_DESTRUCTION / rate-limit",
            fired=defense4_ok and defense5_ok,
            files_harmed=0,  # confirmed by Sandbox.audit() on __exit__
            detail={
                "echo_stdout": echo["stdout"],
                "echo_returncode": echo["returncode"],
                "echo_destructive": echo["destructive"],
                "exec_signal": exec_evt["event_type"] if exec_evt else None,
                "exec_keywords": exec_evt["details"].get("keywords") if exec_evt else None,
                "parent_frozen": ATTACKER_PPID in engine._frozen_pids,
                "burst_workers": _BURST_WORKERS,
                "burst_renames": len(pairs),
                "burst_signal": burst_event["event_type"] if burst_event else None,
                "burst_family": (burst_event["details"].get("profile")
                                 if burst_event else None),
                "kernel_rate_limit_wired": rate_limit_wired,
            },
        )
    print(result.banner())
    return 0 if result.fired else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LockBit 5.0 behavioural simulator (safe)")
    add_common_args(ap)
    ap.add_argument("--validate-defense", action="store_true",
                    help="run session_09 sandbox-guarded Defense #4/#5 validation "
                         "(harmless backup-destruct echo + bounded rename burst)")
    args, _ = ap.parse_known_args()
    if args.validate_defense:
        raise SystemExit(validate_defense(args.target))
    _set_comm("lockbit-sim")
    print("[LOCKBIT5] (simulation) would self-delete and wipe free space post-encryption")
    raise SystemExit(main_for(PROFILE, ap))
