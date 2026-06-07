#!/usr/bin/env python3
"""
sim_akira.py — replicates Akira's documented behavioural profile (SAFE sim).

Akira TTPs reproduced:
  * Extension .akiranew (ESXi/Linux v2 variant; .akira on the C++ line).
  * Intermittent / partial encryption (encrypt some blocks, skip others) for
    speed — the technique designed to evade naive per-file entropy thresholds.
  * Very high speed / low inter-file delay (sub-hour full-host encryption).
  * Prioritises VM datastore files (.vmdk/.vmx) then documents.
  * Drops akira_readme.txt.

Session 09 addition — skip-step / non-sequential write pattern (Defense #1):
  Akira's intermittent encryption issues a read-modify-write storm whose write
  offsets jump around the file (write a block, seek forward, write again) rather
  than advancing sequentially. That non-sequential offset pattern is exactly
  what the eBPF write-offset tracker flags as SILENT_ENCRYPTION. The
  `--validate-defense` mode reproduces it SAFELY: it writes os.urandom() bytes
  at jumped offsets inside a sentinel-guarded sandbox (no cipher, files backed
  up and restored) and feeds the identical offset/length sequence into the
  userspace DetectionEngine to confirm SILENT_ENCRYPTION fires.

NOTE: benign simulation. No real malware. Files are backed up and restored.
Run the R-Sentry sensor first, then this, to measure detection.

    python3 -m simulations.sim_akira --target /tmp/rsentry_lab --traversal dfs
    python3 -m simulations.sim_akira --validate-defense --target /tmp/rsentry_sandbox
"""
import argparse
import os

from simulations.sim_common import (
    ATTACKER_PID, ATTACKER_PPID, DefenseResult, Profile, Sandbox,
    add_common_args, build_validation_engine, main_for,
)

PROFILE = Profile(
    name="AKIRA",
    ext_fn=lambda: "akiranew",
    mode="intermittent",
    block=4096,
    step=2,
    delay=0.0,
    note_name="akira_readme.txt",
    note_text=b"[SIMULATION] Akira: your network has been encrypted.\n",
    priority_exts=("vmdk", "vmx", "edb", "vhd"),
)

# Skip-step write geometry: write a 4 KB block, seek +10 KB, write again.
_WRITE_BLOCK = 4096
_SEEK_STRIDE = 10 * 1024
_WRITES_PER_FILE = 8


def _skip_step_writes(sb: Sandbox, path):
    """Perform Akira-style non-sequential in-place writes on one sandbox file.

    Returns the list of (offset, length) pairs issued, in order, so the caller
    can replay the identical sequence into the DetectionEngine. The bytes
    written are os.urandom() — high entropy, but NO cipher and NO key: a real
    encryptor is never invoked.
    """
    p = sb.assert_inside(path)
    issued = []
    size = p.stat().st_size
    # Open for in-place update (r+b): no rename, no extension change — the
    # defining trait of "silent" in-place encryption.
    with open(p, "r+b") as fh:
        offset = 0
        for _ in range(_WRITES_PER_FILE):
            fh.seek(offset)
            fh.write(os.urandom(_WRITE_BLOCK))
            issued.append((offset, _WRITE_BLOCK))
            # Jump forward by a non-contiguous stride so the next write does NOT
            # land at offset+_WRITE_BLOCK (which would look sequential/benign).
            offset += _SEEK_STRIDE
            if offset > size + _SEEK_STRIDE:
                offset = (offset % max(1, size)) + 1  # wrap, stay non-sequential
        fh.flush()
        os.fsync(fh.fileno())
    return issued


def validate_defense(target: str) -> int:
    """SAFE, sandbox-guarded reproduction of Akira intermittent encryption,
    validated against the userspace write-offset detector (Defense #1)."""
    with Sandbox(target) as sb:
        sb.arm()
        engine = build_validation_engine(sb.root_real)
        files = sb.corpus_files()
        target_file = files[0]
        inode = sb.assert_inside(target_file).stat().st_ino

        issued = _skip_step_writes(sb, target_file)

        # Replay the identical offset/length stream into the detector. The first
        # write to an inode is the baseline; each subsequent non-sequential write
        # increments the counter until _NONSEQ_THRESHOLD trips SILENT_ENCRYPTION.
        signal = None
        nonseq_seen = 0
        for i, (off, length) in enumerate(issued):
            evt = engine.observe_write_offset(
                ATTACKER_PID, ATTACKER_PPID, "akira-sim",
                inode, off, length, str(target_file), ts=float(i),
            )
            if i > 0:
                nonseq_seen += 1
            if evt is not None:
                signal = evt
                break

        result = DefenseResult(
            family="AKIRA",
            defense="#1 write-offset analysis",
            signal="SILENT_ENCRYPTION",
            fired=signal is not None and signal["event_type"] == "SILENT_ENCRYPTION",
            files_harmed=0,  # confirmed by Sandbox.audit() on __exit__
            detail={
                "writes_issued": len(issued),
                "non_sequential_writes": nonseq_seen,
                "pid_frozen": ATTACKER_PID in engine._frozen_pids,
                "severity": signal["severity"] if signal else None,
                "entropy_delta": signal["entropy_delta"] if signal else None,
                "pattern": signal["details"].get("pattern") if signal else None,
            },
        )
    print(result.banner())
    return 0 if result.fired else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Akira behavioural simulator (safe)")
    add_common_args(ap)
    ap.add_argument("--validate-defense", action="store_true",
                    help="run session_09 sandbox-guarded Defense #1 validation "
                         "(non-sequential offset writes -> SILENT_ENCRYPTION)")
    args, _ = ap.parse_known_args()
    if args.validate_defense:
        raise SystemExit(validate_defense(args.target))
    raise SystemExit(main_for(PROFILE, ap))
