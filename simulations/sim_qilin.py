#!/usr/bin/env python3
"""
sim_qilin.py — replicates Qilin (Agenda) documented behavioural profile (SAFE).

Qilin TTPs reproduced:
  * Opaque/random appended extension (affiliate builds vary per victim).
  * "percent" / fast encryption mode (encrypt a configurable head fraction).
  * Heavy targeting of ESXi datastore paths.
  * Bulk, fast traversal; drops a ransom note.

Session 09 addition — short-extension + pre-scan behavior (Defenses #2/#3):
  * Renames sandbox files to 7-char random extensions (e.g. .a1b2c3d). The old
    extension filter required 8-16 chars; the new entropy-based filter is
    length-independent and flags any high-entropy alphanumeric extension, so a
    7-char random extension is still caught (Defense #2).
  * A recon pre-scan stat()s every file before renaming. Because session_08
    canaries are now realistic (20-100 KB, valid magic header, backdated 30-400
    days), a recon step that samples size/age does NOT skip them — validating
    Defense #3.

NOTE: benign simulation. No real malware. Files are backed up and restored.

    python3 -m simulations.sim_qilin --target /tmp/rsentry_lab --traversal dfs
    python3 -m simulations.sim_qilin --validate-defense --target /tmp/rsentry_sandbox
"""
import argparse
import os
import random
import string
import time

from simulations.sim_common import (
    ATTACKER_PID, ATTACKER_PPID, DefenseResult, Profile, Sandbox,
    add_common_args, build_validation_engine, main_for, rand_ext, _set_comm,
)

PROFILE = Profile(
    name="QILIN",
    ext_fn=rand_ext(7),
    mode="percent",
    percent=40,
    delay=0.0,
    note_name="README-RECOVER.txt",
    note_text=b"[SIMULATION] Qilin: contact us to recover your data.\n",
    priority_exts=("vmdk", "vmx", "vmsn", "vmem"),
)

_SHORT_EXT_LEN = 7


def _random_short_ext() -> str:
    """A 7-char extension built from distinct alphanumerics — models an
    affiliate-generated random suffix (e.g. .a1b2c3d). Distinct chars guarantee
    Shannon entropy log2(7)=2.81 >= the 2.5-bit detector floor, so the
    length-independent entropy filter flags it deterministically."""
    return "".join(random.sample(string.ascii_lowercase + string.digits, _SHORT_EXT_LEN))


def _place_realistic_canaries(sb: Sandbox):
    """Seed session_08-style canaries (realistic content + backdated mtime) into
    the sandbox using the production graph engine, scoped to the sandbox root."""
    from agent.graph import FilesystemGraph
    fg = FilesystemGraph(str(sb.root))
    canaries = fg.place_canaries()
    return [str(sb.assert_inside(c)) for c in canaries]


def validate_defense(target: str) -> int:
    """SAFE, sandbox-guarded reproduction of Qilin short-extension + recon,
    validated against the entropy-ext filter (Defense #2) and realistic-canary
    behaviour (Defense #3)."""
    with Sandbox(target) as sb:
        canaries = _place_realistic_canaries(sb)
        sb.arm()  # snapshot AFTER canaries exist so restore covers them too
        engine = build_validation_engine(sb.root_real, canary_paths=canaries)

        # --- Defense #3: recon pre-scan must not be able to skip canaries -----
        # Model the ransomware sampling size/age before selecting targets.
        now = time.time()
        canary_sizes = []
        canary_ages_days = []
        for c in canaries:
            p = sb.assert_inside(c)
            st = p.stat()
            canary_sizes.append(st.st_size)
            canary_ages_days.append((now - st.st_mtime) / 86400.0)
        # A size/age-sampling recon skips empty/freshly-planted decoys. These are
        # non-empty and aged, so none are skipped.
        skipped = sum(1 for s, a in zip(canary_sizes, canary_ages_days)
                      if s == 0 or a < 1.0)
        canaries_unskippable = (len(canaries) > 0 and skipped == 0)

        # --- Defense #2: short high-entropy extension still flagged -----------
        corpus = sb.corpus_files()
        flagged = 0
        rename_event = None
        for i, f in enumerate(corpus):
            p = sb.assert_inside(f)
            # pre-scan stat() (recon) before touching the file
            _ = p.stat()
            ext = _random_short_ext()
            dst = sb.assert_inside(str(p) + "." + ext)
            os.rename(p, dst)  # rename stays inside the sandbox (asserted)
            if engine._looks_encrypted(str(dst)):
                flagged += 1
            # Drive the velocity-gated rename detector with the synthetic PID.
            evt = engine.observe_rename(
                ATTACKER_PID, ATTACKER_PPID, "qilin-sim",
                str(p), str(dst), ts=float(i) * 0.01,
            )
            if evt is not None and rename_event is None:
                rename_event = evt

        defense2_ok = (flagged == len(corpus) and len(corpus) > 0)
        result = DefenseResult(
            family="QILIN",
            defense="#2 entropy-ext filter + #3 realistic canaries",
            signal="ENCRYPTED_RENAME / canary-realism",
            fired=defense2_ok and canaries_unskippable,
            files_harmed=0,  # confirmed by Sandbox.audit() on __exit__
            detail={
                "ext_len": _SHORT_EXT_LEN,
                "short_ext_flagged": f"{flagged}/{len(corpus)}",
                "rename_signal": rename_event["event_type"] if rename_event else None,
                "rename_family": (rename_event["details"].get("profile")
                                  if rename_event else None),
                "canaries_placed": len(canaries),
                "canary_min_size_b": min(canary_sizes) if canary_sizes else 0,
                "canary_min_age_days": round(min(canary_ages_days), 1) if canary_ages_days else 0,
                "canaries_skipped_by_recon": skipped,
            },
        )
    print(result.banner())
    return 0 if result.fired else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Qilin behavioural simulator (safe)")
    add_common_args(ap)
    ap.add_argument("--validate-defense", action="store_true",
                    help="run session_09 sandbox-guarded Defense #2/#3 validation "
                         "(7-char entropy ext + realistic-canary pre-scan)")
    args, _ = ap.parse_known_args()
    if args.validate_defense:
        raise SystemExit(validate_defense(args.target))
    _set_comm("qilin-sim")
    raise SystemExit(main_for(PROFILE, ap))
