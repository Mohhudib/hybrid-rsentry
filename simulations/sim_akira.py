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

NOTE: benign simulation. No real malware. Files are backed up and restored.
Run the R-Sentry sensor first, then this, to measure detection.

    python3 sim_akira.py --target /tmp/rsentry_lab --traversal dfs
"""
import argparse
from simulations.sim_common import Profile, add_common_args, main_for

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

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Akira behavioural simulator (safe)")
    add_common_args(ap)
    raise SystemExit(main_for(PROFILE, ap))
