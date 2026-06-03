#!/usr/bin/env python3
"""
sim_qilin.py — replicates Qilin (Agenda) documented behavioural profile (SAFE).

Qilin TTPs reproduced:
  * Opaque/random appended extension (affiliate builds vary per victim).
  * "percent" / fast encryption mode (encrypt a configurable head fraction).
  * Heavy targeting of ESXi datastore paths.
  * Bulk, fast traversal; drops a ransom note.

NOTE: benign simulation. No real malware. Files are backed up and restored.

    python3 sim_qilin.py --target /tmp/rsentry_lab --traversal dfs
"""
import argparse
from simulations.sim_common import Profile, add_common_args, main_for, rand_ext

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

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Qilin behavioural simulator (safe)")
    add_common_args(ap)
    raise SystemExit(main_for(PROFILE, ap))
