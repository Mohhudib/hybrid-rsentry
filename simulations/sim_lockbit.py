#!/usr/bin/env python3
"""
sim_lockbit.py — replicates LockBit 5.0 documented behavioural profile (SAFE).

LockBit 5.0 TTPs reproduced:
  * Randomised 16-character extension (the 5.0 signature).
  * Two-pass write (quick partial pass, then a thorough pass).
  * Targets VM datastore files (.vmdk/.vmx/.vmsn).
  * Drops ReadMeForDecrypt.txt; simulates post-encryption self-delete (logged).

NOTE: benign simulation. No real malware. Files are backed up and restored.

    python3 sim_lockbit.py --target /tmp/rsentry_lab --traversal dfs
"""
import argparse
from simulations.sim_common import Profile, add_common_args, main_for, rand_ext

PROFILE = Profile(
    name="LOCKBIT5",
    ext_fn=rand_ext(16),
    mode="two_pass",
    delay=0.0,
    note_name="ReadMeForDecrypt.txt",
    note_text=b"[SIMULATION] LockBit 5.0: your files are locked.\n",
    priority_exts=("vmdk", "vmx", "vmsn"),
)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LockBit 5.0 behavioural simulator (safe)")
    add_common_args(ap)
    print("[LOCKBIT5] (simulation) would self-delete and wipe free space post-encryption")
    raise SystemExit(main_for(PROFILE, ap))
