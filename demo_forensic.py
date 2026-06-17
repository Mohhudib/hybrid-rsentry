#!/usr/bin/env python3
"""
demo_forensic.py — Forensic walkthrough of a single ransomware family.

Documents the FULL story of one attack and LEAVES the files on disk so you can
open them on the machine and screenshot the before/after:

  1. BEFORE  — seeds a persistent corpus; prints each file's name, size, content
               preview, Shannon entropy, age, and SHA-256.
  2. ATTACK  — launches a fresh agent (enforce + LSM) and runs the family's
               simulation against THAT corpus, printing the detection +
               containment timeline (layer fired, time-to-detect, stages).
  3. AFTER   — re-scans the same corpus and prints what changed (renames,
               in-place encryption, entropy jumps, SHA changes, canary survival).

Unlike the evaluation harness (which uses a throwaway temp dir and cleans up),
this runs the agent + sim against a PERSISTENT directory and does NOT delete it,
so the artifacts remain for inspection. It still does full agent / iptables /
cgroup cleanup, so the host is left clean.

Usage (privileged — the agent needs root for eBPF/LSM):
    sudo -E ./venv/bin/python demo_forensic.py <family>

Families: akira  qilin  lockbit  entropy_only  canary_touch  writeoffset_only

Cleanup the artifacts when done:
    sudo rm -rf /tmp/rsentry_demo
"""

import sys, os, time, math, shutil, hashlib, signal
from collections import Counter
from pathlib import Path

# --------------------------------------------------------------------------- #
# Pretty printing
# --------------------------------------------------------------------------- #
_TTY = sys.stdout.isatty()
def _c(code, s): return f"\033[{code}m{s}\033[0m" if _TTY else s
BOLD  = lambda s: _c("1", s)
GREEN = lambda s: _c("0;32", s)
RED   = lambda s: _c("0;31", s)
YEL   = lambda s: _c("1;33", s)
CYAN  = lambda s: _c("0;36", s)
GREY  = lambda s: _c("0;90", s)

def banner(t):
    line = "=" * 70
    print("\n" + CYAN(line)); print(CYAN("  " + t)); print(CYAN(line))
def section(t):
    print("\n" + BOLD("--- " + t + " " + "-" * max(0, 66 - len(t))))

FAMILIES = {
    "akira":            "rename",
    "qilin":            "rename",
    "lockbit":          "rename",
    "entropy_only":     "entropy",
    "canary_touch":     "canary",
    "writeoffset_only": "write_offset",
}
DEMO_ROOT = Path("/tmp/rsentry_demo")
CANARY_PREFIXES = ("AAA_", "aaa_", "ZZZ_", "zzz_")

# --------------------------------------------------------------------------- #
# Snapshot helpers
# --------------------------------------------------------------------------- #
def _sha(p: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for c in iter(lambda: f.read(65536), b""): h.update(c)
        return h.hexdigest()[:16]
    except OSError:
        return "(unreadable)"

def _entropy(p: Path) -> float:
    try:
        data = p.read_bytes()
        if not data: return 0.0
        n = len(data); ctr = Counter(data)
        return -sum((c/n) * math.log2(c/n) for c in ctr.values())
    except OSError:
        return 0.0

def _preview(p: Path, n: int = 60) -> str:
    try:
        b = p.read_bytes()[:n]
        try: return b.decode("utf-8", errors="replace").replace("\n", "\\n")
        except Exception: return b.hex()
    except OSError:
        return "(unreadable)"

def snapshot(root: Path) -> dict:
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root))
            st = p.stat()
            snap[rel] = {"size": st.st_size, "sha": _sha(p),
                         "entropy": round(_entropy(p), 2),
                         "age_days": round((time.time() - st.st_mtime)/86400.0, 1)}
    return snap

def print_snapshot(snap: dict, root: Path, preview=True):
    if not snap:
        print(GREY("  (no files)")); return
    for rel, m in snap.items():
        is_can = os.path.basename(rel).startswith(CANARY_PREFIXES)
        print(f"  {BOLD(rel)}{YEL(' [canary]') if is_can else ''}")
        print(GREY(f"      size={m['size']}B  entropy={m['entropy']} bits/byte"
                   f"  age={m['age_days']}d  sha={m['sha']}"))
        if preview:
            print(GREY(f"      preview: {_preview(root / rel)}"))

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    if len(sys.argv) != 2 or sys.argv[1] not in FAMILIES:
        print(f"usage: sudo -E ./venv/bin/python {sys.argv[0]} <family>")
        print(f"families: {'  '.join(FAMILIES)}"); sys.exit(2)

    family = sys.argv[1]
    expected_layer = FAMILIES[family]

    if os.geteuid() != 0:
        print(RED("Must run as root (the agent uses eBPF/LSM)."))
        print(f"Run: sudo -E ./venv/bin/python {sys.argv[0]} {family}"); sys.exit(1)

    # Import harness internals — we reuse its validated launch/observe primitives
    # but drive them against a PERSISTENT dir and skip the filesystem teardown.
    from tests.evaluation.corpus import malicious_samples as M
    from tests.evaluation import harness as H

    banner(f"HYBRID R-SENTRY — FORENSIC DEMO: {family.upper()}")
    print(f"  Expected detection layer: {BOLD(expected_layer)}")

    # Pre-flight: refuse if an agent is already running or env is dirty.
    if H._agent_already_running():
        print(RED("An agent.monitor is already running — stop it first.")); sys.exit(1)
    if H._contain_rules() or H._cgroup_dirs():
        print(RED("Pre-existing rsentry-contain rule/cgroup — clean the env first:"))
        print(GREY("  sudo iptables -S OUTPUT | grep rsentry-contain | "
                   "sed 's/^-A/-D/' | while read r; do sudo iptables $r; done"))
        print(GREY("  sudo rmdir /sys/fs/cgroup/rsentry-contain-* 2>/dev/null"))
        sys.exit(1)

    import uuid
    work = DEMO_ROOT / family
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o777, parents=True)
    os.chown(work, H.OPERATOR_UID, H.OPERATOR_GID)

    entry = [x for x in M.malicious_plan(1) if x["family"] == family][0]
    wl = M.build_workload(entry)
    restart_id = uuid.uuid4().hex[:12]
    baseline_chain = H._output_chain()

    agent = wl_proc = stub = ts_path = symlink_path = log_path = None
    try:
        # ----- 1. BEFORE -----------------------------------------------------
        # Ordering MIRRORS run_trial EXACTLY: start the agent and wait for
        # readiness FIRST, THEN create the corpus, THEN launch + observe
        # (harness.run_trial: _start_agent -> _wait_ready -> workload.setup ->
        # _launch_workload -> _observe). This is the ordering/timing the manual
        # replication missed. Creating the corpus BEFORE the agent (the old order)
        # let the agent's OWN startup canary placement walk into the freshly
        # created corpus zone and seed decoys there, and for canary_touch left the
        # sim renaming decoys the running agent had never registered in its BPF
        # canary_inodes map — so the canary inode never matched and detection was
        # missed. With the agent live first, `work` is empty when it seeds, so its
        # decoys land only in the watch ROOT (never the corpus zone), exactly as in
        # run_trial. The demo therefore seeds NO decoys itself: the eBPF agent
        # seeds its own (via place_canaries/seed_canaries) and only those
        # agent-registered inodes can fire layer=canary.
        section("1. BEFORE — agent live (enforce + LSM); corpus + agent decoys on disk")
        print(GREY("  Agent loads eBPF probes + LSM hooks and places its OWN "
                   "decoys; the demo never seeds decoys itself.\n"))

        H.EVAL_BASE.mkdir(parents=True, exist_ok=True)   # _start_agent writes its log here
        stub = H._StubBackend(); stub.start()
        agent, log_path = H._start_agent(work, lsm=True, enforce=True,
                                         backend_url=stub.url, restart_id=restart_id)
        if not H._wait_ready(log_path, agent, H.READY_TIMEOUT):
            tail = "\n".join(H._read_text(log_path).splitlines()[-15:])
            print(RED(f"  agent did not reach readiness:\n{tail}")); sys.exit(1)

        # Corpus created AFTER the agent is ready (run_trial parity). For
        # canary_touch this returns `work` and the decoys are the ones the agent
        # itself just seeded + registered, so renaming one hits a REAL canary inode.
        target = wl.setup(work)
        print(f"  watch dir : {work}")
        print(f"  attack dir: {target}")
        # Snapshot the ATTACK dir, not the watch root. For non-canary families the
        # corpus lives in `work/<family>_zone` and the agent's decoys sit in the
        # watch ROOT (outside `target`) — so they never appear here and never
        # pollute the diff. For canary_touch, target == work, so the agent-seeded
        # decoys (the thing under attack) ARE shown. This is how "only canary_touch
        # has decoys in the view" falls out without the demo seeding anything.
        before = snapshot(target)
        print(f"\n  {len(before)} file(s) in the attack dir:\n")
        print_snapshot(before, target)

        # ----- 2. ATTACK -----------------------------------------------------
        section("2. ATTACK — running the sim against that corpus")
        print(GREY("  The sim runs under a non-safelisted comm; the agent observes "
                   "from the outside.\n"))

        wl_proc, ts_path, symlink_path, argv = H._launch_workload(
            wl, target, stub.url, restart_id)
        wl_pid = wl_proc.pid

        # _observe CONTRACT (the exact call run_trial makes):
        #   _observe(log_path, pid, response_timeout, workload_proc)
        #     -> (stage_ns {stage -> monotonic_ns}, layer_fired str|None, excerpt)
        # It polls the SAME agent log the agent writes, matching PID-scoped lines:
        #   'detect'   = "SIGSTOP pipeline: pid=<PID> ... layer=<L>"  (DETECTION)
        #   'complete' = "CONTAINMENT COMPLETE PID <PID>"             (containment)
        # Detection is the 'detect' line — NOT inferred from the workload exiting
        # (the workload is SIGKILLed mid-pipeline, so _observe keeps polling for
        # 'complete' once 'detect' is seen, and only an UNDETECTED + exited
        # workload returns early). We therefore derive detected/contained the SAME
        # way run_trial does in enforce mode.
        stage_ns, layer_fired, _ = H._observe(log_path, wl_pid, 30.0, wl_proc)
        t0_ns, _ = H._read_sidechannel(ts_path)

        detected  = "detect" in stage_ns         # run_trial: detected = "detect" in stage_ns
        contained = "complete" in stage_ns        # run_trial: contained = "complete" in stage_ns
        def ms(a, b): return f"{(b-a)/1e6:.1f} ms" if (a and b) else "n/a"
        t_detect  = stage_ns.get("detect")
        t_sigstop = stage_ns.get("sigstop")
        t_kill    = stage_ns.get("kill")
        t_done    = stage_ns.get("complete")

        print(BOLD("  DETECTION & CONTAINMENT TIMELINE"))
        print(f"    detected        : {GREEN('YES') if detected else RED('NO')}")
        print(f"    layer fired     : {BOLD(str(layer_fired))}"
              + ("" if layer_fired == expected_layer
                 else RED(f"  (expected {expected_layer})")))
        print(f"    contained       : {GREEN('YES') if contained else RED('NO')}")
        print(f"    time-to-detect  : {ms(t0_ns, t_detect)}   (onset -> detection)")
        print(f"    detect->SIGSTOP : {ms(t_detect, t_sigstop)}   (freeze)")
        print(f"    SIGSTOP->kill   : {ms(t_sigstop, t_kill)}   (isolate + terminate)")
        print(f"    total contain   : {ms(t_detect, t_done)}   (detection -> complete)")

        # ----- 3. AFTER ------------------------------------------------------
        section("3. AFTER — what changed on disk")
        after = snapshot(target)
        bset, aset = set(before), set(after)
        new      = sorted(aset - bset)
        gone     = sorted(bset - aset)
        changed  = sorted(n for n in (bset & aset) if before[n]["sha"] != after[n]["sha"])

        if new:
            print(f"\n  {RED('NEW / RENAMED files (ransomware artifacts):')}")
            for n in new:
                m = after[n]
                is_can = os.path.basename(n).startswith(CANARY_PREFIXES)
                print(f"    + {BOLD(n)}{YEL(' [was a canary]') if is_can else ''}")
                print(GREY(f"        entropy={m['entropy']} bits/byte  sha={m['sha']}"))
                print(GREY(f"        preview: {_preview(target / n)}"))
        if gone:
            print(f"\n  {YEL('original names gone (renamed away):')}")
            for n in gone: print(f"    - {n}")
        if changed:
            print(f"\n  {RED('content changed in place (encrypted):')}")
            for n in changed:
                print(f"    ~ {BOLD(n)}  entropy "
                      f"{before[n]['entropy']} -> {after[n]['entropy']} bits/byte")
        if not (new or gone or changed):
            print(GREY("  (no on-disk change — the process was frozen before it could write)"))

        cans = [n for n in bset if os.path.basename(n).startswith(CANARY_PREFIXES)]
        if cans:
            intact = [n for n in cans if n in aset and before[n]["sha"] == after[n]["sha"]]
            print(f"\n  {BOLD('Canary decoys:')} {len(intact)}/{len(cans)} intact")

        # ----- VERDICT -------------------------------------------------------
        section("VERDICT")
        ok = detected and contained and layer_fired == expected_layer
        if ok:
            print(GREEN(f"  PASS — {family} detected via '{layer_fired}' and contained."))
        else:
            print(RED(f"  CHECK — detected={detected} layer={layer_fired} "
                      f"(expected {expected_layer}) contained={contained}"))
        print(f"\n  Files left on disk for inspection:\n    {BOLD(str(work))}")
        print(GREY(f"    open / screenshot them, then: sudo rm -rf {DEMO_ROOT}"))
        print()

    finally:
        # Cleanup the agent + host state, but PRESERVE the corpus dir (work).
        if agent is not None and agent.poll() is None:
            try: agent.terminate(); agent.wait(timeout=5)
            except Exception:
                try: agent.kill(); agent.wait(timeout=5)
                except Exception: pass
        if agent is not None: time.sleep(H.AGENT_SETTLE_S)
        if wl_proc is not None and wl_proc.poll() is None:
            for s in (signal.SIGCONT, signal.SIGKILL):
                try: os.kill(wl_proc.pid, s)
                except OSError: pass
        if stub is not None:
            try: stub.stop()
            except Exception: pass
        for ln in H._contain_rules():
            spec = ln.split()
            if spec and spec[0] == "-A":
                try: H._run(["iptables", "-D"] + spec[1:])
                except Exception: pass
        for cg in H._cgroup_dirs():
            try: cg.rmdir()
            except OSError: pass
        if symlink_path is not None and (symlink_path.exists() or symlink_path.is_symlink()):
            try: symlink_path.unlink()
            except OSError: pass
        if ts_path: Path(ts_path).unlink(missing_ok=True)
        if log_path is not None: Path(log_path).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
