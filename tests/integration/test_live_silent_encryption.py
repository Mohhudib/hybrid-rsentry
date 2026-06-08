#!/usr/bin/env python3
"""
tests/integration/test_live_silent_encryption.py — LIVE end-to-end proof that
Defense #1 (SILENT_ENCRYPTION, MITRE ATT&CK **T1486 — Data Encrypted for Impact**)
fires on the REAL kernel ``kprobe__vfs_write`` path against a *fast* attacker, and
is no longer suppressed by the per-PID rate limiter.

THE BUG THIS GUARDS
    In ``agent/monitor_ebpf.py`` the per-PID rate limiter (``{_rl_check}`` →
    ``if (__rate_limited(pid, ts)) return 0;``) used to sit ABOVE the write-offset
    non-sequential counter inside ``kprobe__vfs_write``. A process writing faster
    than ``RATE_LIMIT`` (500 events/ms) — i.e. the real ransomware signature —
    tripped the limiter and early-returned, so its writes never reached the
    non-sequential counter. Result: Defense #1 fired in ``--validate-defense``
    mode (which calls ``observe_write_offset()`` directly, bypassing the kprobe)
    but NEVER against a live fast attack.

    The fix reorders the probe into three bands:
      1. CHEAP COUNTING  — the host-wide per-inode offset counter, NEVER rate-
                           limited (runs on every regular-file write).
      2. CRITICAL BYPASS — a confirmed silent_enc detection emits + freezes the
                           PID even while rate-limited.
      3. EXPENSIVE PATH  — behavioral profiling + burst emits, still throttled by
                           ``{_rl_check}``; an already-frozen PID is short-
                           circuited (post-freeze throttle) so it cannot flood
                           userspace with duplicate events.

WHAT THIS PROVES ON A LIVE KERNEL (nothing mocked — real BPF, real syscalls):
    * A sustained fast burst of NON-sequential writes to a NORMAL file (not a
      canary) lands the attacker PID in ``blocked_pids`` and emits a
      ``silent_enc`` write event — detection survives the rate limiter.
    * A slow benign SEQUENTIAL writer under otherwise-identical conditions is
      NEVER frozen and emits NO silent_enc event (no false positive).
    * Once frozen, the attacker (still writing thousands of times) does NOT flood
      userspace: the post-freeze throttle bounds the emit count.

USAGE
    # Privileged live run — needs root (load BPF + attach the vfs_write kprobe)
    # and a bcc-capable interpreter. The project venv is built WITHOUT system
    # site-packages, so use the system python3 that owns python3-bpfcc:
    sudo /usr/bin/python3 \
        tests/integration/test_live_silent_encryption.py

    # Unprivileged self-check (no BPF load; validates the source-level ordering
    # invariants that make the live behavior possible). Runs under any
    # interpreter — bcc is only imported on the privileged path:
    python3 tests/integration/test_live_silent_encryption.py --selfcheck

SAFETY
    * Spawned writer helpers only ever touch files under /tmp/rsentry_silentenc.
    * No canary files, no containment/SIGKILL is invoked — the test reads the
      BPF ``blocked_pids`` map directly to confirm the freeze, and kills its own
      helpers in a finally block.
"""
from __future__ import annotations

import os
import sys
import textwrap
import time
from pathlib import Path

# Make the project importable when run directly (sudo strips PYTHONPATH).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.monitor_ebpf import build_bpf  # noqa: E402

LAB_DIR = Path("/tmp/rsentry_silentenc")
# Must exceed NONSEQ_THRESH (5) comfortably and keep writing afterwards so the
# post-freeze throttle has thousands of suppressed writes to demonstrate against.
ATTACK_WRITES = 2000
BLOCK_SIZE = 4096
NONSEQ_STRIDE = BLOCK_SIZE * 7  # each write jumps far past the previous end


# --------------------------------------------------------------------------- #
# Writer helpers (run as separate processes so they have their own PID/inode)
# --------------------------------------------------------------------------- #

# Fast attacker: baseline append, then a tight burst of NON-sequential pwrites to
# the SAME inode (classic in-place block-cipher rewrite). os.pwrite is a thin
# libc wrapper, so this loop issues writes about as fast as Python can manage —
# dense enough to engage the per-PID rate limiter.
ATTACKER_SRC = textwrap.dedent(
    f"""
    import os, sys
    path = sys.argv[1]
    buf = b"\\x00" * {BLOCK_SIZE}
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    os.pwrite(fd, buf, 0)                       # baseline -> establishes last_end
    for i in range(1, {ATTACK_WRITES} + 1):
        os.pwrite(fd, buf, i * {NONSEQ_STRIDE}) # jump -> non-sequential every time
    os.close(fd)
    """
).strip()

# Slow benign writer: SEQUENTIAL appends with a pause between each — never seeks
# backward, never exceeds the rate limiter. Must stay clean.
BENIGN_SRC = textwrap.dedent(
    f"""
    import os, sys, time
    path = sys.argv[1]
    buf = b"\\x00" * {BLOCK_SIZE}
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    off = 0
    for _ in range(40):
        os.pwrite(fd, buf, off)                 # sequential -> offset == last_end
        off += {BLOCK_SIZE}
        time.sleep(0.05)                         # slow: ~20 writes/sec
    os.close(fd)
    """
).strip()


# --------------------------------------------------------------------------- #
# Results table (mirrors tests/integration/test_live_containment.py)
# --------------------------------------------------------------------------- #

class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, bool]] = []

    def check(self, name: str, expected: str, observed: str, ok: bool) -> bool:
        self.rows.append((name, expected, observed, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: "
              f"expected={expected!r} observed={observed!r}")
        return ok

    def render(self) -> bool:
        wc = max((len(r[0]) for r in self.rows), default=5)
        we = max((len(r[1]) for r in self.rows), default=8)
        wo = max((len(r[2]) for r in self.rows), default=8)
        wc, we, wo = max(wc, 5), max(we, 8), max(wo, 8)
        line = f"| {{:<{wc}}} | {{:<{we}}} | {{:<{wo}}} | {{:<6}} |"
        sep = f"|{'-'*(wc+2)}|{'-'*(we+2)}|{'-'*(wo+2)}|{'-'*8}|"
        print("\n" + "=" * 80)
        print("RESULTS")
        print("=" * 80)
        print(line.format("Check", "Expected", "Observed", "Result"))
        print(sep)
        for name, exp, obs, ok in self.rows:
            print(line.format(name, exp, obs, "PASS" if ok else "FAIL"))
        all_pass = all(r[3] for r in self.rows)
        print("=" * 80)
        print("OVERALL: " + (
            "PASS — Defense #1 (T1486) fires on the live kernel path; "
            "rate limiter no longer suppresses detection"
            if all_pass else "FAIL"))
        print("=" * 80)
        return all_pass


# --------------------------------------------------------------------------- #
# Self-check (no root): assert the source-level ordering invariants hold
# --------------------------------------------------------------------------- #

def _selfcheck(report: Report) -> int:
    """Validate the kprobe ordering that makes the live fix possible.

    Returns a process exit code (0 = all invariants hold).
    """
    src = build_bpf(enforce=True, lsm=True)
    body = src[src.index("int kprobe__vfs_write"):src.index("// ── Execve handler")]

    i_offset = body.index("write_offset.lookup")              # cheap counter
    i_rl = body.index("if (__rate_limited(pid, ts)) return 0;")
    i_bypass = body.index("CRITICAL EVENT BYPASS")
    has_throttle = ("POST-FREEZE THROTTLE" in body
                    and "if (blocked && *blocked) return 0;" in body)

    report.check("offset counter precedes rate limiter",
                 "counter<limiter", f"{i_offset}<{i_rl}", i_offset < i_rl)
    report.check("critical bypass precedes rate limiter",
                 "bypass<limiter", f"{i_bypass}<{i_rl}", i_bypass < i_rl)
    report.check("post-freeze throttle present",
                 "present", "present" if has_throttle else "absent", has_throttle)
    # Rate limiter must still exist in vfs_write (relocated, not deleted) and in
    # the other three hot-path probes.
    report.check("rate limiter still wired into >=4 probes",
                 ">=4", str(src.count("if (__rate_limited(pid, ts)) return 0;")),
                 src.count("if (__rate_limited(pid, ts)) return 0;") >= 4)
    print("\n[self-check] Source ordering invariants verified. "
          "Run with sudo for the full live-kernel proof.")
    return 0 if report.render() else 1


# --------------------------------------------------------------------------- #
# Live run (root): load BPF, attach kprobe, race a real attacker vs benign writer
# --------------------------------------------------------------------------- #

def _live(report: Report) -> int:
    try:
        from bcc import BPF  # type: ignore
    except Exception as exc:  # pragma: no cover - environment-dependent
        print(f"FAIL: bcc not importable ({exc}); cannot run live kernel test")
        return 3

    import subprocess

    LAB_DIR.mkdir(mode=0o777, exist_ok=True)
    os.chmod(LAB_DIR, 0o777)
    attack_file = LAB_DIR / "attacker.dat"
    benign_file = LAB_DIR / "benign.dat"
    for f in (attack_file, benign_file):
        f.write_bytes(b"")

    # Load the SAME source the agent runs. lsm=False keeps the test independent of
    # the lsm=bpf kernel param: the silent_enc detection + blocked_pids freeze in
    # kprobe__vfs_write are unconditional, so the live path is exercised either way.
    print("[1] LOAD — build_bpf(enforce=True, lsm=False) + attach vfs_write kprobe")
    src = build_bpf(enforce=True, lsm=False)
    b = BPF(text=src)  # kprobe__vfs_write auto-attaches by name

    # Per-PID tally of write events, split by silent_enc flag.
    counts: dict[int, dict[str, int]] = {}

    def _on_write(cpu, data, size):  # noqa: ANN001 - bcc callback signature
        ev = b["write_events"].event(data)
        c = counts.setdefault(int(ev.pid), {"total": 0, "silent": 0})
        c["total"] += 1
        if int(getattr(ev, "silent_enc", 0)):
            c["silent"] += 1

    b["write_events"].open_perf_buffer(_on_write, page_cnt=64)

    def _is_blocked(pid: int) -> bool:
        try:
            v = b["blocked_pids"][b["blocked_pids"].Key(pid)]
            return int(v.value) == 1
        except Exception:
            return False

    attacker = benign = None
    try:
        # ---- 2. SLOW BENIGN (must stay clean) -------------------------------
        print("[2] BENIGN — slow sequential writer (must NOT be frozen)")
        benign = subprocess.Popen([sys.executable, "-c", BENIGN_SRC, str(benign_file)])

        # ---- 3. FAST ATTACKER (must be frozen) ------------------------------
        print("[3] ATTACK — fast non-sequential write burst to a NORMAL file")
        attacker = subprocess.Popen([sys.executable, "-c", ATTACKER_SRC, str(attack_file)])
        attacker_pid = attacker.pid
        benign_pid = benign.pid
        print(f"    attacker PID={attacker_pid}  benign PID={benign_pid}")

        # Drain the perf buffer while the writers run + briefly after.
        deadline = time.time() + 12
        attacker_blocked_at = None
        while time.time() < deadline:
            b.perf_buffer_poll(timeout=100)
            if attacker_blocked_at is None and _is_blocked(attacker_pid):
                attacker_blocked_at = time.time()
            if attacker.poll() is not None and benign.poll() is not None:
                # Keep draining a moment after both exit to flush the buffer.
                for _ in range(5):
                    b.perf_buffer_poll(timeout=100)
                break

        att = counts.get(attacker_pid, {"total": 0, "silent": 0})
        ben = counts.get(benign_pid, {"total": 0, "silent": 0})

        # ---- 4. ASSERT ------------------------------------------------------
        print("[4] ASSERT")
        report.check("attacker frozen in blocked_pids (Defense #1 fired live)",
                     "blocked=True",
                     f"blocked={_is_blocked(attacker_pid)}",
                     _is_blocked(attacker_pid))
        report.check("attacker emitted a silent_enc event",
                     ">=1", str(att["silent"]), att["silent"] >= 1)
        report.check("benign writer NOT frozen (no false positive)",
                     "blocked=False",
                     f"blocked={_is_blocked(benign_pid)}",
                     not _is_blocked(benign_pid))
        report.check("benign writer emitted NO silent_enc event",
                     "0", str(ben["silent"]), ben["silent"] == 0)
        # Post-freeze throttle: the attacker issued ~ATTACK_WRITES writes yet,
        # once frozen, duplicate emits are suppressed. Bound total emits well
        # below the write count (generous bound absorbs the pre-freeze + race
        # window) to prove there is no event flood.
        report.check("no event flood for frozen PID (post-freeze throttle)",
                     f"<=50 (of {ATTACK_WRITES} writes)",
                     str(att["total"]), att["total"] <= 50)

        return 0 if report.render() else 1

    finally:
        print("\n[teardown] killing writer helpers")
        for name, proc in (("attacker", attacker), ("benign", benign)):
            if proc is not None and proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                print(f"    killed {name} PID={proc.pid}")


def main() -> int:
    report = Report()
    if "--selfcheck" in sys.argv:
        return _selfcheck(report)
    if os.geteuid() != 0:
        print("\n" + "!" * 78)
        print("FAIL: live silent-encryption test needs root to load BPF + attach the kprobe.")
        print("Run (review the script first):")
        print(f"  sudo {sys.executable} {Path(__file__).resolve()}")
        print("Or validate the source-ordering invariants without root:")
        print(f"  {sys.executable} {Path(__file__).resolve()} --selfcheck")
        print("!" * 78)
        return 2
    return _live(report)


if __name__ == "__main__":
    sys.exit(main())
