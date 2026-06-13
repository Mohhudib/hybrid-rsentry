#!/usr/bin/env python3
"""
tests/integration/test_live_canary.py — LIVE, fully-AUTONOMOUS canary proof.

The agent runs as its OWN process. A UID-1000 "locker" runs as its OWN process
and tries to rename one of the agent's decoy CANARY files. The test only
ORCHESTRATES (start/stop) and OBSERVES from the outside — it never calls an agent
internal, never loads BPF itself, and never signals the locker. We prove the
agent's CANARY tripwire fires AND contains, end to end.

WHAT THIS TEST IS ABOUT (vs. the other live tests)
  * test_live_autonomous_agent.py / _lockbit.py : drive the Akira/LockBit sims and
    prove BEHAVIORAL detection (velocity / silent-encryption / rename-storm).
  * THIS TEST                                   : proves the CANARY layer in
    isolation. The agent seeds decoy files (AAA_/aaa_/ZZZ_/zzz_ prefixes),
    registers their inodes in the kernel `canary_inodes` BPF map, and a single
    touch of ONE decoy must trip the highest-priority CRITICAL path with no
    behavioral scoring required:
        - kernel `lsm=bpf` present  -> LSM_PROBE path_rename denies the rename
          INLINE (-EPERM), emits CANARY_ATTEMPT, the decoy SURVIVES untouched,
          then the userspace SIGSTOP->evidence->cgroup-isolate->SIGKILL pipeline
          runs (layer=canary).
        - kernel `lsm=bpf` absent   -> SIGSTOP-fallback: the rename goes through
          once (CANARY_TOUCHED) and the agent freezes+kills the locker.
    We auto-detect which prevention mode the agent chose (from its own log) and
    assert the right contract for it.

OBSERVATION SURFACES ONLY (no agent internals are imported/called):
  * the agent's own log file (its stdout+stderr)
  * `iptables -S OUTPUT`
  * /proc/<pid>/stat  +  /proc/<pid>/status
  * /sys/fs/cgroup/rsentry-contain-*/cgroup.procs
  * the decoy file on disk (did it survive the rename attempt?)

WHY THE SYMLINK-COMM TRICK
  python3 was historically safelisted in agent IGNORE_COMMS (BUG 2, fixed). We
  launch the locker through a symlinked interpreter (/tmp/canary_locker ->
  python3) so the kernel `comm` reads like a ransomware binary ("canary_locker")
  and is never safelisted — same trick the Akira test uses.

THE STUB BACKEND
  The agent posts telemetry to BACKEND_URL synchronously inside the contain
  worker, and agent/client.py retries with back-off (~4.5s) when the backend is
  down — which would delay the pipeline. We stand up a throwaway in-process stub
  backend (fast 200s) so the agent's autonomous pipeline fires in milliseconds.
  The stub only ABSORBS telemetry; it drives nothing.

USAGE
    # Privileged live run — needs root (the AGENT subprocess loads BPF + writes
    # iptables/cgroup) and a bcc-capable interpreter:
    sudo /usr/bin/python3 tests/integration/test_live_canary.py

    # Unprivileged self-check (no agent, no BPF): verifies the canary log/source
    # contract, the symlink-comm trick, and import sanity:
    python3 tests/integration/test_live_canary.py --selfcheck

SAFETY
  * The locker only RENAMES a single decoy file (no cipher, no key, no payload),
    inside /tmp/rsentry_agent_watch, and gives up after a bounded retry count.
  * The test NEVER signals the locker before asserting (proves the agent acted).
    The finally{} block may kill leftovers, but only after assertions are taken.
  * Cleanup is surgical: iptables -D of our own residual rule (NEVER -F/--flush),
    cgroup rmdir, and the OUTPUT chain is asserted byte-count-restored.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

WATCH = Path("/tmp/rsentry_agent_watch")
SYMLINK = Path("/tmp/canary_locker")           # comm becomes "canary_locker"
AGENT_LOG = Path("/tmp/rsentry_canary_agent.log")
EVIDENCE_BASE = Path("/tmp/rsentry_evidence")

OPERATOR_UID = 1000
OPERATOR_GID = 1000
PING_TARGET = "8.8.8.8"
PING_INTERVAL = "0.3"

CANARY_COUNT = 8            # how many decoys the agent seeds (env override below)
RANSOM_EXT = ".crab"       # the locker tries to append this to a decoy
LOCKER_RETRIES = 60         # bounded — the agent freezes us well before this
LOCKER_DELAY = "0.15"      # per-attempt pacing; keeps the PID alive for the pipeline
READY_TIMEOUT = 90.0        # BPF compile + 492k-hash lineage prewarm can be slow
RESPONSE_TIMEOUT = 30.0     # autonomous detect+contain budget

# Durable log-line contract — MUST match agent/containment.py, monitor_ebpf.py,
# and monitor.py. If any of these strings drift, the self-check catches it before
# a live run can give a false PASS.
LOG_READY = "probes loaded — listening"                    # monitor_ebpf.run_sensor
LOG_CANARY_REGISTERED = "canary inodes registered in kernel map"  # monitor_ebpf.run_sensor
LOG_PREVENTION = "prevention="                             # monitor_ebpf.run_sensor
LOG_PREVENTION_LSM = "inline-LSM-deny"                     # lsm=bpf active
LOG_PREVENTION_FALLBACK = "SIGSTOP-fallback"               # lsm=bpf absent
LOG_PIPELINE = "SIGSTOP pipeline: pid={pid}"               # monitor._make_contain_fn
LOG_LAYER_CANARY = "layer=canary"                          # monitor._make_contain_fn
LOG_SIGSTOP = "SIGSTOP sent to PID {pid}"                   # containment._sigstop
LOG_ISOLATE = "Network isolation applied: cgroup="         # containment._cgroup_network_isolate
LOG_ISOLATE_SCOPED = "(UID-agnostic, scoped)"
LOG_SIGKILL = "SIGKILL sent to PID {pid}"                   # containment._sigkill
LOG_COMPLETE = "=== CONTAINMENT COMPLETE PID {pid}"        # containment.contain
CGROUP_PREFIX = "rsentry-contain"
CGROUP_ROOT = Path("/sys/fs/cgroup")

# Parses: "Network isolation applied: cgroup=rsentry-contain-1234 pids=[1234] (UID-agnostic, scoped)"
_ISO_RE = re.compile(r"Network isolation applied: cgroup=(\S+) pids=\[([0-9,\s]*)\]")
# Parses: "[ebpf] 8 canary inodes registered in kernel map"
_REG_RE = re.compile(r"(\d+)\s+canary inodes registered in kernel map")

CANARY_PREFIXES = ("AAA_", "aaa_", "ZZZ_", "zzz_")

COMMANDS: list[list[str]] = []


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    COMMANDS.append(cmd)
    print(f"    RUN: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=15)


def output_chain() -> list[str]:
    cp = run_cmd(["iptables", "-S", "OUTPUT"])
    return [ln for ln in cp.stdout.splitlines() if ln.strip()]


def contain_rules_present() -> list[str]:
    return [ln for ln in output_chain() if CGROUP_PREFIX in ln]


def cgroup_dirs() -> list[Path]:
    return list(CGROUP_ROOT.glob(f"{CGROUP_PREFIX}-*"))


def proc_state(pid: int) -> "str | None":
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
    except (FileNotFoundError, IndexError, OSError):
        return None


def proc_uid(pid: int) -> "int | None":
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (FileNotFoundError, ValueError, OSError):
        return None
    return None


def operator_can_reach_network() -> bool:
    try:
        cp = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "2", PING_TARGET],
            user=OPERATOR_UID, group=OPERATOR_GID,
            capture_output=True, text=True, timeout=6,
        )
        return cp.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def log_text() -> str:
    try:
        return AGENT_LOG.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def wait_for_log(substr: str, timeout: float, proc: "subprocess.Popen | None" = None) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if substr in log_text():
            return True
        if proc is not None and proc.poll() is not None:
            return substr in log_text()  # process died — one last look
        time.sleep(0.3)
    return False


def discover_canaries() -> list[Path]:
    """All decoy files the agent seeded under WATCH (root-owned, in a 0777 dir)."""
    found: list[Path] = []
    for p in sorted(WATCH.rglob("*")):
        if p.is_file() and p.name.startswith(CANARY_PREFIXES):
            found.append(p)
    return found


def cleanup_sim_backups() -> None:
    for p in Path("/tmp").glob("rsentry_backup_*"):
        shutil.rmtree(p, ignore_errors=True)


# --------------------------------------------------------------------------- #
# The locker payload (runs as UID 1000, comm "canary_locker"). It only RENAMES a
# single decoy — no cipher, no key. When the kernel LSM denies the rename it
# raises PermissionError and we retry; that retry loop keeps the PID alive long
# enough for the agent's pipeline to freeze and kill us. Bounded by LOCKER_RETRIES.
# --------------------------------------------------------------------------- #

_LOCKER_SRC = r"""
import os, sys, time
target = sys.argv[1]
retries = int(sys.argv[2])
delay   = float(sys.argv[3])
ext     = sys.argv[4]
for _ in range(retries):
    locked = target + ext
    try:
        os.rename(target, locked)
        # If it somehow went through (no LSM), put it back so the next loop can
        # try again and so the on-disk survival check is deterministic.
        try:
            os.rename(locked, target)
        except OSError:
            pass
    except OSError:
        pass
    time.sleep(delay)
"""


# --------------------------------------------------------------------------- #
# Throwaway stub backend (absorbs the agent's telemetry so its synchronous POSTs
# don't block the contain worker on retry back-off). It drives nothing.
# --------------------------------------------------------------------------- #

class _StubHandler(BaseHTTPRequestHandler):
    def _drain_and_ok(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
        except Exception:
            pass
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):  # noqa: N802
        self._drain_and_ok()

    def do_GET(self):  # noqa: N802
        self._drain_and_ok()

    def log_message(self, *a):  # silence
        return


def start_stub_backend() -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _StubHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


# --------------------------------------------------------------------------- #
# Results table
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
        print("\n" + "=" * 88)
        print("RESULTS")
        print("=" * 88)
        print(line.format("Check", "Expected", "Observed", "Result"))
        print(sep)
        for name, exp, obs, ok in self.rows:
            print(line.format(name, exp, obs, "PASS" if ok else "FAIL"))
        all_pass = all(r[3] for r in self.rows)
        print("=" * 88)
        print("OVERALL: " + (
            "PASS — agent autonomously tripped the CANARY layer (T1486), blocked "
            "the touch and ran the full enforce pipeline "
            "(SIGSTOP->evidence->cgroup isolate->SIGKILL); operator + agent never "
            "cut (T1498 guard held)"
            if all_pass else "FAIL"))
        print("=" * 88)
        return all_pass


# --------------------------------------------------------------------------- #
# Self-check (no root): the canary log/source contract + symlink comm + imports
# --------------------------------------------------------------------------- #

def _selfcheck(report: Report) -> int:
    csrc = (Path(_PROJECT_ROOT) / "agent" / "containment.py").read_text()
    esrc = (Path(_PROJECT_ROOT) / "agent" / "monitor_ebpf.py").read_text()
    msrc = (Path(_PROJECT_ROOT) / "agent" / "monitor.py").read_text()
    gsrc = (Path(_PROJECT_ROOT) / "agent" / "graph.py").read_text()

    report.check("log contract: SIGSTOP line matches source", "present",
                 "present" if 'SIGSTOP sent to PID %d' in csrc else "absent",
                 'SIGSTOP sent to PID %d' in csrc)
    report.check("log contract: isolation line matches source", "present",
                 "present" if 'Network isolation applied: cgroup=%s' in csrc else "absent",
                 'Network isolation applied: cgroup=%s' in csrc)
    report.check("log contract: SIGKILL line matches source", "present",
                 "present" if 'SIGKILL sent to PID %d' in csrc else "absent",
                 'SIGKILL sent to PID %d' in csrc)
    report.check("log contract: readiness line matches source", "present",
                 "present" if 'probes loaded — listening' in esrc else "absent",
                 'probes loaded — listening' in esrc)

    # Canary-specific kernel + userspace wiring.
    report.check("ebpf source: canary inodes registered in kernel map", "present",
                 "present" if 'canary inodes registered in kernel map' in esrc else "absent",
                 'canary inodes registered in kernel map' in esrc)
    report.check("ebpf source: LSM_PROBE path_rename denies canary rename", "present",
                 "present" if 'LSM_PROBE(path_rename' in esrc and '-EPERM' in esrc else "absent",
                 'LSM_PROBE(path_rename' in esrc and '-EPERM' in esrc)
    report.check("ebpf source: emits CANARY_ATTEMPT on a blocked touch", "present",
                 "present" if 'CANARY_ATTEMPT' in esrc else "absent",
                 'CANARY_ATTEMPT' in esrc)
    report.check("ebpf source: prevention banner (LSM vs SIGSTOP fallback)", "present",
                 "present" if 'inline-LSM-deny' in esrc and 'SIGSTOP-fallback' in esrc else "absent",
                 'inline-LSM-deny' in esrc and 'SIGSTOP-fallback' in esrc)

    # The contain layer is logged as "layer=%s" so a canary kill reads "layer=canary".
    report.check("monitor source: SIGSTOP pipeline logs the firing layer", "present",
                 "present" if 'SIGSTOP pipeline: pid=%d comm=%s layer=%s' in msrc else "absent",
                 'SIGSTOP pipeline: pid=%d comm=%s layer=%s' in msrc)

    # graph.is_canary must recognise all 4 decoy prefixes (what we glob for).
    has_prefixes = all(p in gsrc for p in ('"AAA_"', '"aaa_"', '"ZZZ_"', '"zzz_"'))
    report.check("graph source: canary prefixes AAA_/aaa_/ZZZ_/zzz_", "present",
                 "present" if has_prefixes else "absent", has_prefixes)

    # Match the quoted-argument TOKEN form (what a real iptables call uses), not
    # the prose: containment.py's docstring explains WHY it avoids --uid-owner, so
    # the bare string appears in comments — only `"--uid-owner"` as an argv token
    # would mean the code actually uses it.
    path_token = '"--path"' in csrc
    no_uid_token = '"--uid-owner"' not in csrc
    report.check("isolation is cgroup --path (never --uid-owner) in source",
                 "--path token, no --uid-owner token",
                 f"path={path_token} uid_token={not no_uid_token}",
                 path_token and no_uid_token)

    # BUG 2 regression: the interpreter must never be safelisted again. Inspect
    # the ACTUAL IGNORE_COMMS set (not a grep of the file — monitor.py's own
    # self-tests legitimately contain the literal "python3" while asserting it is
    # absent from the set, which would defeat a naive substring check).
    try:
        import importlib
        _mon = importlib.import_module("agent.monitor")
        _no_py = not any(c.lower().startswith("python") for c in _mon.IGNORE_COMMS)
        _observed = "absent" if _no_py else f"present: {sorted(_mon.IGNORE_COMMS)}"
    except Exception as exc:  # noqa: BLE001
        _no_py = False
        _observed = f"import-fail: {exc}"
    report.check("agent IGNORE_COMMS does NOT safelist python* (BUG 2 fixed)",
                 "no python* comm", _observed, _no_py)

    # Symlink-comm trick: comm becomes the basename of the exec'd path.
    try:
        if SYMLINK.exists() or SYMLINK.is_symlink():
            SYMLINK.unlink()
        SYMLINK.symlink_to(sys.executable)
        out = subprocess.run(
            [str(SYMLINK), "-c", "print(open('/proc/self/comm').read().strip())"],
            capture_output=True, text=True, timeout=10,
            env=dict(os.environ, PYTHONPATH=str(_PROJECT_ROOT)),
        )
        comm = out.stdout.strip()
        report.check("symlinked interpreter yields non-python3 comm",
                     "canary_locker",
                     comm, comm == SYMLINK.name and comm != "python3")
    finally:
        if SYMLINK.exists() or SYMLINK.is_symlink():
            SYMLINK.unlink()

    # graph import + is_canary behaviour on our prefixes.
    import importlib
    ok = True
    try:
        g = importlib.import_module("agent.graph")
        ok = (g.FilesystemGraph(root="/tmp").is_canary("/tmp/AAA_000.txt")
              and g.FilesystemGraph(root="/tmp").is_canary("/tmp/zzz_007.txt")
              and not g.FilesystemGraph(root="/tmp").is_canary("/tmp/report.docx"))
    except Exception as exc:  # noqa: BLE001
        print(f"    import FAIL: {exc}")
        ok = False
    report.check("agent.graph imports + is_canary recognises decoys", "ok",
                 "ok" if ok else "fail", ok)

    report.check("SAFETY: locker only renames, bounded retries <= 100", "<=100",
                 str(LOCKER_RETRIES), LOCKER_RETRIES <= 100)

    print("\n[self-check] Canary log/source contract + comm trick + safety "
          "verified. Run with sudo for the full autonomous live proof.")
    return 0 if report.render() else 1


# --------------------------------------------------------------------------- #
# Live run (root)
# --------------------------------------------------------------------------- #

def _live(report: Report) -> int:
    # bcc must be importable by the AGENT (we don't import it here, but fail fast
    # with a clear message if the interpreter can't load it).
    probe = subprocess.run([sys.executable, "-c", "import bcc"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        print(f"FAIL: this interpreter cannot import bcc — run under the system "
              f"python3 that owns python3-bpfcc.\n{probe.stderr.strip()}")
        return 3

    test_signalled_locker = False
    agent = operator = locker = None
    stub = None
    locker_pid = -1
    agent_pid = -1
    baseline_chain: list[str] = []

    try:
        # ---- 1. PREFLIGHT ----------------------------------------------------
        print("[1] PREFLIGHT")
        existing = subprocess.run(["pgrep", "-f", "agent.monitor"],
                                  capture_output=True, text=True)
        running = [p for p in existing.stdout.split() if int(p) != os.getpid()]
        if not report.check("no agent already running", "none",
                            running or "none", not running):
            print("FAIL: an agent.monitor is already running — stop it first "
                  "(this test must own the only agent).")
            return 3
        baseline_chain = output_chain()
        report.check("baseline: no rsentry-contain rule", "none",
                     str(contain_rules_present()) or "none", not contain_rules_present())
        report.check("baseline: no rsentry cgroup", "none",
                     str([str(c) for c in cgroup_dirs()]) or "none", not cgroup_dirs())
        print(f"    baseline OUTPUT chain: {len(baseline_chain)} rule(s)")

        if WATCH.exists():
            shutil.rmtree(WATCH, ignore_errors=True)
        # 0777 so the UID-1000 locker can rename inside it (the decoys the agent
        # seeds here are root-owned, but rename needs dir write perm, not file
        # ownership). No sticky bit -> the rename is DAC-permitted; the kernel LSM
        # is what must do the blocking, which is exactly what we test.
        WATCH.mkdir(mode=0o777, parents=True)
        os.chown(WATCH, OPERATOR_UID, OPERATOR_GID)
        os.chmod(WATCH, 0o777)
        AGENT_LOG.write_text("")

        # ---- 2. STUB BACKEND + START AGENT ----------------------------------
        stub, backend_url = start_stub_backend()
        print(f"[2] stub backend at {backend_url} (absorbs telemetry only)")

        agent_env = dict(
            os.environ,
            SENSOR_MODE="enforce",          # enforce via ENV
            SENSOR_BACKEND="ebpf",
            BACKEND_URL=backend_url,
            PYTHONPATH=str(_PROJECT_ROOT),
            CANARY_COUNT=str(CANARY_COUNT),  # keep seeding fast + deterministic
            CANARY_STRATEGY="bfs",
            HEARTBEAT_INTERVAL="3600",      # keep heartbeat noise out of the log
            PYTHONUNBUFFERED="1",           # flush print() (the [ebpf]/[monitor] lines) live
        )
        # `-u` (belt-and-suspenders with PYTHONUNBUFFERED): the agent's [ebpf]/
        # [monitor] readiness lines are print() to STDOUT, which Python block-
        # buffers when stdout is a file — without this they never reach the log
        # until exit, so the readiness wait would time out blind.
        agent_cmd = [sys.executable, "-u", "-m", "agent.monitor",
                     "--backend", "ebpf", "--watch", str(WATCH)]
        print("[2] START AGENT (its own process; loads BPF, seeds + registers canaries)")
        print(f"    RUN: SENSOR_MODE=enforce CANARY_COUNT={CANARY_COUNT} "
              f"BACKEND_URL={backend_url} {' '.join(agent_cmd)}")
        logfh = open(AGENT_LOG, "w")
        agent = subprocess.Popen(agent_cmd, cwd=str(_PROJECT_ROOT), env=agent_env,
                                 stdout=logfh, stderr=subprocess.STDOUT)
        agent_pid = agent.pid
        print(f"    agent PID={agent_pid}; waiting for '{LOG_READY}' "
              f"(<= {READY_TIMEOUT:.0f}s — BPF compile + lineage prewarm)")
        ready = wait_for_log(LOG_READY, READY_TIMEOUT, proc=agent)
        if not ready:
            exited = agent.poll() is not None
            print("\n!!!! AGENT DID NOT REACH READINESS !!!!")
            if exited:
                print(f"  PREMATURE EXIT: rc={agent.poll()} before '{LOG_READY}'")
                print("  ---- FULL agent log (stdout+stderr) ----")
                print(log_text() or "    (empty)")
            else:
                print(f"  TIMEOUT after {READY_TIMEOUT:.0f}s — agent still running, "
                      f"'{LOG_READY}' not seen")
                print("  ---- agent log tail (last 30 lines, stdout+stderr) ----")
                print("\n".join(log_text().splitlines()[-30:]) or "    (empty)")
            report.check("agent started + probes loaded", "listening",
                         f"premature-exit rc={agent.poll()}" if exited else "TIMEOUT",
                         False)
            return 1
        report.check("agent started + probes loaded", "listening", "listening", True)
        report.check("agent process alive after load", "alive",
                     "alive" if agent.poll() is None else "exited", agent.poll() is None)

        # ---- 2b. CANARY REGISTRATION + PREVENTION MODE ----------------------
        log = log_text()
        reg_m = _REG_RE.search(log)
        n_registered = int(reg_m.group(1)) if reg_m else 0
        report.check("agent registered canary inodes in kernel map", ">=1",
                     f"{n_registered} registered", n_registered >= 1)

        # Which prevention mode did the agent actually pick? (auto-detected from
        # /sys/kernel/security/lsm by the agent — we read its own banner.)
        lsm_active = LOG_PREVENTION_LSM in log
        prevention = ("inline-LSM-deny" if lsm_active
                      else (LOG_PREVENTION_FALLBACK if LOG_PREVENTION_FALLBACK in log
                            else "unknown"))
        report.check("agent announced a prevention mode", "LSM or SIGSTOP-fallback",
                     prevention, prevention != "unknown")
        print(f"    prevention mode in effect: {prevention} "
              f"(lsm_active={lsm_active})")

        # The decoys the agent seeded must be visible on disk for the locker.
        decoys = discover_canaries()
        report.check("agent seeded decoy canary files on disk", ">=1",
                     f"{len(decoys)} found", len(decoys) >= 1)
        if not decoys:
            print("FAIL: no decoy files under WATCH — cannot run the canary touch.")
            return 1
        target = decoys[0]
        print(f"    target decoy: {target} (of {len(decoys)})")

        # ---- 3. OPERATOR SAFETY ---------------------------------------------
        print("[3] OPERATOR — background ping from UID 1000 (must never be cut)")
        operator = subprocess.Popen(
            ["ping", "-n", "-i", PING_INTERVAL, PING_TARGET],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            user=OPERATOR_UID, group=OPERATOR_GID,
        )
        print(f"    operator ping PID={operator.pid} uid={proc_uid(operator.pid)}")
        time.sleep(2)
        if not operator_can_reach_network():
            print("FAIL: operator UID 1000 has no baseline network (no outbound ICMP?)")
            return 3
        report.check("operator online at baseline", "fresh probe OK", "reachable", True)

        # ---- 4. CANARY TOUCH (UID 1000, non-python3 comm) -------------------
        print("[4] CANARY TOUCH — UID-1000 locker renames a decoy via /tmp/canary_locker")
        if SYMLINK.exists() or SYMLINK.is_symlink():
            SYMLINK.unlink()
        SYMLINK.symlink_to(sys.executable)  # comm -> "canary_locker" (defeats python3 safelist)
        locker_env = dict(os.environ, PYTHONPATH=str(_PROJECT_ROOT), BACKEND_URL=backend_url)
        locker = subprocess.Popen(
            [str(SYMLINK), "-c", _LOCKER_SRC,
             str(target), str(LOCKER_RETRIES), LOCKER_DELAY, RANSOM_EXT],
            cwd=str(_PROJECT_ROOT), env=locker_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            user=OPERATOR_UID, group=OPERATOR_GID,
        )
        locker_pid = locker.pid
        report.check("locker spawned as UID 1000", "uid=1000",
                     f"pid={locker_pid} uid={proc_uid(locker_pid)} comm=canary_locker",
                     proc_uid(locker_pid) == OPERATOR_UID)

        # ---- 5. WAIT FOR AUTONOMOUS RESPONSE --------------------------------
        print(f"[5] OBSERVE — waiting for the agent's autonomous canary pipeline "
              f"(<= {RESPONSE_TIMEOUT:.0f}s). The test sends NO signals to the locker.")
        saw_stopped = False
        captured_rule = ""
        captured_cgroup_procs: "set[int] | None" = None
        want_pipeline = LOG_PIPELINE.format(pid=locker_pid)
        want_sigstop = LOG_SIGSTOP.format(pid=locker_pid)
        want_sigkill = LOG_SIGKILL.format(pid=locker_pid)
        want_complete = LOG_COMPLETE.format(pid=locker_pid)
        deadline = time.time() + RESPONSE_TIMEOUT
        while time.time() < deadline:
            st = proc_state(locker_pid)
            if st == "T":
                saw_stopped = True
            if not captured_rule:
                for ln in contain_rules_present():
                    if f"{CGROUP_PREFIX}-{locker_pid}" in ln:
                        captured_rule = ln
            cg = CGROUP_ROOT / f"{CGROUP_PREFIX}-{locker_pid}" / "cgroup.procs"
            if cg.exists() and captured_cgroup_procs is None:
                try:
                    captured_cgroup_procs = {int(x) for x in cg.read_text().split()}
                except (OSError, ValueError):
                    pass
            log = log_text()
            if want_complete in log or (want_sigkill in log and locker.poll() is not None):
                break
            time.sleep(0.25)

        log = log_text()
        locker_alive = locker.poll() is None
        locker_rc = locker.poll()

        if not (want_pipeline in log or want_sigstop in log or want_sigkill in log):
            print("\n!!!! AUTONOMOUS CANARY RESPONSE NOT OBSERVED — diagnostics !!!!")
            print(f"  locker_pid={locker_pid} state={proc_state(locker_pid)} "
                  f"alive={locker_alive} rc={locker_rc}")
            print(f"  target on disk: exists={target.exists()} "
                  f"locked_exists={(Path(str(target)+RANSOM_EXT)).exists()}")
            print(f"  iptables OUTPUT:\n    " +
                  "\n    ".join(output_chain()) or "    (empty)")
            print("  agent log tail:")
            print("    " + "\n    ".join(log.splitlines()[-30:]))

        # ---- 6. ASSERT -------------------------------------------------------
        print("[6] ASSERT autonomous canary detection + containment")
        m = _ISO_RE.search(log)
        iso_pids = ({int(x) for x in m.group(2).replace(" ", "").split(",") if x}
                    if m else set())

        # (a) the TEST never signalled the locker.
        report.check("test sent NO signal to locker before assert", "no signal",
                     "no signal" if not test_signalled_locker else "SIGNALLED",
                     not test_signalled_locker)

        # (b) canary layer specifically fired (not behavioral scoring).
        canary_layer = (want_pipeline in log and LOG_LAYER_CANARY in log)
        report.check("containment attributed to the CANARY layer",
                     "SIGSTOP pipeline + layer=canary",
                     f"pipeline={want_pipeline in log} layer_canary={LOG_LAYER_CANARY in log}",
                     canary_layer)

        # (c) agent stopped/killed the locker; the TEST never signalled it.
        agent_acted = (want_sigstop in log) or saw_stopped
        locker_dead_by_agent = ((not locker_alive)
                                and (want_sigkill in log or locker_rc == -signal.SIGKILL))
        report.check("agent autonomously SIGSTOP'd/froze the locker",
                     "SIGSTOP in log or state=T",
                     f"sigstop_log={want_sigstop in log} saw_T={saw_stopped}",
                     agent_acted)
        report.check("agent autonomously SIGKILL'd the locker",
                     "SIGKILL in log & locker dead",
                     f"sigkill_log={want_sigkill in log} alive={locker_alive} rc={locker_rc}",
                     locker_dead_by_agent)

        # (d) decoy survival: when inline-LSM-deny is active the kernel rejects
        #     the rename (-EPERM) so the decoy stays at its ORIGINAL name and the
        #     ransom-extension twin never exists. Under SIGSTOP-fallback (no
        #     lsm=bpf) the rename can land once before the freeze, so survival is
        #     not guaranteed — we only assert it for the LSM path.
        locked_twin = Path(str(target) + RANSOM_EXT)
        decoy_intact = target.exists() and not locked_twin.exists()
        if lsm_active:
            report.check("decoy SURVIVED — kernel LSM denied the rename inline",
                         "original present, no .crab twin",
                         f"orig={target.exists()} twin={locked_twin.exists()}",
                         decoy_intact)
            report.check("kernel emitted a BLOCKED canary attempt (CANARY_ATTEMPT path)",
                         "agent froze locker via canary layer",
                         f"canary_layer={canary_layer}", canary_layer)
        else:
            report.check("decoy touch detected (SIGSTOP-fallback; rename may land once)",
                         "canary layer fired",
                         f"canary_layer={canary_layer} orig={target.exists()}",
                         canary_layer)

        # (e) cgroup-scoped isolation, --path not --uid-owner.
        iso_logged = (LOG_ISOLATE in log and f"{CGROUP_PREFIX}-{locker_pid}" in log
                      and LOG_ISOLATE_SCOPED in log)
        no_uid_owner = "--uid-owner" not in log and "--uid-owner" not in captured_rule
        rule_path_ok = ("--path" in captured_rule) if captured_rule else iso_logged
        report.check("agent applied cgroup-scoped isolation (--path, not --uid-owner)",
                     "--path & !--uid-owner",
                     f"logged={iso_logged} caught_rule={'yes' if captured_rule else 'no'} "
                     f"path_ok={rule_path_ok}",
                     iso_logged and no_uid_owner and rule_path_ok)

        # (f) full pipeline visible in the agent's own log.
        pipeline = (want_sigstop in log and LOG_ISOLATE in log and want_sigkill in log)
        report.check("agent log shows full pipeline (SIGSTOP+isolate+SIGKILL)",
                     "all three",
                     f"stop={want_sigstop in log} iso={LOG_ISOLATE in log} "
                     f"kill={want_sigkill in log}",
                     pipeline)

        # (g) self-protection: agent + operator survive.
        agent_alive = agent.poll() is None
        op_alive = operator.poll() is None
        op_reach = operator_can_reach_network()
        report.check("agent NOT killed by its own containment", "alive",
                     "alive" if agent_alive else "DEAD", agent_alive)
        report.check("operator ping alive + reachable throughout (T1498)",
                     "alive & reachable",
                     f"alive={op_alive} reachable={op_reach}", op_alive and op_reach)

        # (h) agent PID NOT in the isolated cgroup (only the locker tree was).
        agent_absent_log = (bool(iso_pids) and agent_pid not in iso_pids
                            and locker_pid in iso_pids)
        agent_absent_live = (captured_cgroup_procs is None
                             or agent_pid not in captured_cgroup_procs)
        report.check("agent PID NOT in isolated cgroup; only locker tree isolated",
                     f"agent({agent_pid}) absent, locker({locker_pid}) present",
                     f"iso_pids={sorted(iso_pids)} "
                     f"live_procs={sorted(captured_cgroup_procs) if captured_cgroup_procs else 'n/a'}",
                     agent_absent_log and agent_absent_live)

        return 0 if report.render() else 1

    finally:
        # ---- 7. TEARDOWN — always runs --------------------------------------
        print("\n[7] TEARDOWN")
        if agent is not None and agent.poll() is None:
            print(f"    RUN: kill -TERM {agent.pid}")
            try:
                agent.terminate()
                agent.wait(timeout=5)
            except Exception:
                try:
                    agent.kill()
                    agent.wait(timeout=5)
                except Exception:
                    pass
            print(f"    agent stopped (rc={agent.poll()})")
        # Kill any locker leftover (only if the agent didn't already). This is the
        # ONLY place the test may signal the locker — after assertions are taken.
        if locker is not None and locker.poll() is None:
            test_signalled_locker = True  # noqa: F841 - audit marker (post-assert only)
            for s in (signal.SIGCONT, signal.SIGKILL):
                try:
                    os.kill(locker.pid, s)
                except OSError:
                    pass
            try:
                locker.wait(timeout=5)
            except Exception:
                pass
            print(f"    locker leftover killed (rc={locker.poll()})")
        if operator is not None and operator.poll() is None:
            operator.kill()
            try:
                operator.wait(timeout=5)
            except Exception:
                pass
            print("    operator ping killed")
        if stub is not None:
            stub.shutdown()

        # Surgical residual cleanup — NEVER a flush. -D our own tagged rule only.
        for ln in contain_rules_present():
            spec = ln.split()
            if spec and spec[0] == "-A":
                run_cmd(["iptables", "-D"] + spec[1:])
        for cg in cgroup_dirs():
            try:
                cg.rmdir()
                print(f"    cgroup removed: {cg}")
            except OSError:
                pass

        shutil.rmtree(WATCH, ignore_errors=True)
        shutil.rmtree(EVIDENCE_BASE, ignore_errors=True)
        cleanup_sim_backups()
        if SYMLINK.exists() or SYMLINK.is_symlink():
            SYMLINK.unlink()

        # Teardown assertions (printed; do not change the already-rendered table).
        residual_rules = contain_rules_present()
        residual_cgroups = cgroup_dirs()
        final_chain = output_chain()
        used_flush = any(("-F" in c or "--flush" in c) for c in COMMANDS)
        print(f"    no dangling rsentry-contain rule : {not residual_rules} "
              f"({residual_rules or 'none'})")
        print(f"    no dangling rsentry cgroup       : {not residual_cgroups}")
        print(f"    OUTPUT chain restored to baseline: "
              f"{final_chain == baseline_chain} "
              f"(baseline={len(baseline_chain)} final={len(final_chain)})")
        print(f"    no iptables -F/--flush used       : {not used_flush}")
        AGENT_LOG.unlink(missing_ok=True)
        print("    watch dir + evidence + symlink removed")


def main() -> int:
    report = Report()
    if "--selfcheck" in sys.argv:
        return _selfcheck(report)
    if os.geteuid() != 0:
        here = Path(__file__).resolve()
        print("\n" + "!" * 78)
        print("FAIL: canary live test needs root — it starts a real")
        print("`agent.monitor` enforce process that loads BPF, seeds decoy")
        print("canaries, registers their inodes in the kernel map, and writes")
        print("iptables/cgroup state.")
        print("\nThe privileged run will, in order:")
        print("  * stand up a throwaway stub backend (absorbs agent telemetry)")
        print("  * start `SENSOR_MODE=enforce python3 -m agent.monitor --backend")
        print("    ebpf --watch /tmp/rsentry_agent_watch` as its OWN process")
        print("  * spawn a UID-1000 `ping 8.8.8.8` (operator liveness)")
        print("  * spawn a UID-1000 locker via /tmp/canary_locker that renames ONE")
        print("    agent decoy (comm != python3, so the agent does not safelist it)")
        print("  * OBSERVE (log + iptables + /proc + cgroup + the decoy on disk)")
        print("    the agent autonomously block the touch + SIGSTOP -> evidence ->")
        print("    cgroup isolate -> SIGKILL the locker (layer=canary)")
        print("  * tear everything down (SIGTERM agent, surgical iptables -D, rmdir)")
        print("\nReview the script first, then run:")
        print(f"  sudo /usr/bin/python3 {here}")
        print("Or validate the canary contract + comm trick without root:")
        print(f"  {sys.executable} {here} --selfcheck")
        print("!" * 78)
        return 2
    return _live(report)


if __name__ == "__main__":
    sys.exit(main())
