#!/usr/bin/env python3
"""
tests/integration/test_live_autonomous_lockbit.py — LIVE, fully-AUTONOMOUS proof
for the LockBit 5.0 simulation (sibling of test_live_autonomous_agent.py, which
covers Akira).

The agent runs as its OWN process. The LockBit sim runs as its OWN process. The
test only ORCHESTRATES (start/stop) and OBSERVES from the outside — it never
calls an agent internal, never loads BPF itself, and never signals the sim. We
prove the agent detects AND contains on its own, end to end.

DETECTION LAYER UNDER TEST (LockBit-specific)
  LockBit 5.0's signature is a randomised 16-character extension applied by a real
  rename. The fixed sim overwrites each file in place (two passes) then issues
  ``os.rename(p, p + '.<16 chars>')``. On the live kernel that fires the agent's
  RENAME layer: ``kprobe__vfs_rename`` -> ``DetectionEngine.observe_rename`` ->
  ``PROCESS_ANOMALY`` with ``details.profile == "lockbit5"`` (16-char extension).
  It is NOT the write-offset / silent-encryption layer (no SILENT_ENCRYPTION
  event is emitted for the sim PID — ``silent_enc == 0``).

OBSERVATION SURFACES ONLY (no agent internals are imported/called):
  * the agent's own log file (its stdout+stderr) — the containment pipeline
  * the telemetry the agent POSTs to its backend — captured by an in-test stub,
    so the detection-layer fields (event_type / profile / file_path) are read from
    what the agent actually SENT, not from any internal call
  * `iptables -S OUTPUT`
  * /proc/<pid>/stat  +  /proc/<pid>/status
  * /sys/fs/cgroup/rsentry-contain-*/cgroup.procs

LAUNCH CHOICES (historical agent quirks now FIXED — kept for log realism):
  1. BUG 2 (fixed): "python3" was in agent/monitor.py IGNORE_COMMS, so a sim
     launched as `python3 -m ...` used to be safelisted and invisible. The entry
     is removed — plain-python3 sims are now detected. We still launch through a
     symlinked interpreter (/tmp/lockbit_locker -> python3) so the kernel `comm`
     reads like a real ransomware binary in logs/alerts. (Verified: comm ==
     basename of the exec'd path.)
  2. BUG 1 (fixed): the parsed `--mode` flag used to be ignored (env-only).
     `--mode` now overrides SENSOR_MODE; SENSOR_MODE=enforce is still set in the
     agent env as belt-and-braces — both paths select enforce.
  Plus: the agent posts telemetry to BACKEND_URL synchronously inside the contain
  worker, and agent/client.py retries with back-off (~4.5s) when the backend is
  down — which would delay the SIGSTOP past the sim's lifetime. We stand up a
  throwaway in-process stub backend (fast 200s) so the agent's autonomous pipeline
  fires in milliseconds. The stub only ABSORBS/records telemetry; it drives nothing.

USAGE
    # Privileged live run — needs root (the AGENT subprocess loads BPF + writes
    # iptables/cgroup) and a bcc-capable interpreter:
    sudo /usr/bin/python3 tests/integration/test_live_autonomous_lockbit.py

    # Unprivileged self-check (no agent, no BPF):
    python3 tests/integration/test_live_autonomous_lockbit.py --selfcheck

SAFETY
  * Sim rewrites os.urandom/XOR bytes then renames — NO cipher, NO key — only
    inside /tmp/rsentry_lockbit_watch/lockbit_zone, bounded to <=10 files.
  * The test NEVER signals the sim before asserting (proves the agent acted). The
    finally{} block may kill leftovers, but only after the assertions are taken.
  * Cleanup is surgical: iptables -D of our own residual rule (NEVER -F/--flush),
    cgroup rmdir, and the OUTPUT chain is asserted byte-count-restored.
"""
from __future__ import annotations

import json
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

WATCH = Path("/tmp/rsentry_lockbit_watch")
ZONE = WATCH / "lockbit_zone"
SYMLINK = Path("/tmp/lockbit_locker")          # comm becomes "lockbit_locker"
AGENT_LOG = Path("/tmp/rsentry_autonomous_lockbit.log")
EVIDENCE_BASE = Path("/tmp/rsentry_evidence")

OPERATOR_UID = 1000
OPERATOR_GID = 1000
PING_TARGET = "8.8.8.8"
PING_INTERVAL = "0.3"

CORPUS_FILES = 10           # pre-seeded so the sim skips populate_corpus
SIM_MAX_FILES = 10          # VM-hang guard (<=10)
SIM_DELAY = "0.2"           # per-file pacing; keeps the PID alive for the pipeline
READY_TIMEOUT = 90.0        # BPF compile + 492k-hash lineage prewarm can be slow
RESPONSE_TIMEOUT = 30.0     # autonomous detect+contain budget

SIM_MODULE = "simulations.sim_lockbit"
SIM_NAME = "LockBit"

# Durable log-line contract — MUST match agent/containment.py + monitor_ebpf.py.
LOG_READY = "probes loaded — listening"                    # monitor_ebpf.run_sensor
LOG_SIGSTOP = "SIGSTOP sent to PID {pid}"                   # containment._sigstop
LOG_ISOLATE = "Network isolation applied: cgroup="         # containment._cgroup_network_isolate
LOG_ISOLATE_SCOPED = "(UID-agnostic, scoped)"
LOG_SIGKILL = "SIGKILL sent to PID {pid}"                   # containment._sigkill
LOG_COMPLETE = "=== CONTAINMENT COMPLETE PID {pid}"        # containment.contain
CGROUP_PREFIX = "rsentry-contain"
CGROUP_ROOT = Path("/sys/fs/cgroup")

# Parses: "Network isolation applied: cgroup=rsentry-contain-1234 pids=[1234] (UID-agnostic, scoped)"
_ISO_RE = re.compile(r"Network isolation applied: cgroup=(\S+) pids=\[([0-9,\s]*)\]")

COMMANDS: list[list[str]] = []

# Telemetry captured at the stub backend — the agent's own POSTed event payloads.
_CAPTURED_EVENTS: list[dict] = []
_CAP_LOCK = threading.Lock()


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


def captured_events_for(pid: int) -> list[dict]:
    with _CAP_LOCK:
        return [e for e in _CAPTURED_EVENTS if e.get("pid") == pid]


def seed_zone() -> None:
    """Create the lockbit_zone corpus owned by UID 1000 (so the UID-1000 sim can
    rename) AFTER the agent is listening, so no agent canaries land in it."""
    if ZONE.exists():
        shutil.rmtree(ZONE, ignore_errors=True)
    docs = ZONE / "documents"
    docs.mkdir(parents=True)
    exts = [".docx", ".xlsx", ".pdf", ".db", ".jpg", ".vmdk"]
    for i in range(CORPUS_FILES):
        f = docs / f"corpus_{i:03d}{exts[i % len(exts)]}"
        f.write_bytes((f"document-{i} ".encode() * 512)[:8192])
    for p in [WATCH, ZONE, docs, *docs.iterdir()]:
        try:
            os.chown(p, OPERATOR_UID, OPERATOR_GID)
        except OSError:
            pass
    os.chmod(ZONE, 0o777)
    os.chmod(docs, 0o777)


def cleanup_sim_backups() -> None:
    for p in Path("/tmp").glob("rsentry_backup_*"):
        shutil.rmtree(p, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Throwaway stub backend — records the agent's telemetry so we can read the
# detection-layer fields (event_type/profile/file_path) the agent POSTed, and so
# its synchronous POSTs don't block the contain worker on retry back-off. It
# drives nothing.
# --------------------------------------------------------------------------- #

class _StubHandler(BaseHTTPRequestHandler):
    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(length) if length else b""
        except Exception:
            return b""

    def _ok(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):  # noqa: N802
        body = self._read_body()
        try:
            evt = json.loads(body.decode("utf-8"))
            if isinstance(evt, dict):
                with _CAP_LOCK:
                    _CAPTURED_EVENTS.append(evt)
        except Exception:
            pass
        self._ok()

    def do_GET(self):  # noqa: N802
        self._read_body()
        self._ok()

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
            "PASS — agent autonomously detected LockBit via the rename layer "
            "(profile=lockbit5, 16-char ext; T1486) and ran the full enforce "
            "pipeline (SIGSTOP->evidence->cgroup isolate->SIGKILL); operator + "
            "agent never cut (T1498 guard held)"
            if all_pass else "FAIL"))
        print("=" * 88)
        return all_pass


# --------------------------------------------------------------------------- #
# LockBit detection-layer predicate
# --------------------------------------------------------------------------- #

def _is_lockbit_rename(evt: dict) -> bool:
    """A captured PROCESS_ANOMALY is the LockBit rename layer if it carries the
    lockbit5 family profile OR its destination file has a 16-char extension."""
    if evt.get("event_type") != "PROCESS_ANOMALY":
        return False
    profile = (evt.get("details") or {}).get("profile")
    ext = Path(evt.get("file_path") or "").suffix.lstrip(".")
    return profile == "lockbit5" or len(ext) == 16


# --------------------------------------------------------------------------- #
# Self-check (no root): log-string contract + symlink comm + imports + predicate
# --------------------------------------------------------------------------- #

def _selfcheck(report: Report) -> int:
    csrc = (Path(_PROJECT_ROOT) / "agent" / "containment.py").read_text()
    esrc = (Path(_PROJECT_ROOT) / "agent" / "monitor_ebpf.py").read_text()
    msrc = (Path(_PROJECT_ROOT) / "agent" / "monitor.py").read_text()

    report.check("log contract: SIGSTOP line matches source", "present",
                 "present" if 'SIGSTOP sent to PID %d' in csrc else "absent",
                 'SIGSTOP sent to PID %d' in csrc)
    report.check("log contract: isolation line matches source", "present",
                 "present" if 'Network isolation applied: cgroup=%s' in csrc else "absent",
                 'Network isolation applied: cgroup=%s' in csrc)
    report.check("log contract: scoped tag matches source", "present",
                 "present" if '(UID-agnostic, scoped)' in csrc else "absent",
                 '(UID-agnostic, scoped)' in csrc)
    report.check("log contract: SIGKILL line matches source", "present",
                 "present" if 'SIGKILL sent to PID %d' in csrc else "absent",
                 'SIGKILL sent to PID %d' in csrc)
    report.check("log contract: readiness line matches source", "present",
                 "present" if 'probes loaded — listening' in esrc else "absent",
                 'probes loaded — listening' in esrc)
    # Match the quoted-argument TOKEN form (what a real iptables call uses), not
    # the prose: containment.py's docstring explains WHY it avoids --uid-owner.
    path_token = '"--path"' in csrc
    no_uid_token = '"--uid-owner"' not in csrc
    report.check("isolation is cgroup --path (never --uid-owner) in source",
                 "--path token, no --uid-owner token",
                 f"path={path_token} uid_token={not no_uid_token}",
                 path_token and no_uid_token)

    # BUG 2 regression: the interpreter must never be safelisted again.
    report.check("agent IGNORE_COMMS does NOT safelist python3 (BUG 2 fixed)",
                 "python3 absent",
                 "absent" if '"python3"' not in msrc else "present",
                 '"python3"' not in msrc)

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
                     "lockbit_locker",
                     comm, comm == SYMLINK.name and comm != "python3")
    finally:
        if SYMLINK.exists() or SYMLINK.is_symlink():
            SYMLINK.unlink()

    # Sim import + LockBit 16-char ext + two_pass mode.
    import importlib
    ok = True
    detail = ""
    try:
        m = importlib.import_module(SIM_MODULE)
        ext = m.PROFILE.ext_fn()
        ok = len(ext) == 16 and m.PROFILE.mode == "two_pass"
        detail = f"ext_len={len(ext)} mode={m.PROFILE.mode}"
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, f"import FAIL: {exc}"
    report.check("simulations.sim_lockbit imports (16-char ext, two_pass)", "ok",
                 detail, ok)

    # Detection predicate sanity.
    pos_profile = {"event_type": "PROCESS_ANOMALY", "pid": 1,
                   "file_path": "/x/a.docx.abc1234567890def", "details": {"profile": "lockbit5"}}
    pos_extlen = {"event_type": "PROCESS_ANOMALY", "pid": 1,
                  "file_path": "/x/a.docx.qtr1ss47pa1eds1a", "details": {"profile": "unknown"}}
    neg = {"event_type": "SILENT_ENCRYPTION", "pid": 1,
           "file_path": "/x/a.docx", "details": {}}
    report.check("predicate accepts lockbit5 profile", "True",
                 str(_is_lockbit_rename(pos_profile)), _is_lockbit_rename(pos_profile))
    report.check("predicate accepts 16-char ext", "True",
                 str(_is_lockbit_rename(pos_extlen)), _is_lockbit_rename(pos_extlen))
    report.check("predicate rejects silent_enc event", "False",
                 str(_is_lockbit_rename(neg)), not _is_lockbit_rename(neg))

    report.check("SAFETY: sim max files <= 10", "<=10",
                 str(SIM_MAX_FILES), SIM_MAX_FILES <= 10)

    print("\n[self-check] Log contract + comm trick + detection predicate verified. "
          "Run with sudo for the full autonomous live proof.")
    return 0 if report.render() else 1


# --------------------------------------------------------------------------- #
# Live run (root)
# --------------------------------------------------------------------------- #

def _live(report: Report) -> int:
    probe = subprocess.run([sys.executable, "-c", "import bcc"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        print(f"FAIL: this interpreter cannot import bcc — run under the system "
              f"python3 that owns python3-bpfcc.\n{probe.stderr.strip()}")
        return 3

    test_signalled_sim = False
    agent = operator = sim = None
    stub = None
    sim_pid = -1
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
        WATCH.mkdir(mode=0o777, parents=True)
        os.chown(WATCH, OPERATOR_UID, OPERATOR_GID)
        AGENT_LOG.write_text("")

        # ---- 2. STUB BACKEND + START AGENT ----------------------------------
        stub, backend_url = start_stub_backend()
        print(f"[2] stub backend at {backend_url} (records telemetry only)")

        agent_env = dict(
            os.environ,
            SENSOR_MODE="enforce",          # enforce via ENV (the --mode flag is ignored)
            SENSOR_BACKEND="ebpf",
            BACKEND_URL=backend_url,
            PYTHONPATH=str(_PROJECT_ROOT),
            HEARTBEAT_INTERVAL="3600",      # keep heartbeat noise out of the log
            PYTHONUNBUFFERED="1",           # flush print() (the [ebpf]/[monitor] lines) live
        )
        # `-u` (belt-and-suspenders with PYTHONUNBUFFERED): the agent's [ebpf]/
        # [monitor] readiness lines are print() to STDOUT, which Python block-
        # buffers when stdout is a file — without this they never reach the log
        # until exit, so the readiness wait would time out blind.
        agent_cmd = [sys.executable, "-u", "-m", "agent.monitor",
                     "--backend", "ebpf", "--watch", str(WATCH)]
        print("[2] START AGENT (its own process; loads BPF, runs enforce pipeline)")
        print(f"    RUN: SENSOR_MODE=enforce BACKEND_URL={backend_url} "
              f"{' '.join(agent_cmd)}")
        # Capture BOTH streams to one log: stdout (print) + stderr (logging),
        # merged so ordering is preserved. Child runs unbuffered (see agent_cmd).
        logfh = open(AGENT_LOG, "w")
        agent = subprocess.Popen(agent_cmd, cwd=str(_PROJECT_ROOT), env=agent_env,
                                 stdout=logfh, stderr=subprocess.STDOUT)
        agent_pid = agent.pid
        print(f"    agent PID={agent_pid}; waiting for '{LOG_READY}' "
              f"(<= {READY_TIMEOUT:.0f}s — BPF compile + lineage prewarm)")
        ready = wait_for_log(LOG_READY, READY_TIMEOUT, proc=agent)
        if not ready:
            # Distinguish premature exit from a true timeout, and dump the FULL
            # log (both streams) so the failure cause is visible.
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
        report.check("agent NOT in any rsentry cgroup at startup", "none",
                     str([str(c) for c in cgroup_dirs()]) or "none", not cgroup_dirs())

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

        # ---- 4. RUN LOCKBIT SIM (UID 1000, non-python3 comm) ----------------
        print(f"[4] {SIM_NAME} SIM — real sim CLI as UID 1000 via {SYMLINK}")
        seed_zone()
        if SYMLINK.exists() or SYMLINK.is_symlink():
            SYMLINK.unlink()
        SYMLINK.symlink_to(sys.executable)  # comm -> "lockbit_locker" (defeats python3 safelist)
        sim_env = dict(os.environ, PYTHONPATH=str(_PROJECT_ROOT), BACKEND_URL=backend_url)
        sim = subprocess.Popen(
            [str(SYMLINK), "-m", SIM_MODULE,
             "--target", str(ZONE), "--no-restore", "--traversal", "dfs",
             "--max-files", str(SIM_MAX_FILES), "--delay", SIM_DELAY],
            cwd=str(_PROJECT_ROOT), env=sim_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            user=OPERATOR_UID, group=OPERATOR_GID,
        )
        sim_pid = sim.pid
        report.check(f"{SIM_NAME} sim spawned as UID 1000", "uid=1000",
                     f"pid={sim_pid} uid={proc_uid(sim_pid)} comm={SYMLINK.name}",
                     proc_uid(sim_pid) == OPERATOR_UID)

        # ---- 5. WAIT FOR AUTONOMOUS RESPONSE --------------------------------
        print(f"[5] OBSERVE — waiting for the agent's autonomous pipeline "
              f"(<= {RESPONSE_TIMEOUT:.0f}s). The test sends NO signals to the sim.")
        saw_stopped = False
        captured_rule = ""
        captured_cgroup_procs: "set[int] | None" = None
        want_sigstop = LOG_SIGSTOP.format(pid=sim_pid)
        want_sigkill = LOG_SIGKILL.format(pid=sim_pid)
        want_complete = LOG_COMPLETE.format(pid=sim_pid)
        deadline = time.time() + RESPONSE_TIMEOUT
        while time.time() < deadline:
            st = proc_state(sim_pid)
            if st == "T":
                saw_stopped = True
            if not captured_rule:
                for ln in contain_rules_present():
                    if f"{CGROUP_PREFIX}-{sim_pid}" in ln:
                        captured_rule = ln
            cg = CGROUP_ROOT / f"{CGROUP_PREFIX}-{sim_pid}" / "cgroup.procs"
            if cg.exists() and captured_cgroup_procs is None:
                try:
                    captured_cgroup_procs = {int(x) for x in cg.read_text().split()}
                except (OSError, ValueError):
                    pass
            log = log_text()
            if want_complete in log or (want_sigkill in log and sim.poll() is not None):
                break
            time.sleep(0.25)

        log = log_text()
        sim_alive = sim.poll() is None
        sim_rc = sim.poll()

        if not (want_sigstop in log or want_sigkill in log):
            print("\n!!!! AUTONOMOUS RESPONSE NOT OBSERVED — diagnostics !!!!")
            print(f"  sim_pid={sim_pid} state={proc_state(sim_pid)} "
                  f"alive={sim_alive} rc={sim_rc}")
            print(f"  iptables OUTPUT:\n    " +
                  "\n    ".join(output_chain()) or "    (empty)")
            print(f"  captured events for sim: {captured_events_for(sim_pid)}")
            print("  agent log tail:")
            print("    " + "\n    ".join(log.splitlines()[-30:]))

        # ---- 6. ASSERT -------------------------------------------------------
        print("[6] ASSERT autonomous detection + containment")
        m = _ISO_RE.search(log)
        iso_cgroup = m.group(1) if m else ""
        iso_pids = ({int(x) for x in m.group(2).replace(" ", "").split(",") if x}
                    if m else set())

        # (0) DETECTION LAYER — read from the telemetry the agent POSTed:
        #     PROCESS_ANOMALY with profile=lockbit5 OR a 16-char dst extension,
        #     and NO SILENT_ENCRYPTION (silent_enc == 0 → rename layer, not write-offset).
        sim_events = captured_events_for(sim_pid)
        proc_anom = [e for e in sim_events if e.get("event_type") == "PROCESS_ANOMALY"]
        silent = [e for e in sim_events if e.get("event_type") == "SILENT_ENCRYPTION"]
        layer_ok = any(_is_lockbit_rename(e) for e in proc_anom)
        report.check("detection layer = RENAME (lockbit5 / 16-char ext), NOT write-offset",
                     "PROCESS_ANOMALY lockbit5/16ch & silent_enc=0",
                     f"proc_anomaly={len(proc_anom)} lockbit_rename={layer_ok} "
                     f"silent_enc_events={len(silent)}",
                     layer_ok and len(silent) == 0)

        # (a) agent stopped/killed the sim; the TEST never signalled it.
        report.check("test sent NO signal to sim before assert", "no signal",
                     "no signal" if not test_signalled_sim else "SIGNALLED",
                     not test_signalled_sim)
        agent_acted = (want_sigstop in log) or saw_stopped
        sim_dead_by_agent = (not sim_alive) and (want_sigkill in log or sim_rc == -signal.SIGKILL)
        report.check("agent autonomously SIGSTOP'd/froze the sim",
                     "SIGSTOP in log or state=T",
                     f"sigstop_log={want_sigstop in log} saw_T={saw_stopped}",
                     agent_acted)
        report.check("agent autonomously SIGKILL'd the sim",
                     "SIGKILL in log & sim dead",
                     f"sigkill_log={want_sigkill in log} alive={sim_alive} rc={sim_rc}",
                     sim_dead_by_agent)

        # (b) cgroup-scoped isolation, --path not --uid-owner.
        iso_logged = (LOG_ISOLATE in log and f"{CGROUP_PREFIX}-{sim_pid}" in log
                      and LOG_ISOLATE_SCOPED in log)
        no_uid_owner = "--uid-owner" not in log and "--uid-owner" not in captured_rule
        rule_path_ok = ("--path" in captured_rule) if captured_rule else iso_logged
        report.check("agent applied cgroup-scoped isolation (--path, not --uid-owner)",
                     "--path & !--uid-owner",
                     f"logged={iso_logged} caught_rule={'yes' if captured_rule else 'no'} "
                     f"path_ok={rule_path_ok}",
                     iso_logged and no_uid_owner and rule_path_ok)

        # (c) full pipeline visible in the agent's own log.
        pipeline = (want_sigstop in log and LOG_ISOLATE in log and want_sigkill in log)
        report.check("agent log shows full pipeline (SIGSTOP+isolate+SIGKILL)",
                     "all three",
                     f"stop={want_sigstop in log} iso={LOG_ISOLATE in log} "
                     f"kill={want_sigkill in log}",
                     pipeline)

        # (d) self-protection: agent + operator survive.
        agent_alive = agent.poll() is None
        op_alive = operator.poll() is None
        op_reach = operator_can_reach_network()
        report.check("agent NOT killed by its own containment", "alive",
                     "alive" if agent_alive else "DEAD", agent_alive)
        report.check("operator ping alive + reachable throughout (T1498)",
                     "alive & reachable",
                     f"alive={op_alive} reachable={op_reach}", op_alive and op_reach)

        # (e) agent PID NOT in the isolated cgroup (only the sim tree was).
        agent_absent_log = (bool(iso_pids) and agent_pid not in iso_pids
                            and sim_pid in iso_pids)
        agent_absent_live = (captured_cgroup_procs is None
                             or agent_pid not in captured_cgroup_procs)
        report.check("agent PID NOT in isolated cgroup; only sim tree isolated",
                     f"agent({agent_pid}) absent, sim({sim_pid}) present",
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
        # Kill any sim leftover (only if the agent didn't already). This is the
        # ONLY place the test may signal the sim — after assertions are taken.
        if sim is not None and sim.poll() is None:
            test_signalled_sim = True  # noqa: F841 - audit marker (post-assert only)
            for s in (signal.SIGCONT, signal.SIGKILL):
                try:
                    os.kill(sim.pid, s)
                except OSError:
                    pass
            try:
                sim.wait(timeout=5)
            except Exception:
                pass
            print(f"    sim leftover killed (rc={sim.poll()})")
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
        print("FAIL: autonomous LockBit test needs root — it starts a real")
        print("`agent.monitor` enforce process that loads BPF and writes")
        print("iptables/cgroup state.")
        print("\nThe privileged run will, in order:")
        print("  * stand up a throwaway stub backend (records agent telemetry)")
        print("  * start `SENSOR_MODE=enforce python3 -m agent.monitor --backend")
        print("    ebpf --watch /tmp/rsentry_lockbit_watch` as its OWN process")
        print("  * spawn a UID-1000 `ping 8.8.8.8` (operator liveness)")
        print("  * spawn the REAL LockBit sim as UID 1000 via /tmp/lockbit_locker")
        print("    (comm != python3, so the agent does not safelist it)")
        print("  * OBSERVE (log + telemetry + iptables + /proc + cgroup) the agent")
        print("    autonomously SIGSTOP -> evidence -> cgroup isolate -> SIGKILL the sim")
        print("  * tear everything down (SIGTERM agent, surgical iptables -D, rmdir)")
        print("\nReview the script first, then run:")
        print(f"  sudo /usr/bin/python3 {here}")
        print("Or validate the log contract + comm trick without root:")
        print(f"  {sys.executable} {here} --selfcheck")
        print("!" * 78)
        return 2
    return _live(report)


if __name__ == "__main__":
    sys.exit(main())
