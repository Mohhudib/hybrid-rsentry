#!/usr/bin/env python3
"""
tests/evaluation/harness.py — the shared evaluation orchestrator.  [ROOT to run]

One Trial = one labeled workload (malicious or benign) run against a FRESH agent,
observed ONLY from the outside (agent log, /proc, iptables, cgroup, the workload's
own monotonic side-channel). No agent internals are ever called. This is the
foundation every efficacy/efficiency/robustness test builds on; it implements the
binding definitions of docs/evaluation-design.md §0 and the procedure of §1.4.

WHAT THIS MODULE PROVIDES
  * Workload      — a runnable, labeled unit (built by the corpus/ plans).
  * TrialResult   — the per-trial record (exact fields the design specifies).
  * run_trial()   — start a fresh agent, run one workload, observe, tear down.

CLOCK DISCIPLINE (design §0.5)
  Everything is CLOCK_MONOTONIC via time.monotonic_ns(). On Linux this clock is
  system-wide, so the sim's side-channel t0/touch timestamps (sim process) and the
  harness's stage timestamps (this process) live in ONE comparable domain. Stage
  timestamps are *observer* timestamps — recorded when the harness first sees the
  PID-scoped log signature during a tight poll — so they carry a bounded poll
  latency (design §2.6 internal-validity threat). A future refinement can swap in
  the kernel BPF event ts for sub-millisecond t_detect.

PASSIVE OBSERVATION ONLY
  Detection/containment timestamps are parsed from log lines the agent ALREADY
  emits (agent/containment.py + agent/monitor.py); we add nothing to the hot path.

SAFETY / TEARDOWN
  Surgical: SIGTERM the agent, SIGCONT+SIGKILL any workload leftover, remove only
  our own tagged iptables rule (never -F/--flush), rmdir our cgroup, and assert the
  OUTPUT chain is byte-for-byte restored. Mirrors the proven live-test teardown.
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
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

OPERATOR_UID = 1000
OPERATOR_GID = 1000
EVAL_BASE = Path("/tmp/rsentry_eval")
EVIDENCE_BASE = Path("/tmp/rsentry_evidence")
READY_TIMEOUT = 90.0          # BPF compile + ~492k-hash lineage prewarm
POLL_INTERVAL = 0.003         # fine poll so stage observer-latency stays small
CGROUP_PREFIX = "rsentry-contain"
CGROUP_ROOT = Path("/sys/fs/cgroup")
LOG_READY = "probes loaded — listening"

# Event types that count as a detection in AUDIT mode (no SIGSTOP pipeline line);
# in ENFORCE mode the SIGSTOP-pipeline line is the canonical Detection signal.
CRITICAL_EVENT_TYPES = frozenset({
    "CANARY_TOUCHED", "CANARY_ATTEMPT", "SILENT_ENCRYPTION",
    "BACKUP_DESTRUCTION", "PROCESS_ANOMALY",
})

# Layers the ablation may ask to disable — none are wired in the agent yet.
KNOWN_LAYERS = frozenset({"canary", "rename", "write_offset", "entropy", "execve"})


# --------------------------------------------------------------------------- #
# Workload — a runnable labeled unit (built by corpus/malicious_samples.py and
# corpus/benign_workloads.py). Kept here so corpus modules and run_trial agree.
# --------------------------------------------------------------------------- #

@dataclass
class Workload:
    """One runnable labeled workload.

    setup(watch_dir) -> target: create the corpus under the fresh watch dir
        (root creates it, then chowns to UID 1000) and return the path the
        workload operates on.
    build_argv(exec_path, target, ts_path) -> argv: the command line. exec_path
        is the symlink path when `comm` is set (comm trick), else "" and argv[0]
        is the tool itself. ts_path is the side-channel path or None.
    comm: when set, the workload is launched through /tmp/<comm> -> interpreter
        so the kernel `comm` is not 'python3' (defeats the IGNORE_COMMS safelist).
        None means run argv[0] directly (a real non-safelisted binary, e.g. gzip).
    uses_timestamps: malicious sims that emit the --eval-timestamps side-channel.
    canary_check() -> bool|None: optional; whether a decoy survived (canary sims).
    """
    sample_id: str
    label: int                                   # 1 malicious, 0 benign
    family_or_class: str
    setup: Callable[[Path], Path]
    build_argv: Callable[[str, Path, Optional[str]], List[str]]
    comm: Optional[str] = None
    uses_timestamps: bool = False
    interpreter: str = "/usr/bin/python3"
    expected_primary_layer: Optional[str] = None
    canary_check: Optional[Callable[[], Optional[bool]]] = None
    run_as_uid: int = OPERATOR_UID
    run_as_gid: int = OPERATOR_GID


# --------------------------------------------------------------------------- #
# TrialResult — the per-trial record (exact fields from the task spec)
# --------------------------------------------------------------------------- #

@dataclass
class TrialResult:
    sample_id: str
    label: int                              # 1=malicious, 0=benign
    family_or_class: str
    t0: Optional[float]                     # first malicious file-touch (monotonic_ns)
    t_detect: Optional[float]
    t_decide: Optional[float]
    t_sigstop: Optional[float]
    t_isolate: Optional[float]
    t_kill: Optional[float]
    t_complete: Optional[float]
    layer_fired: Optional[str]              # canary|rename|write_offset|entropy|execve
    detected: bool                          # D: CRITICAL decision for trial PID
    contained: bool                         # C: CONTAINMENT COMPLETE for trial PID
    canary_survived: Optional[bool]
    files_touched_before_freeze: Optional[int]
    agent_restart_id: str
    host_loadavg: float
    raw_log_excerpt: str                    # PID-scoped pipeline lines, for audit

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Small external-observation helpers (never touch agent internals)
# --------------------------------------------------------------------------- #

def _run(cmd: List[str], timeout: float = 15.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _output_chain() -> List[str]:
    cp = _run(["iptables", "-S", "OUTPUT"])
    return [ln for ln in cp.stdout.splitlines() if ln.strip()]


def _contain_rules() -> List[str]:
    return [ln for ln in _output_chain() if CGROUP_PREFIX in ln]


def _cgroup_dirs() -> List[Path]:
    return list(CGROUP_ROOT.glob(f"{CGROUP_PREFIX}-*"))


def _proc_alive(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def _agent_already_running() -> List[str]:
    cp = _run(["pgrep", "-f", "agent.monitor"])
    return [p for p in cp.stdout.split() if p.strip() and int(p) != os.getpid()]


# --------------------------------------------------------------------------- #
# Throwaway stub backend — absorbs agent telemetry (so the synchronous contain-
# worker POST never stalls on retry back-off) AND records every event so AUDIT-
# mode detection can be inferred from the emitted CRITICAL/HIGH events.
# --------------------------------------------------------------------------- #

class _StubBackend:
    def __init__(self) -> None:
        self.events: List[dict] = []          # recorded POST bodies
        self._lock = threading.Lock()
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def _drain(self) -> bytes:
                try:
                    n = int(self.headers.get("Content-Length", 0) or 0)
                    return self.rfile.read(n) if n else b""
                except Exception:
                    return b""

            def do_POST(self):  # noqa: N802
                body = self._drain()
                try:
                    payload = json.loads(body.decode() or "{}")
                    with outer._lock:
                        outer.events.append(payload)
                except Exception:
                    pass
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, *a):  # silence
                return

        self._srv = HTTPServer(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}"

    def start(self) -> None:
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self) -> None:
        try:
            self._srv.shutdown()
        except Exception:
            pass

    def detected_pid(self, pid: int) -> bool:
        """AUDIT-mode detection proxy: any recorded event for this PID with
        CRITICAL/HIGH severity or a critical event type."""
        with self._lock:
            for ev in self.events:
                if int(ev.get("pid", -1)) != pid:
                    continue
                if str(ev.get("severity", "")).upper() in ("CRITICAL", "HIGH"):
                    return True
                if ev.get("event_type") in CRITICAL_EVENT_TYPES:
                    return True
        return False


# --------------------------------------------------------------------------- #
# layer_toggles — ablation hook. No per-layer decision gate exists in the agent
# yet (design §3.2 / §7-Q4), so disabling any layer raises — we never fake it.
# --------------------------------------------------------------------------- #

def _validate_layer_toggles(layer_toggles: Optional[Dict[str, bool]]) -> None:
    if not layer_toggles:
        return
    for layer, enabled in layer_toggles.items():
        if layer not in KNOWN_LAYERS:
            raise ValueError(f"unknown layer {layer!r}; known: {sorted(KNOWN_LAYERS)}")
        if enabled:
            continue  # enabling is the default; nothing to do
        # TODO(ablation): wire SENSOR_DISABLE_<LAYER> decision-path gates into
        # agent/monitor_ebpf.py run_sensor (the _handle_* dispatchers) and
        # agent/monitor.py before Axis-3 ablation can run. Until then we refuse
        # to silently run a no-op "disabled" config that would look like data.
        raise NotImplementedError(
            f"layer_toggles[{layer!r}]=disabled is not supported: the agent has "
            f"no per-layer decision-path gate yet (docs/evaluation-design.md "
            f"§3.2 / §7-Q4). Add a SENSOR_DISABLE_{layer.upper()} gate first."
        )


# --------------------------------------------------------------------------- #
# Agent lifecycle
# --------------------------------------------------------------------------- #

def _start_agent(watch_dir: Path, *, lsm: bool, enforce: bool,
                 backend_url: str, restart_id: str) -> Tuple[subprocess.Popen, Path]:
    """Start a fresh `agent.monitor` (eBPF) and return (proc, log_path). Caller
    waits for readiness. Mirrors the live-test launch (unbuffered, merged
    stdout+stderr to a file)."""
    log_path = EVAL_BASE / f"agent_{restart_id}.log"
    env = dict(
        os.environ,
        SENSOR_MODE="enforce" if enforce else "audit",
        SENSOR_BACKEND="ebpf",
        BACKEND_URL=backend_url,
        PYTHONPATH=str(_PROJECT_ROOT),
        HEARTBEAT_INTERVAL="3600",
        PYTHONUNBUFFERED="1",
    )
    cmd = [sys.executable, "-u", "-m", "agent.monitor",
           "--backend", "ebpf", "--watch", str(watch_dir),
           "--mode", "enforce" if enforce else "audit",
           "--lsm" if lsm else "--no-lsm"]
    logfh = open(log_path, "w")
    proc = subprocess.Popen(cmd, cwd=str(_PROJECT_ROOT), env=env,
                            stdout=logfh, stderr=subprocess.STDOUT)
    return proc, log_path


def _wait_ready(log_path: Path, proc: subprocess.Popen, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if LOG_READY in _read_text(log_path):
            return True
        if proc.poll() is not None:
            return LOG_READY in _read_text(log_path)
        time.sleep(0.2)
    return False


# --------------------------------------------------------------------------- #
# Workload launch
# --------------------------------------------------------------------------- #

def _launch_workload(workload: Workload, target: Path, backend_url: str,
                     restart_id: str) -> Tuple[subprocess.Popen, Optional[str],
                                               Optional[Path], List[str]]:
    """Launch the workload as UID 1000. Returns (proc, ts_path, symlink_path, argv)."""
    ts_path: Optional[str] = None
    if workload.uses_timestamps:
        ts_path = str(EVAL_BASE / f"ts_{restart_id}.jsonl")
        # CRITICAL: EVAL_BASE is root-owned (run_trial runs as root), but the sim
        # runs as UID 1000 and opens this file for append. Creating it inside the
        # root-owned dir from UID 1000 would EACCES — which previously raised in
        # the sim's writer __init__ BEFORE any file op, so the sim exited doing
        # nothing and the agent observed silence. Pre-create the file as root and
        # hand it to the operator so the sim can append (append needs write on the
        # existing file only, not on the root-owned directory).
        Path(ts_path).touch()
        try:
            os.chown(ts_path, workload.run_as_uid, workload.run_as_gid)
        except OSError:
            pass

    symlink_path: Optional[Path] = None
    exec_path = ""
    if workload.comm:
        symlink_path = Path("/tmp") / workload.comm
        if symlink_path.exists() or symlink_path.is_symlink():
            symlink_path.unlink()
        symlink_path.symlink_to(workload.interpreter)  # comm := basename
        exec_path = str(symlink_path)

    argv = workload.build_argv(exec_path, target, ts_path)
    env = dict(os.environ, PYTHONPATH=str(_PROJECT_ROOT), BACKEND_URL=backend_url)
    proc = subprocess.Popen(
        argv, cwd=str(_PROJECT_ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        user=workload.run_as_uid, group=workload.run_as_gid,
    )
    return proc, ts_path, symlink_path, argv


# --------------------------------------------------------------------------- #
# Observation — parse PID-scoped log signatures, recording monotonic_ns at the
# first sighting of each stage.
# --------------------------------------------------------------------------- #

def _stage_signatures(pid: int) -> Dict[str, "re.Pattern[str]"]:
    """PID-scoped regex for each stage. Each is matched on its OWN log line:
      detect   — "SIGSTOP pipeline: pid=<PID> … layer=<L>"   (monitor._make_contain_fn)
      sigstop  — "SIGSTOP sent to PID <PID>"                  (containment._sigstop)
      isolate  — "Network isolation applied: cgroup=…<PID>"   (containment._cgroup…)
      kill     — "SIGKILL sent to PID <PID>"                  (containment._sigkill)
      complete — "=== CONTAINMENT COMPLETE PID <PID>"         (containment.contain)
    """
    p = re.escape(str(pid))
    return {
        # detect/decide collapse to one observable (the pipeline line); separating
        # them needs the kernel BPF event ts (not surfaced) — documented TODO.
        "detect":  re.compile(rf"SIGSTOP pipeline: pid={p}\b.*?layer=(\w+)"),
        "sigstop": re.compile(rf"SIGSTOP sent to PID {p}\b"),
        "isolate": re.compile(rf"Network isolation applied: cgroup=\S*{CGROUP_PREFIX}-{p}\b"),
        "kill":    re.compile(rf"SIGKILL sent to PID {p}\b"),
        "complete": re.compile(rf"CONTAINMENT COMPLETE PID {p}\b"),
    }


# Leading timestamp written by the agent's logging.basicConfig format
# ("%(asctime)s [%(levelname)s] …") — e.g. "2026-06-14 12:00:00,123".
_ASCTIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")


def _parse_asctime(line: str) -> Optional[datetime]:
    """Parse the agent log line's own millisecond wall-clock timestamp, or None."""
    m = _ASCTIME_RE.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        return None


def _observe(log_path: Path, pid: int, response_timeout: float,
             workload_proc: subprocess.Popen) -> Tuple[Dict[str, int],
                                                        Optional[str], str]:
    """Poll the agent log until CONTAINMENT COMPLETE for this PID (or timeout),
    then compose per-stage timestamps in the CLOCK_MONOTONIC domain.

    WAIT CONTRACT (fixes the early-teardown bug):
      * Detection (D, the "SIGSTOP pipeline" line) and Containment completion
        (C, the "CONTAINMENT COMPLETE" line) are SEPARATE observables (design
        §0.2). Once D is seen we wait ONLY for C or the response_timeout — never
        returning on workload exit, because the workload PID is SIGKILLed mid-
        pipeline and C is logged AFTER it dies.
      * If D is NOT seen and the workload has exited, it will (almost certainly)
        never be detected (benign / clean finish): we give a bounded grace for
        trailing log flush, then stop — so benign trials don't burn the full
        response_timeout.

    TIMESTAMP COMPOSITION (fixes t_sigstop == t_detect):
      t_detect is anchored at its observer monotonic_ns sighting (so MTTD =
      t_detect - t0 stays in one comparable clock with the sim's t0). The later
      stages are placed by their PRECISE asctime delta from the detect line (the
      agent's own ms-resolution clock), so t_sigstop/t_isolate/t_kill/t_complete
      separate from t_detect instead of collapsing on poll granularity. Falls
      back to the observer stamp if a line carried no parseable timestamp.
    """
    sigs = _stage_signatures(pid)
    obs_ns: Dict[str, int] = {}            # observer monotonic_ns at first sighting
    wall: Dict[str, datetime] = {}         # the matched line's own asctime
    layer_fired: Optional[str] = None
    deadline = time.monotonic() + response_timeout
    NO_DETECT_GRACE = 3.0                   # bounded wait after an undetected exit
    workload_gone_at: Optional[float] = None

    def _scan(text: str, now: int) -> None:
        nonlocal layer_fired
        for line in text.splitlines():
            for name, rx in sigs.items():
                if name in obs_ns:
                    continue
                m = rx.search(line)
                if m:
                    obs_ns[name] = now
                    w = _parse_asctime(line)
                    if w is not None:
                        wall[name] = w
                    if name == "detect" and m.groups():
                        layer_fired = m.group(1)

    while time.monotonic() < deadline:
        now = time.monotonic_ns()
        _scan(_read_text(log_path), now)
        if "complete" in obs_ns:
            break                          # terminal observable — done
        if "detect" not in obs_ns:
            # Not detected yet. If the workload has already exited, only wait a
            # bounded grace for any trailing line, then stop.
            if workload_proc.poll() is not None:
                if workload_gone_at is None:
                    workload_gone_at = time.monotonic()
                elif time.monotonic() - workload_gone_at >= NO_DETECT_GRACE:
                    break
        # else: DETECTED — keep polling for completion regardless of workload
        # state (it is SIGKILLed before COMPLETE is logged). Never break here.
        time.sleep(POLL_INTERVAL)

    # Final read to catch any line written just before the loop ended.
    _scan(_read_text(log_path), time.monotonic_ns())

    # Compose the monotonic-domain stage map (see docstring).
    stage_ns: Dict[str, int] = {}
    t_detect = obs_ns.get("detect")
    if t_detect is not None:
        stage_ns["detect"] = t_detect
        for name in ("sigstop", "isolate", "kill", "complete"):
            if name not in obs_ns:
                continue
            if "detect" in wall and name in wall:
                delta_s = max(0.0, (wall[name] - wall["detect"]).total_seconds())
                stage_ns[name] = t_detect + int(delta_s * 1_000_000_000)
            else:
                stage_ns[name] = obs_ns[name]
    else:
        # No detect line (e.g. AUDIT mode): fall back to observer stamps.
        for name in ("sigstop", "isolate", "kill", "complete"):
            if name in obs_ns:
                stage_ns[name] = obs_ns[name]

    excerpt_lines = [
        ln for ln in _read_text(log_path).splitlines()
        if f"pid={pid}" in ln or f"PID {pid}" in ln or f"{CGROUP_PREFIX}-{pid}" in ln
    ]
    return stage_ns, layer_fired, "\n".join(excerpt_lines[-50:])


def _read_sidechannel(ts_path: Optional[str]) -> Tuple[Optional[int], List[int]]:
    """Return (t0_ns, [touch_ns, ...]) from the sim side-channel, or (None, [])."""
    if not ts_path:
        return None, []
    p = Path(ts_path)
    if not p.is_file():
        return None, []
    touches: List[int] = []
    for line in _read_text(p).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event") == "touch" and "ts_ns" in rec:
            touches.append(int(rec["ts_ns"]))
    touches.sort()
    t0 = touches[0] if touches else None
    return t0, touches


# --------------------------------------------------------------------------- #
# Teardown — always runs
# --------------------------------------------------------------------------- #

def _teardown(agent: Optional[subprocess.Popen], workload: Optional[subprocess.Popen],
              stub: Optional[_StubBackend], baseline_chain: List[str],
              watch_dir: Optional[Path], symlink_path: Optional[Path],
              ts_path: Optional[str], log_path: Optional[Path],
              preserve_log: bool = False) -> None:
    # 1. Stop the agent (graceful, then hard).
    if agent is not None and agent.poll() is None:
        try:
            agent.terminate(); agent.wait(timeout=5)
        except Exception:
            try:
                agent.kill(); agent.wait(timeout=5)
            except Exception:
                pass
    # 2. Kill any workload leftover (only AFTER the result was taken).
    if workload is not None and workload.poll() is None:
        for s in (signal.SIGCONT, signal.SIGKILL):
            try:
                os.kill(workload.pid, s)
            except OSError:
                pass
        try:
            workload.wait(timeout=5)
        except Exception:
            pass
    if stub is not None:
        stub.stop()
    # 3. Surgical iptables cleanup — delete only our own tagged rule, NEVER -F.
    for ln in _contain_rules():
        spec = ln.split()
        if spec and spec[0] == "-A":
            try:
                _run(["iptables", "-D"] + spec[1:])
            except Exception:
                pass
    for cg in _cgroup_dirs():
        try:
            cg.rmdir()
        except OSError:
            pass
    # 4. Filesystem cleanup.
    if watch_dir is not None:
        shutil.rmtree(watch_dir, ignore_errors=True)
    shutil.rmtree(EVIDENCE_BASE, ignore_errors=True)
    if symlink_path is not None and (symlink_path.exists() or symlink_path.is_symlink()):
        try:
            symlink_path.unlink()
        except OSError:
            pass
    if ts_path:
        Path(ts_path).unlink(missing_ok=True)
    if log_path is not None and not preserve_log:
        log_path.unlink(missing_ok=True)
    # 5. Best-effort assertion (logged via return value of caller, not raised).
    final = _output_chain()
    if final != baseline_chain:
        print(f"[harness] WARNING: OUTPUT chain not restored to baseline "
              f"(baseline={len(baseline_chain)} final={len(final)})", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def run_trial(workload: Workload, *, lsm: bool, enforce: bool,
              layer_toggles: Optional[Dict[str, bool]] = None,
              response_timeout: float = 30.0,
              preserve_log: bool = False, debug: bool = False) -> TrialResult:
    """Run ONE labeled workload against a FRESH agent and return its TrialResult.

    Requires root (the agent loads BPF and writes iptables/cgroup). Observes only
    from the outside. Always tears down surgically, even on error.

    preserve_log: keep the per-trial agent log at EVAL_BASE/agent_<restart_id>.log
        instead of deleting it in teardown (diagnostics — read the FULL log after).
    """
    if os.geteuid() != 0:
        raise PermissionError(
            "run_trial requires root — it starts a real agent.monitor that loads "
            "BPF and writes iptables/cgroup. Run the trial under sudo.")
    _validate_layer_toggles(layer_toggles)

    running = _agent_already_running()
    if running:
        raise RuntimeError(
            f"an agent.monitor is already running (pids={running}); a trial must "
            f"own the only agent. Stop it first.")

    restart_id = uuid.uuid4().hex[:12]
    baseline_chain = _output_chain()
    if _contain_rules() or _cgroup_dirs():
        raise RuntimeError("pre-existing rsentry-contain rule/cgroup; environment "
                           "is dirty — clean it before running trials.")

    EVAL_BASE.mkdir(parents=True, exist_ok=True)
    watch_dir = EVAL_BASE / f"watch_{restart_id}"
    if watch_dir.exists():
        shutil.rmtree(watch_dir, ignore_errors=True)
    watch_dir.mkdir(mode=0o777, parents=True)
    os.chown(watch_dir, OPERATOR_UID, OPERATOR_GID)

    agent: Optional[subprocess.Popen] = None
    wl_proc: Optional[subprocess.Popen] = None
    stub: Optional[_StubBackend] = None
    ts_path: Optional[str] = None
    symlink_path: Optional[Path] = None
    log_path: Optional[Path] = None
    host_loadavg = os.getloadavg()[0]

    try:
        stub = _StubBackend()
        stub.start()

        agent, log_path = _start_agent(watch_dir, lsm=lsm, enforce=enforce,
                                       backend_url=stub.url, restart_id=restart_id)
        if not _wait_ready(log_path, agent, READY_TIMEOUT):
            tail = "\n".join(_read_text(log_path).splitlines()[-20:])
            raise RuntimeError(
                f"agent did not reach readiness in {READY_TIMEOUT:.0f}s "
                f"(rc={agent.poll()}). Log tail:\n{tail}")

        # Prepare corpus (root creates, chowns to operator inside setup or here).
        target = workload.setup(watch_dir)

        wl_proc, ts_path, symlink_path, argv = _launch_workload(
            workload, target, stub.url, restart_id)
        wl_pid = wl_proc.pid

        if debug:
            time.sleep(0.05)   # let the kernel set comm
            try:
                comm = Path(f"/proc/{wl_pid}/comm").read_text().strip()
            except OSError:
                comm = "(exited)"
            ts_owner = None
            if ts_path and Path(ts_path).exists():
                st = os.stat(ts_path)
                ts_owner = f"uid={st.st_uid} mode={oct(st.st_mode & 0o777)}"
            print("[debug] agent --watch =", watch_dir, file=sys.stderr)
            print("[debug] sim --target  =", target, file=sys.stderr)
            print("[debug] watch==target.parent.parent?",
                  watch_dir in target.parents, file=sys.stderr)
            print("[debug] sim argv      =", argv, file=sys.stderr)
            print("[debug] sim pid       =", wl_pid, file=sys.stderr)
            print("[debug] sim comm      =", comm,
                  "(safelisted!)" if comm in ("python3", "python") else "(ok)",
                  file=sys.stderr)
            print("[debug] ts_path       =", ts_path, "owner:", ts_owner,
                  file=sys.stderr)

        stage_ns, layer_fired, excerpt = _observe(
            log_path, wl_pid, response_timeout, wl_proc)

        t0_ns, touches = _read_sidechannel(ts_path)

        detected = ("detect" in stage_ns) or stub.detected_pid(wl_pid)
        contained = "complete" in stage_ns
        t_sigstop = stage_ns.get("sigstop")
        files_before = (sum(1 for t in touches if t < t_sigstop)
                        if (t_sigstop is not None and touches) else None)
        canary_survived = (workload.canary_check()
                           if workload.canary_check is not None else None)

        result = TrialResult(
            sample_id=workload.sample_id,
            label=workload.label,
            family_or_class=workload.family_or_class,
            t0=float(t0_ns) if t0_ns is not None else None,
            t_detect=float(stage_ns["detect"]) if "detect" in stage_ns else None,
            t_decide=float(stage_ns["detect"]) if "detect" in stage_ns else None,
            t_sigstop=float(t_sigstop) if t_sigstop is not None else None,
            t_isolate=float(stage_ns["isolate"]) if "isolate" in stage_ns else None,
            t_kill=float(stage_ns["kill"]) if "kill" in stage_ns else None,
            t_complete=float(stage_ns["complete"]) if "complete" in stage_ns else None,
            layer_fired=layer_fired,
            detected=detected,
            contained=contained,
            canary_survived=canary_survived,
            files_touched_before_freeze=files_before,
            agent_restart_id=restart_id,
            host_loadavg=round(host_loadavg, 2),
            raw_log_excerpt=excerpt,
        )
        return result
    finally:
        _teardown(agent, wl_proc, stub, baseline_chain, watch_dir,
                  symlink_path, ts_path, log_path, preserve_log=preserve_log)
