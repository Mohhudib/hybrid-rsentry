"""
monitor.py — Hybrid R-Sentry endpoint agent monitor.

Supports two sensor backends switchable via SENSOR_BACKEND env var or --backend flag:
  inotify  — original watchdog/inotify sensor (legacy, kept for A/B benchmarking)
  ebpf     — eBPF sensor (monitor_ebpf.py): reliable PID, kernel velocity counter,
             optional inline LSM block, system-wide encrypted-rename capture (Option A)

Environment variables:
  SENSOR_BACKEND     inotify | ebpf          (default: ebpf)
  SENSOR_MODE        enforce | audit          (default: enforce)
  WATCH_PATH         directory to monitor     (default: /home)
  BACKEND_URL        FastAPI server URL       (default: http://localhost:8000)
  HOST_ID            agent hostname/uuid      (default: socket.gethostname())
  CANARY_STRATEGY    bfs | dfs                (default: bfs)
  HEARTBEAT_INTERVAL seconds between pulses   (default: 30)
  REPOSITION_INTERVAL seconds between Markov  (default: 300)
  DRY_RUN            true | false             (default: false)
  EBPF_THRESHOLD     velocity threshold       (default: 2)
  EBPF_WINDOW        velocity window secs     (default: 3.0)
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

# Auto-load .env from project root
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")
except ImportError:
    pass
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SENSOR_BACKEND      = os.getenv("SENSOR_BACKEND", "ebpf")
SENSOR_MODE         = os.getenv("SENSOR_MODE", "enforce")
WATCH_PATH          = os.getenv("WATCH_PATH", "/home")
BACKEND_URL         = os.getenv("BACKEND_URL", "http://localhost:8000")
HOST_ID             = os.getenv("HOST_ID", __import__("socket").gethostname())
CANARY_STRATEGY     = os.getenv("CANARY_STRATEGY", "bfs")
HEARTBEAT_INTERVAL  = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
REPOSITION_INTERVAL = int(os.getenv("REPOSITION_INTERVAL", "300"))
DRY_RUN             = os.getenv("DRY_RUN", "false").lower() == "true"
EBPF_THRESHOLD      = int(os.getenv("EBPF_THRESHOLD", "2"))
EBPF_WINDOW         = float(os.getenv("EBPF_WINDOW", "3.0"))

COMBINED_CRITICAL   = 70.0
COMBINED_HIGH       = 40.0


def _resolve_mode(cli_mode: Optional[str]) -> str:
    """
    Resolve the sensor mode with explicit precedence:
    CLI --mode flag > SENSOR_MODE env var > default ("enforce").

    BUG 1 fix: argparse previously defaulted --mode to SENSOR_MODE and the
    parsed value was never consumed, so only the env var ever took effect.
    """
    return cli_mode if cli_mode else SENSOR_MODE

# SECURITY: never safelist scripting interpreters (python*, perl, bash, node…).
# Ransomware frequently runs as `python3 -m ...`; safelisting the interpreter
# comm suppresses every detection layer for it. R-Sentry's own python workers
# (celery, uvicorn) are covered by their own comm names below.
IGNORE_COMMS = {
    "Xorg", "gnome-shell", "nautilus", "systemd", "dockerd", "containerd",
    "redis-server", "postgres", "celery", "uvicorn",
    "git", "cargo", "rsync", "make", "gcc", "cc1", "ld",
    # Note: "python3" intentionally omitted — uvicorn/celery are listed explicitly,
    # and simulation scripts set their own comm (lockbit-sim, akira-sim, qilin-sim)
    # so mass renames from unknown Python scripts must still be detectable.
}

RANSOMWARE_EXTENSIONS = {
    ".enc", ".encrypted", ".locked", ".crypto", ".crypt", ".cry",
    ".aes", ".aes256", ".wcry", ".wncry", ".wnry",
    ".locky", ".lukitus", ".zepto", ".odin", ".thor",
    ".ryk", ".ryuk", ".sage", ".cerber", ".gdcb", ".dharma", ".wallet",
    ".akira", ".akiranew", ".powerranges",
}

TARGETED_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt",
    ".jpg", ".jpeg", ".png", ".bmp",
    ".db", ".sqlite", ".sqlite3", ".sql",
    ".txt", ".csv", ".json", ".xml",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv",
}

# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------
def _validate_watch_path(watch_path: str) -> None:
    import pathlib
    resolved = pathlib.Path(watch_path).resolve()
    if not resolved.exists():
        logger.critical(
            "WATCH_PATH=%s does not exist — create the directory and restart.", watch_path
        )
        sys.exit(1)
    check = resolved
    for _ in range(10):
        if (check / ".git").is_dir():
            logger.critical(
                "WATCH_PATH=%s is inside a git repository at %s. "
                "Set WATCH_PATH to a directory outside the repo and restart.",
                watch_path, check,
            )
            sys.exit(1)
        parent = check.parent
        if parent == check:
            break
        check = parent

# ---------------------------------------------------------------------------
# Integration seam adapters
# ---------------------------------------------------------------------------

def _make_emit_fn(agent_client) -> Callable[[dict], None]:
    """
    Adapter: monitor_ebpf emits a full 10-field dict;
    client.AgentClient.send_event takes individual keyword args.
    Severity is already computed by DetectionEngine — pass it through.
    Uses a background thread queue to avoid blocking the BPF poll loop.
    """
    import queue as _queue
    _q: _queue.Queue = _queue.Queue(maxsize=1000)

    def _worker():
        while True:
            event = _q.get()
            if event is None:
                break
            try:
                agent_client.send_event(
                    event_type    = event["event_type"],
                    pid           = int(event["pid"]),
                    process_name  = str(event["process_name"]),
                    file_path     = str(event["file_path"]),
                    lineage_score = float(event["lineage_score"]),
                    entropy_delta = float(event["entropy_delta"]),
                    canary_hit    = bool(event["canary_hit"]),
                    details       = event.get("details", {}),
                    severity      = event["severity"],
                )
            except Exception as exc:
                logger.error("emit failed: %s | event=%s", exc, event.get("event_type"))
            finally:
                _q.task_done()

    _t = threading.Thread(target=_worker, daemon=True)
    _t.start()

    def emit(event: dict) -> None:
        try:
            _q.put_nowait(event)
        except _queue.Full:
            logger.warning("emit queue full — dropping event %s", event.get("event_type"))
    return emit


def _make_contain_fn(contain_fn, dry_run_fn, client) -> Callable[[int, str, str], None]:
    """
    Adapter: monitor_ebpf calls contain(pid, comm, layer);
    containment.contain() takes only pid.

    layer names the detection layer that fired the containment
    ("canary" | "rename" | "write_offset" | "entropy" | "execve") so each
    SIGSTOP pipeline log line is attributable to its signal source.
    """
    _contained: set = set()
    _lock = threading.Lock()

    def contain(pid: int, comm: str, layer: str = "unknown") -> None:
        with _lock:
            if pid in _contained:
                return
            _contained.add(pid)
        logger.critical("SIGSTOP pipeline: pid=%d comm=%s layer=%s", pid, comm, layer)
        client.send_containment_triggered(
            pid=pid, process_name=comm,
            file_path="", lineage_score=0.0, entropy_delta=0.0,
        )
        result = dry_run_fn(pid) if DRY_RUN else contain_fn(pid)
        client.send_containment_complete(pid, result.to_dict())

    return contain


def _make_lineage_fn(score_for_event_fn) -> Callable[[int], float]:
    def lineage_fn(pid: int) -> float:
        try:
            return float(score_for_event_fn(pid).get("lineage_score", 0.0))
        except Exception as exc:
            logger.debug("lineage_fn error pid=%d: %s", pid, exc)
            return 0.0
    return lineage_fn


def _make_entropy_fn(entropy_engine) -> Callable[[str], float]:
    def entropy_fn(path: str) -> float:
        if not path or not path.startswith("/"):
            return 0.0
        try:
            result = entropy_engine.observe(path)
            if result:
                return float(result.get("entropy_delta", 0.0))
            rec = entropy_engine._records.get(path)
            return float(rec.latest()) if rec else 0.0
        except Exception as exc:
            logger.debug("entropy_fn error path=%s: %s", path, exc)
            return 0.0
    return entropy_fn

# ---------------------------------------------------------------------------
# Markov repositioner wrapper — suppress_path integration
# ---------------------------------------------------------------------------

class _RepositionerWithSuppression:
    """
    Wraps MarkovRepositioner and calls engine.suppress_path()
    before every shutil.move so the eBPF sensor doesn't alert on its own moves.
    """
    def __init__(self, repositioner):
        self._r = repositioner
        self._ebpf_engine = None  # injected after engine is built

    def observe(self, directory: str) -> None:
        self._r.observe(directory)

    def should_reposition(self) -> bool:
        return self._r.should_reposition()

    def summary(self) -> dict:
        return self._r.summary()

    @property
    def canary_paths(self):
        return self._r.canary_paths

    @canary_paths.setter
    def canary_paths(self, v):
        self._r.canary_paths = v

    def reposition(self, fs_graph=None):
        if self._ebpf_engine is not None:
            for p in self._r.canary_paths:
                self._ebpf_engine.suppress_path(str(p), ttl=15.0)
        new_paths = self._r.reposition(fs_graph=fs_graph)
        if self._ebpf_engine is not None:
            self._ebpf_engine.register_canaries([str(p) for p in new_paths])
        return new_paths

# ---------------------------------------------------------------------------
# inotify backend (original — preserved for A/B benchmarking)
# ---------------------------------------------------------------------------

def _combined_score(lineage_score: float, entropy_delta: float) -> float:
    entropy_norm = min(entropy_delta / 8.0, 1.0) * 100
    return lineage_score * 0.6 + entropy_norm * 0.4


def _check_ransomware_rename(src: str, dest: str) -> Optional[str]:
    dest_suffix = Path(dest).suffix.lower()
    if dest_suffix not in RANSOMWARE_EXTENSIONS:
        return None
    return "CRITICAL" if Path(src).suffix.lower() in TARGETED_EXTENSIONS else "HIGH"


class RsentryEventHandler:

    def __init__(self, fs_graph, entropy_engine, repositioner, client,
                 score_for_event_fn, is_whitelisted_fn, auto_contain=True):
        from watchdog.events import FileSystemEventHandler
        self.__class__ = type(
            "RsentryEventHandler",
            (FileSystemEventHandler, RsentryEventHandler),
            dict(RsentryEventHandler.__dict__),
        )
        self.fs_graph          = fs_graph
        self.entropy_engine    = entropy_engine
        self.repositioner      = repositioner
        self.client            = client
        self.score_for_event   = score_for_event_fn
        self.is_whitelisted    = is_whitelisted_fn
        self.auto_contain      = auto_contain
        self._contained_pids: set = set()
        self._lock             = threading.Lock()

    def _handle_event(self, event_type: str, src_path: str, pid: int = 0):
        canary_hit = self.fs_graph.is_canary(src_path)
        if not canary_hit and self.is_whitelisted(src_path):
            return

        lineage_data  = self.score_for_event(pid) if pid else {
            "lineage_score": 0.0, "process_name": "unknown",
            "exe": "", "ancestors": [], "sha256": None, "reasons": [],
        }
        lineage_score = lineage_data["lineage_score"]
        process_name  = lineage_data.get("process_name") or "unknown"

        entropy_alert = self.entropy_engine.observe(src_path) if not canary_hit else None
        entropy_delta = entropy_alert["entropy_delta"] if entropy_alert else 0.0

        self.repositioner.observe(str(Path(src_path).parent))
        score = _combined_score(lineage_score, entropy_delta)

        if canary_hit:
            final_event, severity = "CANARY_TOUCHED", "CRITICAL"
        elif entropy_alert and lineage_score >= 40:
            final_event = "COMBINED_ALERT"
            severity    = "CRITICAL" if score >= COMBINED_CRITICAL else "HIGH"
        elif entropy_alert:
            final_event = "ENTROPY_SPIKE"
            severity    = entropy_alert.get("severity", "MEDIUM")
        elif lineage_score >= 40:
            final_event = "PROCESS_ANOMALY"
            severity    = "CRITICAL" if score >= COMBINED_CRITICAL else "HIGH"
        else:
            return

        details = {
            "original_event":  event_type,
            "combined_score":  round(score, 2),
            "lineage_reasons": lineage_data.get("reasons", []),
            "ancestors":       lineage_data.get("ancestors", []),
            "sha256":          lineage_data.get("sha256"),
            "sensor":          "inotify",
        }
        self.client.send_event(
            event_type=final_event, pid=pid, process_name=process_name,
            file_path=src_path, lineage_score=lineage_score,
            entropy_delta=entropy_delta, canary_hit=canary_hit,
            details=details, severity=severity,
        )

        if severity == "CRITICAL" and self.auto_contain:
            if pid > 0:
                self._trigger_containment(pid, process_name, src_path,
                                          lineage_score, entropy_delta, canary_hit)
            else:
                self.client.send_containment_triggered(
                    pid=0, process_name="unknown", file_path=src_path,
                    lineage_score=lineage_score, entropy_delta=entropy_delta,
                    canary_hit=canary_hit,
                )

    def _trigger_containment(self, pid, process_name, file_path,
                              lineage_score, entropy_delta, canary_hit=False):
        with self._lock:
            if pid in self._contained_pids:
                return
            self._contained_pids.add(pid)
        from agent.containment import contain as _contain, dry_run_contain
        self.client.send_containment_triggered(
            pid=pid, process_name=process_name, file_path=file_path,
            lineage_score=lineage_score, entropy_delta=entropy_delta,
            canary_hit=canary_hit,
        )
        result = dry_run_contain(pid) if DRY_RUN else _contain(pid)
        self.client.send_containment_complete(pid, result.to_dict())

    def _emit_rename_alert(self, src, dest, severity, sub_type="RANSOMWARE_RENAME"):
        self.client.send_event(
            event_type="ENTROPY_SPIKE", pid=0, process_name="unknown",
            file_path=dest, lineage_score=0.0, entropy_delta=0.0,
            canary_hit=False, severity=severity,
            details={"sub_type": sub_type, "src_path": src, "dest_path": dest,
                     "src_extension": Path(src).suffix.lower(),
                     "dest_extension": Path(dest).suffix.lower(),
                     "sensor": "inotify"},
        )

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event("modified", event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        src = event.src_path
        if Path(src).suffix.lower() in RANSOMWARE_EXTENSIONS:
            self._emit_rename_alert(src, src, "HIGH", "RANSOMWARE_CREATED")
            return
        self._handle_event("created", src)

    def on_deleted(self, event):
        if not event.is_directory and self.fs_graph.is_canary(event.src_path):
            self.client.send_event(
                event_type="CANARY_TOUCHED", pid=0, process_name="unknown",
                file_path=event.src_path, lineage_score=0.0, entropy_delta=0.0,
                canary_hit=True, severity="CRITICAL",
                details={"sub_type": "deleted", "sensor": "inotify"},
            )

    def on_moved(self, event):
        if event.is_directory:
            return
        src, dest = event.src_path, event.dest_path
        if self.fs_graph.is_canary(src):
            self.client.send_event(
                event_type="CANARY_TOUCHED", pid=0, process_name="unknown",
                file_path=src, lineage_score=0.0, entropy_delta=0.0,
                canary_hit=True, severity="CRITICAL",
                details={"sub_type": "moved", "dest": dest, "sensor": "inotify"},
            )
            return
        severity = _check_ransomware_rename(src, dest)
        if severity:
            self._emit_rename_alert(src, dest, severity)


# ---------------------------------------------------------------------------
# Monitor orchestrator
# ---------------------------------------------------------------------------

class Monitor:
    def __init__(self, watch_path: str = WATCH_PATH,
                 backend: str = SENSOR_BACKEND,
                 auto_contain: bool = True,
                 mode: str = SENSOR_MODE,
                 lsm: Optional[bool] = None):
        """
        mode: "enforce" | "audit" — passed through to the sensor (BUG 1 fix:
              previously the module-level SENSOR_MODE env constant was used
              unconditionally and the CLI flag was silently dropped).
        lsm:  None = auto-detect kernel BPF-LSM support (default),
              True/False = force on/off (BUG 4 fix: --lsm/--no-lsm).
        """
        self.watch_path   = watch_path
        self.backend      = backend
        self.auto_contain = auto_contain
        self.mode         = mode
        self.lsm          = lsm
        self._stop_event  = threading.Event()

        from agent.client      import AgentClient
        from agent.containment import contain as _contain, dry_run_contain
        from agent.entropy     import EntropyEngine
        from agent.lineage     import score_for_event
        from agent.adaptive    import MarkovRepositioner
        try:
            from agent import monitor_ebpf as _ebpf
        except ImportError:
            _ebpf = None
        try:
            from agent.graph import FilesystemGraph
        except ImportError:
            FilesystemGraph = None
        try:
            from agent.exceptions import is_whitelisted
        except ImportError:
            is_whitelisted = lambda p: False

        self.client         = AgentClient(backend_url=BACKEND_URL, host_id=HOST_ID)
        self.entropy_engine = EntropyEngine()

        if FilesystemGraph:
            self.fs_graph = FilesystemGraph(root=watch_path)
            canaries      = self.fs_graph.place_canaries(strategy=CANARY_STRATEGY)
        else:
            self.fs_graph = None
            canaries      = []

        if not canaries and _ebpf:
            canaries = _ebpf.seed_canaries([watch_path], per_dir=5)

        raw_repo          = MarkovRepositioner(
            canary_paths=[Path(p) for p in canaries]
        )
        self.repositioner = _RepositionerWithSuppression(raw_repo)

        self.emit_fn    = _make_emit_fn(self.client)
        self.contain_fn = _make_contain_fn(_contain, dry_run_contain, self.client)
        # Pre-warm lineage cache (loads 492k dpkg hashes once at startup)
        logger.info("Pre-warming lineage cache...")
        try:
            import os as _os
            score_for_event(_os.getpid())
            logger.info("Lineage cache ready")
        except Exception:
            pass
        self.lineage_fn = _make_lineage_fn(score_for_event)
        self.entropy_fn = _make_entropy_fn(self.entropy_engine)

        self._ebpf    = _ebpf
        self._contain = _contain
        self._dry_run = dry_run_contain
        self._score   = score_for_event
        self._wl      = is_whitelisted
        self._canaries= [str(p) for p in canaries]
        self._sim_fn  = None

    def _heartbeat_loop(self):
        while not self._stop_event.is_set():
            self.client.send_heartbeat()
            self._stop_event.wait(HEARTBEAT_INTERVAL)

    def _reposition_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(REPOSITION_INTERVAL)
            if self.repositioner.should_reposition():
                logger.info("Markov repositioning triggered")
                old_paths = [str(p) for p in self.repositioner.canary_paths]
                self.repositioner.reposition(fs_graph=self.fs_graph)
                new_paths = [str(p) for p in self.repositioner.canary_paths]
                summary   = self.repositioner.summary()
                self.client.send_event(
                    event_type="HEARTBEAT", pid=0,
                    process_name="markov-repositioner",
                    file_path="", lineage_score=0.0, entropy_delta=0.0,
                    canary_hit=False, severity="LOW",
                    details={
                        "sub_type":      "MARKOV_REPOSITION",
                        "moved":         [{"from": o, "to": n}
                                          for o, n in zip(old_paths, new_paths)],
                        "hotspots":      summary.get("top_hotspots", []),
                        "n_observations":summary.get("n_observations", 0),
                    },
                )

    def _run_inotify(self):
        from watchdog.observers import Observer
        handler = RsentryEventHandler(
            fs_graph           = self.fs_graph,
            entropy_engine     = self.entropy_engine,
            repositioner       = self.repositioner,
            client             = self.client,
            score_for_event_fn = self._score,
            is_whitelisted_fn  = self._wl,
            auto_contain       = self.auto_contain,
        )
        observer = Observer()
        observer.schedule(handler, self.watch_path, recursive=True)
        observer.start()
        print(f"[monitor] backend=inotify watch={self.watch_path}")
        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()

    def _run_ebpf(self):
        if self._ebpf is None:
            logger.critical("monitor_ebpf.py not found in agent/ package")
            sys.exit(1)
        if os.geteuid() != 0:
            logger.critical("eBPF backend requires root: sudo -E python3 -m agent.monitor")
            sys.exit(1)

        self._ebpf.IGNORE_COMMS.update(IGNORE_COMMS)


        print(f"[monitor] backend=eBPF mode={self.mode} "
              f"threshold={EBPF_THRESHOLD}/{EBPF_WINDOW}s "
              f"watch={self.watch_path}")

        self._ebpf.run_sensor(
            watch_dirs     = [self.watch_path],
            canary_paths   = self._canaries,
            host_id        = HOST_ID,
            mode           = self.mode,
            lsm            = self.lsm,
            threshold      = EBPF_THRESHOLD,
            window_seconds = EBPF_WINDOW,
            emit           = self.emit_fn,
            contain        = self.contain_fn,
            lineage_fn     = self.lineage_fn,
            entropy_fn     = self.entropy_fn,
            sim_fn         = self._sim_fn if hasattr(self, "_sim_fn") else None,
            stop_event     = self._stop_event,
        )

    def set_sim(self, sim_path: str, sim_target: str, sim_traversal: str) -> None:
        """Wire a simulation to run inside the eBPF sensor loop."""
        import importlib.util as _ilu
        import sys as _sys
        import pathlib as _pl
        _proj = _pl.Path('/home/kali/hybrid-rsentry').resolve()
        _sim_abs = _pl.Path(sim_path).resolve()
        if not _sim_abs.exists():
            raise ValueError(f"--run-sim path {sim_path!r} does not exist")
        if not str(_sim_abs).startswith(str(_proj)):
            raise ValueError(
                f"--run-sim path {sim_path!r} must be inside {_proj}"
            )
        _sys.path.insert(0, str(_proj))
        _sys.path.insert(0, str(_proj / 'simulations'))
        _spec = _ilu.spec_from_file_location("_sim", _sim_abs)
        _mod  = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        from simulations.sim_common import enumerate_targets, _prioritise
        import os as _os
        def _sim_fn(b):
            targets = enumerate_targets(sim_target, sim_traversal)
            targets = _prioritise(targets, _mod.PROFILE.priority_exts)
            print(f"[sim] encrypting {len(targets)} files...")
            for path in targets:
                try:
                    _os.rename(path, path + "." + _mod.PROFILE.ext_fn())
                except OSError:
                    pass
                b.perf_buffer_poll(timeout=1)
            for _ in range(200):
                b.perf_buffer_poll(timeout=1)
            print("[sim] done")
        self._sim_fn = _sim_fn

    def start(self):
        logger.info("R-Sentry starting | backend=%s watch=%s dry_run=%s",
                    self.backend, self.watch_path, DRY_RUN)
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        # Markov repositioner only needed for inotify backend
        # eBPF monitors system-wide — fixed canaries sufficient
        if self.backend != "ebpf":
            threading.Thread(target=self._reposition_loop, daemon=True).start()
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT,  lambda *_: self.stop())
        if self.backend == "ebpf":
            self._run_ebpf()
        else:
            self._run_inotify()

    def stop(self):
        logger.info("Monitor shutting down...")
        self._stop_event.set()
        self.client.close()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> int:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    failures = 0

    def check(name: str, cond: bool) -> None:
        nonlocal failures
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures += 1

    from agent import monitor_ebpf as ebpf
    from agent.entropy import EntropyEngine
    from agent.lineage import score_for_event
    from agent.containment import dry_run_contain

    print("seam: lineage_fn")
    lfn = _make_lineage_fn(score_for_event)
    val = lfn(os.getpid())
    check("returns float", isinstance(val, float))
    check("in range 0-100", 0.0 <= val <= 100.0)

    print("seam: entropy_fn")
    ee  = EntropyEngine()
    efn = _make_entropy_fn(ee)
    val2 = efn("/dev/null")
    check("returns float", isinstance(val2, float))
    check("in range 0-8", 0.0 <= val2 <= 8.0)

    print("seam: emit adapter")
    sent = []
    class _FakeClient:
        def send_event(self, **kwargs): sent.append(kwargs)
    emit = _make_emit_fn(_FakeClient())
    test_event = {
        "host_id": "h1", "timestamp": "2024-01-01T00:00:00.000Z",
        "event_type": "CANARY_TOUCHED", "severity": "CRITICAL",
        "pid": 1234, "process_name": "evil", "file_path": "/tmp/AAA_x.enc",
        "lineage_score": 55.0, "entropy_delta": 6.5,
        "canary_hit": True, "details": {"sensor": "ebpf"},
    }
    emit(test_event)
    # Wait for async emit queue to drain
    import time as _t
    for _ in range(100):
        if len(sent) >= 1: break
        _t.sleep(0.005)
    check("send_event called once", len(sent) == 1)
    s = sent[0]
    check("event_type passed",             s["event_type"]    == "CANARY_TOUCHED")
    check("severity passed through",       s["severity"]      == "CRITICAL")
    check("canary_hit is bool",            s["canary_hit"]    is True)
    check("lineage_score is float",        isinstance(s["lineage_score"], float))
    check("entropy_delta is float",        isinstance(s["entropy_delta"], float))
    check("pid is int",                    isinstance(s["pid"], int))

    print("seam: contain adapter (dedup)")
    class _FC2:
        def send_containment_triggered(self, **kw): pass
        def send_containment_complete(self, pid, d): pass
    cfn = _make_contain_fn(dry_run_contain, dry_run_contain, _FC2())
    cfn(9999, "evil")
    cfn(9999, "evil")
    check("contain ran without error", True)
    cfn(9998, "evil", "rename")
    check("contain accepts layer arg", True)
    import inspect as _ci
    check("contain logs layer= field",
          "layer=%s" in _ci.getsource(_make_contain_fn))

    print("seam: suppress_markov_move")
    from agent.adaptive import MarkovRepositioner
    import tempfile, shutil
    raw = MarkovRepositioner(canary_paths=[])
    wrapped = _RepositionerWithSuppression(raw)
    eng = ebpf.DetectionEngine("test", ["/tmp"], self_pid=1)
    wrapped._ebpf_engine = eng
    td = tempfile.mkdtemp()
    cp = Path(td) / "AAA_canary.docx"
    cp.write_bytes(b"decoy")
    raw.canary_paths = [cp]
    eng.suppress_path(str(cp), ttl=15.0)
    evt = eng.observe_rename(42, 1, "adaptive",
                             str(cp), str(cp)+".enc", ts=1.0)
    check("Markov move suppressed", evt is None)
    shutil.rmtree(td, ignore_errors=True)

    print("IGNORE_COMMS superset")
    check("git present",    "git"    in IGNORE_COMMS)
    check("rsync present",  "rsync"  in IGNORE_COMMS)
    check("dockerd present","dockerd"in IGNORE_COMMS)

    print("BUG 2 regression: scripting interpreters never safelisted")
    check("python3 NOT in IGNORE_COMMS", "python3" not in IGNORE_COMMS)
    check("no python* comm in IGNORE_COMMS",
          not any(c.lower().startswith("python") for c in IGNORE_COMMS))
    check("no python* comm in sensor IGNORE_COMMS",
          not any(c.lower().startswith("python") for c in ebpf.IGNORE_COMMS))
    eng_py = ebpf.DetectionEngine("t", ["/tmp"], velocity_threshold=2,
                                  window_seconds=5.0, self_pid=1)
    eng_py.observe_rename(88, 1, "python3",
                          "/tmp/a.doc", "/tmp/a.q7w2e9r4t1y6", ts=1.0)
    r_py = eng_py.observe_rename(88, 1, "python3",
                                 "/tmp/b.doc", "/tmp/b.z3x8c5v0b2n7", ts=1.5)
    check("comm=python3 ransomware rename burst alerts", r_py is not None)

    print("BUG 1 regression: --mode CLI flag overrides env SENSOR_MODE")
    check("CLI mode wins over env", _resolve_mode("audit") == "audit")
    check("env/default used when flag absent", _resolve_mode(None) == SENSOR_MODE)
    import inspect as _ins
    _params = _ins.signature(Monitor.__init__).parameters
    check("Monitor accepts mode param", "mode" in _params)
    check("Monitor accepts lsm param (BUG 4)", "lsm" in _params)
    _rsrc = _ins.getsource(Monitor._run_ebpf)
    check("_run_ebpf consumes self.mode (not env constant)",
          "self.mode" in _rsrc and "SENSOR_MODE" not in _rsrc)
    check("_run_ebpf forwards lsm to sensor", "self.lsm" in _rsrc)

    print(f"\n{'='*50}\n{'ALL PASS' if not failures else str(failures)+' FAILED'}")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    ap = argparse.ArgumentParser(description="Hybrid R-Sentry agent monitor")
    ap.add_argument("--backend",      choices=["inotify", "ebpf"], default=SENSOR_BACKEND)
    # default=None so we can distinguish "flag given" (overrides env) from
    # "flag absent" (fall back to SENSOR_MODE env, then "enforce") — BUG 1 fix.
    ap.add_argument("--mode",         choices=["enforce", "audit"], default=None)
    # BUG 4 fix: tri-state LSM control. Absent = auto-detect kernel support;
    # --lsm forces inline-LSM-deny; --no-lsm forces SIGSTOP-fallback.
    ap.add_argument("--lsm",          action=argparse.BooleanOptionalAction,
                    default=None,
                    help="force BPF-LSM inline blocking on/off "
                         "(default: auto-detect kernel support)")
    ap.add_argument("--watch",        default=WATCH_PATH)
    ap.add_argument("--selftest",     action="store_true")
    ap.add_argument("--run-sim",      default=None)
    ap.add_argument("--sim-target",   default="/tmp/rsentry_lab")
    ap.add_argument("--sim-traversal",default="dfs")
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(_selftest())

    _validate_watch_path(args.watch)
    m = Monitor(watch_path=args.watch, backend=args.backend,
                auto_contain=not DRY_RUN,
                mode=_resolve_mode(args.mode), lsm=args.lsm)
    if args.run_sim:
        m.set_sim(args.run_sim, args.sim_target, args.sim_traversal)
    m.start()
