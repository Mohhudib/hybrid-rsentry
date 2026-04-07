"""
monitor.py — Watchdog/inotify canary file watcher.
Orchestrates graph, entropy, lineage, adaptive, containment, and client.
"""
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from watchdog.events import (
    FileClosedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from agent.adaptive import MarkovRepositioner
from agent.client import AgentClient
from agent.containment import contain, ContainmentResult
from agent.entropy import EntropyEngine
from agent.graph import FilesystemGraph
from agent.lineage import score_for_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------
WATCH_PATH = os.getenv("WATCH_PATH", "/home")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
HOST_ID = os.getenv("HOST_ID", "kali-endpoint-01")
CANARY_STRATEGY = os.getenv("CANARY_STRATEGY", "bfs")
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
REPOSITION_INTERVAL = int(os.getenv("REPOSITION_INTERVAL", "300"))  # seconds
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

# Thresholds for combined alert
COMBINED_CRITICAL = 70.0
COMBINED_HIGH = 40.0


def _combined_score(lineage_score: float, entropy_delta: float) -> float:
    """Weighted combination of lineage and entropy signals (0–100)."""
    entropy_norm = min(entropy_delta / 8.0, 1.0) * 100
    return lineage_score * 0.6 + entropy_norm * 0.4


class RsentryEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler.
    For every file-system event it:
      1. Checks if the path is a canary → CRITICAL
      2. Runs entropy analysis
      3. Scores process lineage
      4. Decides combined severity
      5. Ships event to backend
      6. Triggers containment if needed
    """

    def __init__(
        self,
        fs_graph: FilesystemGraph,
        entropy_engine: EntropyEngine,
        repositioner: MarkovRepositioner,
        client: AgentClient,
        auto_contain: bool = True,
    ):
        super().__init__()
        self.fs_graph = fs_graph
        self.entropy_engine = entropy_engine
        self.repositioner = repositioner
        self.client = client
        self.auto_contain = auto_contain
        self._contained_pids: set[int] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _process_info(self, pid: int) -> dict:
        try:
            import psutil
            proc = psutil.Process(pid)
            return {"name": proc.name(), "exe": proc.exe()}
        except Exception:
            return {"name": "unknown", "exe": ""}

    def _handle_event(self, event_type: str, src_path: str, pid: int = 0):
        canary_hit = self.fs_graph.is_canary(src_path)

        # Lineage
        lineage_data = score_for_event(pid) if pid else {
            "lineage_score": 0.0, "process_name": "unknown",
            "exe": "", "ancestors": [], "sha256": None, "reasons": [],
        }
        lineage_score = lineage_data["lineage_score"]
        process_name = lineage_data["process_name"] or "unknown"

        # Entropy
        entropy_alert = self.entropy_engine.observe(src_path) if not canary_hit else None
        entropy_delta = entropy_alert["entropy_delta"] if entropy_alert else 0.0

        # Record directory access for Markov model
        parent_dir = str(Path(src_path).parent)
        self.repositioner.observe(parent_dir)

        # Combined score
        score = _combined_score(lineage_score, entropy_delta)

        # Determine actual event_type and severity
        if canary_hit:
            final_event = "CANARY_TOUCHED"
            severity = "CRITICAL"
        elif entropy_alert and lineage_score >= 40:
            final_event = "COMBINED_ALERT"
            severity = "CRITICAL" if score >= COMBINED_CRITICAL else "HIGH"
        elif entropy_alert:
            final_event = "ENTROPY_SPIKE"
            severity = entropy_alert.get("severity", "MEDIUM")
        elif lineage_score >= 40:
            final_event = "PROCESS_ANOMALY"
            severity = "CRITICAL" if score >= COMBINED_CRITICAL else "HIGH"
        else:
            # Low-signal event — skip to avoid noise
            return

        details = {
            "original_event": event_type,
            "combined_score": round(score, 2),
            "lineage_reasons": lineage_data.get("reasons", []),
            "ancestors": lineage_data.get("ancestors", []),
            "sha256": lineage_data.get("sha256"),
        }

        self.client.send_event(
            event_type=final_event,
            pid=pid,
            process_name=process_name,
            file_path=src_path,
            lineage_score=lineage_score,
            entropy_delta=entropy_delta,
            canary_hit=canary_hit,
            details=details,
            severity=severity,
        )

        # Auto-containment on CRITICAL
        if severity == "CRITICAL" and self.auto_contain and pid > 0:
            self._trigger_containment(pid, process_name, src_path,
                                       lineage_score, entropy_delta)

    def _trigger_containment(
        self, pid: int, process_name: str, file_path: str,
        lineage_score: float, entropy_delta: float,
    ):
        with self._lock:
            if pid in self._contained_pids:
                return
            self._contained_pids.add(pid)

        logger.critical("Initiating containment for PID %d (%s)", pid, process_name)
        self.client.send_containment_triggered(
            pid=pid, process_name=process_name, file_path=file_path,
            lineage_score=lineage_score, entropy_delta=entropy_delta,
        )

        if DRY_RUN:
            from agent.containment import dry_run_contain
            result: ContainmentResult = dry_run_contain(pid)
        else:
            result = contain(pid)

        self.client.send_containment_complete(pid, result.to_dict())

    # ------------------------------------------------------------------
    # Watchdog event dispatch
    # ------------------------------------------------------------------

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_event("modified", event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_event("created", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        # Canary deletion is also a strong signal
        if self.fs_graph.is_canary(event.src_path):
            self.client.send_event(
                event_type="CANARY_TOUCHED",
                pid=0,
                process_name="unknown",
                file_path=event.src_path,
                lineage_score=0.0,
                entropy_delta=0.0,
                canary_hit=True,
                details={"sub_type": "deleted"},
                severity="CRITICAL",
            )

    def on_moved(self, event):
        if event.is_directory:
            return
        if self.fs_graph.is_canary(event.src_path):
            self.client.send_event(
                event_type="CANARY_TOUCHED",
                pid=0,
                process_name="unknown",
                file_path=event.src_path,
                lineage_score=0.0,
                entropy_delta=0.0,
                canary_hit=True,
                details={"sub_type": "moved", "dest": event.dest_path},
                severity="CRITICAL",
            )


# ---------------------------------------------------------------------------
# Main monitor orchestrator
# ---------------------------------------------------------------------------

class Monitor:
    def __init__(self, watch_path: str = WATCH_PATH, auto_contain: bool = True):
        self.watch_path = watch_path
        self.auto_contain = auto_contain

        self.fs_graph = FilesystemGraph(root=watch_path)
        self.entropy_engine = EntropyEngine()
        self.client = AgentClient(backend_url=BACKEND_URL, host_id=HOST_ID)

        # Place canaries; repositioner seeded with initial paths
        canaries = self.fs_graph.place_canaries(strategy=CANARY_STRATEGY)
        self.repositioner = MarkovRepositioner(canary_paths=canaries)

        self.handler = RsentryEventHandler(
            fs_graph=self.fs_graph,
            entropy_engine=self.entropy_engine,
            repositioner=self.repositioner,
            client=self.client,
            auto_contain=auto_contain,
        )
        self.observer = Observer()
        self._stop_event = threading.Event()

    def _heartbeat_loop(self):
        while not self._stop_event.is_set():
            self.client.send_heartbeat()
            self._stop_event.wait(HEARTBEAT_INTERVAL)

    def _reposition_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(REPOSITION_INTERVAL)
            if self.repositioner.should_reposition():
                logger.info("Markov repositioning triggered")
                self.repositioner.reposition(fs_graph=self.fs_graph)

    def start(self):
        logger.info("Hybrid R-Sentry monitor starting | watch=%s dry_run=%s",
                    self.watch_path, DRY_RUN)

        self.observer.schedule(self.handler, self.watch_path, recursive=True)
        self.observer.start()

        # Background threads
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._reposition_loop, daemon=True).start()

        # Handle signals
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())

        logger.info("Monitor running. Press Ctrl+C to stop.")
        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        finally:
            self.stop()

    def stop(self):
        logger.info("Monitor shutting down...")
        self._stop_event.set()
        self.observer.stop()
        self.observer.join()
        self.client.close()
        logger.info("Monitor stopped.")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    monitor = Monitor(watch_path=WATCH_PATH, auto_contain=not DRY_RUN)
    monitor.start()
