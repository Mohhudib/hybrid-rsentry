#!/usr/bin/env python3
"""
diag_one_trial.py — diagnose the post-SIGSTOP containment halt under the harness.
ROOT-ONLY. Run it under the SAME interpreter the harness uses for the agent:

    cd ~/hybrid-rsentry && set -a && source .env && set +a
    sudo -E ~/hybrid-rsentry/venv/bin/python tests/evaluation/diag_one_trial.py

WHY a dedicated diagnostic: the agent's contain worker swallows exceptions
(agent/monitor_ebpf.py `_contain_worker`: `except Exception: pass`), so when
containment.contain() raises mid-pipeline the traceback NEVER reaches the agent
log. The full agent log can only show which step logged LAST — not the error. So:

  PART 0  env snapshot (cwd / euid / cgroup2 / evidence base / protected pids)
  PART A  probe each psutil call _capture_evidence() makes on a UID-1000 victim,
          then call containment.contain(victim) DIRECTLY and print the traceback
          if it raises — this is the exception the agent worker hides.
  PART B  run ONE real Akira trial via the harness with the agent log PRESERVED,
          then print the FULL agent log (so we can see Tree frozen / Evidence
          captured / Network isolation / SIGKILL ordering in the live agent).

Everything is cleaned up: the victim is killed, and any rsentry-contain iptables
rule / cgroup created during PART A is removed surgically (never a flush).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.evaluation.harness import (          # reuse the proven helpers
    _contain_rules, _cgroup_dirs, _run, EVAL_BASE,
)


def _proc_state(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
    except (FileNotFoundError, IndexError, OSError):
        return "?"


def _cleanup_contain_residue() -> None:
    """Remove any rsentry-contain rule/cgroup left by a partial PART A run."""
    for ln in _contain_rules():
        spec = ln.split()
        if spec and spec[0] == "-A":
            _run(["iptables", "-D"] + spec[1:])
    for cg in _cgroup_dirs():
        try:
            cg.rmdir()
        except OSError:
            pass


def part0_env() -> None:
    print("=" * 72)
    print("PART 0 — environment snapshot")
    print("=" * 72)
    from agent import containment as C
    print(f"  cwd            = {os.getcwd()}")
    print(f"  euid           = {os.geteuid()}  (need 0)")
    print(f"  sys.executable = {sys.executable}")
    print(f"  cgroup2 avail  = {C._cgroup2_available()}  (CGROUP2_ROOT={C.CGROUP2_ROOT})")
    print(f"  EVIDENCE_BASE  = {C.EVIDENCE_BASE}  exists={C.EVIDENCE_BASE.exists()} "
          f"writable={os.access(C.EVIDENCE_BASE.parent, os.W_OK)}")
    try:
        prot = sorted(C._agent_protected_pids())
        print(f"  protected pids = {prot[:8]}{' ...' if len(prot) > 8 else ''}")
    except Exception as exc:  # noqa: BLE001
        print(f"  protected pids = ERROR {exc!r}")


def part_a() -> None:
    print("\n" + "=" * 72)
    print("PART A — direct containment.contain() on a UID-1000 victim")
    print("=" * 72)
    import psutil
    from agent import containment

    # A python victim with open files + a real exe path mirrors the sim's /proc
    # footprint better than bare `sleep`.
    victim = subprocess.Popen(
        ["/usr/bin/python3", "-c",
         "import time; fs=[open('/etc/hostname') for _ in range(3)]; time.sleep(120)"],
        user=1000, group=1000,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.4)
    print(f"  victim pid={victim.pid} state={_proc_state(victim.pid)} "
          f"uid={_proc_uid(victim.pid)}")

    # (a) Probe each psutil accessor _capture_evidence() calls — pinpoints which
    #     one raises and whether it is one the (NoSuchProcess, AccessDenied)
    #     handler at containment.py:204 would actually catch.
    print("\n  psutil probes (as _capture_evidence calls them):")
    p = psutil.Process(victim.pid)
    for name in ("name", "exe", "cmdline", "open_files",
                 "net_connections", "memory_info", "cpu_times", "create_time"):
        try:
            getattr(p, name)()
            print(f"    psutil.{name}() .......... OK")
        except Exception as exc:  # noqa: BLE001
            caught = isinstance(exc, (psutil.NoSuchProcess, psutil.AccessDenied))
            print(f"    psutil.{name}() .......... RAISED {type(exc).__name__}: {exc} "
                  f"[{'caught by handler' if caught else 'NOT caught → would abort pipeline'}]")

    # (b) Run the full pipeline directly — surfaces the traceback the agent hides.
    print("\n  calling containment.contain(victim) directly ...")
    try:
        res = containment.contain(victim.pid)
        d = res.to_dict()
        print("  contain() RETURNED (no exception). Summary:")
        for k in ("stopped", "descendants", "evidence_dir", "iptables_rule",
                  "cgroup_path", "isolation_comment", "isolated_pids",
                  "killed", "error"):
            print(f"      {k} = {d.get(k)}")
    except Exception:  # noqa: BLE001
        print("  contain() RAISED — THIS is the traceback the agent worker swallows:\n")
        traceback.print_exc()
    finally:
        for s in (signal.SIGCONT, signal.SIGKILL):
            try:
                os.kill(victim.pid, s)
            except OSError:
                pass
        try:
            victim.wait(timeout=5)
        except Exception:
            pass
        _cleanup_contain_residue()
        print("  PART A cleanup done (victim killed, residue removed)")


def _proc_uid(pid: int):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (FileNotFoundError, ValueError, OSError):
        return None
    return None


def part_b() -> None:
    print("\n" + "=" * 72)
    print("PART B — one Akira trial via the harness, FULL agent log preserved")
    print("=" * 72)
    from tests.evaluation.corpus import malicious_samples as M
    from tests.evaluation.harness import run_trial

    wl = M.build_workload(M.malicious_plan(1)[0])
    res = run_trial(wl, lsm=True, enforce=True, response_timeout=15.0,
                    preserve_log=True)
    d = res.to_dict()
    print("  RESULT:")
    for k in ("sample_id", "detected", "contained", "layer_fired",
              "t_detect", "t_sigstop", "t_isolate", "t_kill", "t_complete",
              "agent_restart_id"):
        print(f"      {k} = {d[k]}")

    log_path = EVAL_BASE / f"agent_{res.agent_restart_id}.log"
    print(f"\n  --- FULL AGENT LOG ({log_path}) ---")
    if log_path.exists():
        print(log_path.read_text())
        log_path.unlink(missing_ok=True)
    else:
        print("  (agent log missing — preserve_log may have failed)")


def main() -> int:
    if os.geteuid() != 0:
        print("FAIL: run under sudo (root). See the module docstring.")
        return 2
    part0_env()
    part_a()
    part_b()
    print("\n" + "=" * 72)
    print("DIAGNOSIS GUIDE")
    print("=" * 72)
    print("  * PART A traceback present  → containment.contain() raises in this")
    print("    environment (the agent worker swallows it). The psutil-probe line")
    print("    marked 'NOT caught' is the culprit accessor in _capture_evidence.")
    print("  * PART A clean + PART B halts after 'SIGSTOP sent' → compare the FULL")
    print("    log's last line: 'Tree frozen' missing ⇒ _freeze_tree; 'Evidence")
    print("    captured' missing ⇒ _capture_evidence; both present but no 'Network")
    print("    isolation applied' ⇒ isolation step.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
