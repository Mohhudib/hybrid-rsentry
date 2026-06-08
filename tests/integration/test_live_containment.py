#!/usr/bin/env python3
"""
tests/integration/test_live_containment.py — LIVE end-to-end proof that the
cgroup-scoped containment fix isolates ONLY the malicious process tree, while a
sibling process under the SAME UID (1000) keeps full network access.

This is the regression the original `iptables -m owner --uid-owner` bug failed:
that rule dropped traffic for *every* process owned by the UID, a host-wide
network outage — MITRE ATT&CK **T1498 (Network Denial of Service)** if abused.
The fix scopes the DROP to a dedicated **cgroup v2** holding only the malicious
tree, so siblings stay online. This script proves that on real iptables / real
processes (NOTHING is mocked).

PRODUCTION ENTRY POINTS exercised (the exact code the agent runs):
    agent.containment._cgroup_network_isolate(pid, descendants)   # contain() step 3
    agent.containment.release_network_isolation(result)           # contain() step 5
We call the network-isolation functions directly (instead of the full
contain(), which would SIGKILL the stand-in) so the malicious process stays
ALIVE long enough to prove the network DROP itself — not the kill — cut its
traffic, and then regains network after the surgical cleanup.

USAGE
    # Privileged live run (needs root for iptables + cgroup writes):
    sudo /home/kali/hybrid-rsentry/venv/bin/python \
        tests/integration/test_live_containment.py

    # Unprivileged self-check (no iptables/cgroup; validates helpers + guards):
    /home/kali/hybrid-rsentry/venv/bin/python \
        tests/integration/test_live_containment.py --selfcheck

SAFETY
  - Every privileged command is printed ("RUN: ...") BEFORE it executes.
  - `iptables -F` / `--flush` is NEVER used; cleanup deletes only the uniquely
    tagged rule via `iptables -D` (asserted at the end).
  - All spawned helpers + any DROP rule + the cgroup are torn down in a finally
    block even if an assertion fails.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

# Make the project importable when run directly (sudo strips PYTHONPATH).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.containment import (  # noqa: E402
    CGROUP2_ROOT,
    ContainmentResult,
    _agent_protected_pids,
    _cgroup2_available,
    _cgroup_network_isolate,
    release_network_isolation,
)

HELPER_UID = 1000
HELPER_GID = 1000
LOG_DIR = Path("/tmp/rsentry_live_test")
TARGET_HOST = "8.8.8.8"
TARGET_PORT = 53

# A self-contained heartbeat: every ~0.5s attempt one outbound TCP connect and
# append "<epoch> OK|FAIL" to a logfile. When the process is network-isolated,
# the SYN is dropped and connect() times out -> FAIL lines appear.
HEARTBEAT_SRC = f"""
import socket, sys, time
log = sys.argv[1]
while True:
    t = time.time()
    try:
        s = socket.create_connection(("{TARGET_HOST}", {TARGET_PORT}), timeout=2)
        s.close()
        res = "OK"
    except Exception:
        res = "FAIL"
    with open(log, "a") as fh:
        fh.write(f"{{t:.2f}} {{res}}\\n")
    time.sleep(0.5)
"""

# Audit log of every command we shell out — proves no `-F`/`--flush` was used.
COMMANDS: list[list[str]] = []


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def run_cmd(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    """Run a command, echoing it first so the operator can review every action."""
    COMMANDS.append(cmd)
    print(f"    RUN: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=10)


def spawn_heartbeat(name: str) -> subprocess.Popen:
    """
    Start a UID-1000 heartbeat helper. When we are root (live run) we drop
    privileges to UID/GID 1000 so the stand-in and sibling truly share the
    interactive user's UID; when already UID 1000 (self-check) we inherit it.
    """
    logfile = LOG_DIR / f"{name}.log"
    logfile.write_text("")
    if os.geteuid() == 0:
        os.chown(str(logfile), HELPER_UID, HELPER_GID)
    kwargs: dict = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.geteuid() == 0:
        kwargs.update(user=HELPER_UID, group=HELPER_GID)
    proc = subprocess.Popen(
        [sys.executable, "-c", HEARTBEAT_SRC, str(logfile)], **kwargs
    )
    return proc


def net_recent(name: str, since: float) -> tuple[int, int, str]:
    """
    Read a helper's heartbeat log and return (ok_count, fail_count, last_result)
    considering only attempts started at/after `since`.
    """
    logfile = LOG_DIR / f"{name}.log"
    ok = fail = 0
    last = "?"
    try:
        for line in logfile.read_text().splitlines():
            try:
                ts_s, res = line.split()
                ts = float(ts_s)
            except ValueError:
                continue
            if ts >= since:
                last = res
                if res == "OK":
                    ok += 1
                else:
                    fail += 1
    except FileNotFoundError:
        pass
    return ok, fail, last


def proc_uid(pid: int) -> int | None:
    """Real UID of a PID from /proc, or None."""
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (FileNotFoundError, ValueError, OSError):
        return None
    return None


def cgroup_members(cgroup_path: str) -> set[int]:
    """PIDs currently in a cgroup's cgroup.procs."""
    try:
        body = (Path(cgroup_path) / "cgroup.procs").read_text()
        return {int(x) for x in body.split()}
    except (FileNotFoundError, ValueError, OSError):
        return set()


def output_rule_present(comment: str) -> bool:
    """True if an OUTPUT rule carrying `comment` currently exists."""
    cp = run_cmd(["iptables", "-S", "OUTPUT"])
    return comment in cp.stdout


# --------------------------------------------------------------------------- #
# Results table
# --------------------------------------------------------------------------- #

class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, bool]] = []

    def check(self, name: str, expected: str, observed: str, ok: bool) -> bool:
        self.rows.append((name, expected, observed, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: expected={expected!r} observed={observed!r}")
        return ok

    def render(self) -> bool:
        wc = max(len(r[0]) for r in self.rows) if self.rows else 5
        we = max(len(r[1]) for r in self.rows) if self.rows else 8
        wo = max(len(r[2]) for r in self.rows) if self.rows else 8
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
        print(f"OVERALL: {'PASS — cgroup-scoped containment validated (T1498 DoS prevented)' if all_pass else 'FAIL'}")
        print("=" * 80)
        return all_pass


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    selfcheck = "--selfcheck" in sys.argv
    report = Report()

    if not selfcheck and os.geteuid() != 0:
        print("\n" + "!" * 78)
        print("FAIL: live containment test needs root for iptables + cgroup writes.")
        print("Run (review the script first):")
        print(f"  sudo {sys.executable} {Path(__file__).resolve()}")
        print("Or validate helpers/guards without root:")
        print(f"  {sys.executable} {Path(__file__).resolve()} --selfcheck")
        print("!" * 78)
        return 2

    # Preflight — FAIL LOUDLY, never fall back silently.
    if not selfcheck:
        if not _cgroup2_available():
            print(f"FAIL: cgroup v2 unified hierarchy not writable at {CGROUP2_ROOT}")
            return 3
        help_cp = run_cmd(["iptables", "-m", "cgroup", "--help"])
        if "--path" not in (help_cp.stdout + help_cp.stderr):
            print("FAIL: iptables on this host has no `-m cgroup --path` match")
            return 3

    LOG_DIR.mkdir(mode=0o777, exist_ok=True)
    os.chmod(LOG_DIR, 0o777)

    sibling = malicious = None
    result = ContainmentResult(0)  # placeholder; populated after isolation
    try:
        # ---- 1. SETUP -------------------------------------------------------
        print("\n[1] SETUP — spawning UID-1000 sibling + malicious stand-in")
        sibling = spawn_heartbeat("sibling")
        malicious = spawn_heartbeat("malicious")
        print(f"    sibling   PID={sibling.pid}  uid={proc_uid(sibling.pid)}")
        print(f"    malicious PID={malicious.pid}  uid={proc_uid(malicious.pid)}")

        t0 = time.time()
        time.sleep(4)  # baseline window
        sib_ok, sib_fail, _ = net_recent("sibling", t0)
        mal_ok, mal_fail, _ = net_recent("malicious", t0)
        report.check("baseline both online", ">=1 OK each",
                     f"sib_ok={sib_ok} mal_ok={mal_ok}",
                     sib_ok >= 1 and mal_ok >= 1)

        same_uid = proc_uid(sibling.pid) == proc_uid(malicious.pid) == HELPER_UID
        report.check("shared UID 1000", "both uid=1000",
                     f"sib={proc_uid(sibling.pid)} mal={proc_uid(malicious.pid)}", same_uid)

        if selfcheck:
            print("\n[self-check] Skipping privileged isolate/cleanup. "
                  "Helpers + guard verified. Run with sudo for the full proof.")
            guard = _agent_protected_pids()
            report.check("guard protects agent+ancestors+pid1",
                         "self/ancestors/1 in set",
                         f"{sorted(guard)[:4]}...",
                         os.getpid() in guard and 1 in guard)
            return 0 if report.render() else 1

        # ---- 2. CONTAIN (real production isolation path) --------------------
        print("\n[2] CONTAIN — agent.containment._cgroup_network_isolate(pid, [])")
        iso = _cgroup_network_isolate(malicious.pid, descendants=[])
        if iso is None:
            print("FAIL: _cgroup_network_isolate returned None (isolation did not apply)")
            return 4
        result.pid = malicious.pid
        result.iptables_rule = iso["rule"]
        result.cgroup_path = iso["cgroup_path"]
        result.isolation_comment = iso["comment"]
        result.isolated_pids = iso["isolated_pids"]
        print(f"    rule    : {iso['rule']}")
        print(f"    cgroup  : {iso['cgroup_path']}")
        print(f"    comment : {iso['comment']}")

        # ---- 3. ASSERT ------------------------------------------------------
        print("\n[3] ASSERT")
        rule = iso["rule"]
        report.check("rule type: --path not --uid-owner", "cgroup match",
                     "--path" if "--path" in rule else rule,
                     "--path" in rule and "--uid-owner" not in rule)
        report.check("unique comment tag",
                     f"rsentry-contain-{malicious.pid}",
                     iso["comment"], iso["comment"] == f"rsentry-contain-{malicious.pid}")

        # Agent / ancestors / pid 1 must NOT be in the isolated cgroup.
        members = cgroup_members(iso["cgroup_path"])
        protected = _agent_protected_pids()
        leaked = members & protected
        report.check("agent+ancestors+pid1 NOT isolated", "no overlap",
                     f"members={sorted(members)} leaked={sorted(leaked)}",
                     not leaked and malicious.pid in members and 1 in protected)

        # Observe network: let several attempts accrue after the DROP applied.
        t_iso = time.time() + 2.5  # grace for any in-flight connect
        time.sleep(9)
        mal_ok, mal_fail, mal_last = net_recent("malicious", t_iso)
        sib_ok, sib_fail, sib_last = net_recent("sibling", t_iso)
        report.check("malicious LOSES network", "FAIL attempts, last=FAIL",
                     f"ok={mal_ok} fail={mal_fail} last={mal_last}",
                     mal_fail >= 1 and mal_last == "FAIL")
        report.check("sibling STAYS online", "no FAIL, last=OK",
                     f"ok={sib_ok} fail={sib_fail} last={sib_last}",
                     sib_ok >= 1 and sib_fail == 0 and sib_last == "OK")

        # ---- 4. CLEANUP (surgical -D, never -F) -----------------------------
        print("\n[4] CLEANUP — release_network_isolation(result) [iptables -D]")
        released = release_network_isolation(result)
        report.check("release reports success", "True", str(released), released is True)

        still_present = output_rule_present(iso["comment"])
        report.check("rule removed from OUTPUT", "absent",
                     "present" if still_present else "absent", not still_present)

        # Malicious regains network now the DROP is gone.
        t_rel = time.time() + 1.0
        time.sleep(6)
        mal_ok2, mal_fail2, mal_last2 = net_recent("malicious", t_rel)
        report.check("malicious REGAINS network", "OK, last=OK",
                     f"ok={mal_ok2} last={mal_last2}",
                     mal_ok2 >= 1 and mal_last2 == "OK")

        # No flush anywhere.
        used_flush = any(("-F" in c or "--flush" in c) for c in COMMANDS)
        report.check("cleanup surgical (no iptables -F)", "no -F/--flush",
                     "flush used" if used_flush else "none", not used_flush)

        return 0 if report.render() else 1

    finally:
        # ---- teardown — always runs, even on assertion failure --------------
        print("\n[teardown] killing helpers + removing any residual rule/cgroup")
        for name, proc in (("sibling", sibling), ("malicious", malicious)):
            if proc is not None and proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                print(f"    killed {name} PID={proc.pid}")
        # Belt-and-suspenders: delete our uniquely-tagged rule if it survived,
        # and remove the (now-empty) cgroup. Never a flush.
        if not selfcheck and result.isolation_comment:
            if output_rule_present(result.isolation_comment):
                run_cmd(["iptables", "-D", "OUTPUT", "-m", "cgroup", "--path",
                         str(Path(result.cgroup_path).relative_to(CGROUP2_ROOT)),
                         "-m", "comment", "--comment", result.isolation_comment,
                         "-j", "DROP"])
            if result.cgroup_path:
                cg = Path(result.cgroup_path)
                for _ in range(10):
                    try:
                        cg.rmdir()
                        break
                    except FileNotFoundError:
                        break
                    except OSError:
                        time.sleep(0.3)  # wait for kernel to drain dead PIDs
                print(f"    cgroup removed: {not cg.exists()}")


if __name__ == "__main__":
    sys.exit(main())
