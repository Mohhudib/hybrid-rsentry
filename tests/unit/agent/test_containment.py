"""
tests/unit/agent/test_containment.py
Unit tests for agent/containment.py — the SIGSTOP → evidence → iptables DROP →
SIGKILL pipeline. Every destructive syscall (os.kill, subprocess.run, psutil)
is mocked; no real process or firewall rule is ever touched.
"""
import signal
import subprocess

import psutil
import pytest

from agent import containment
from agent.containment import (
    ContainmentResult, _sigstop, _sigkill, _get_descendants,
    _freeze_tree, _kill_tree, _capture_evidence,
    _cgroup_network_isolate, _move_into_cgroup, _agent_protected_pids,
    release_network_isolation, contain, dry_run_contain,
)


# --- ContainmentResult ------------------------------------------------------

class TestContainmentResult:
    def test_to_dict_keys(self):
        d = ContainmentResult(123).to_dict()
        for k in ["pid", "descendants", "stopped", "evidence_dir",
                  "iptables_rule", "killed", "error", "timestamp", "tree_size"]:
            assert k in d

    def test_tree_size_counts_root_plus_descendants(self):
        r = ContainmentResult(1)
        r.descendants = [2, 3, 4]
        assert r.to_dict()["tree_size"] == 4

    def test_evidence_dir_serialised_as_str_or_none(self):
        r = ContainmentResult(1)
        assert r.to_dict()["evidence_dir"] is None


# --- _sigstop ---------------------------------------------------------------

class TestSigstop:
    def test_success(self, mocker):
        kill = mocker.patch("agent.containment.os.kill")
        assert _sigstop(999) is True
        kill.assert_called_once_with(999, signal.SIGSTOP)

    def test_process_gone_returns_false(self, mocker):
        mocker.patch("agent.containment.os.kill", side_effect=ProcessLookupError)
        assert _sigstop(999) is False

    def test_permission_denied_returns_false(self, mocker):
        mocker.patch("agent.containment.os.kill", side_effect=PermissionError)
        assert _sigstop(999) is False


# --- _get_descendants -------------------------------------------------------

class TestGetDescendants:
    def test_returns_child_pids(self, mocker):
        proc = mocker.MagicMock()
        proc.children.return_value = [
            mocker.MagicMock(pid=11), mocker.MagicMock(pid=12)]
        mocker.patch("agent.containment.psutil.Process", return_value=proc)
        assert _get_descendants(10) == [11, 12]

    def test_no_such_process_returns_empty(self, mocker):
        mocker.patch("agent.containment.psutil.Process",
                     side_effect=psutil.NoSuchProcess(10))
        assert _get_descendants(10) == []


# --- _freeze_tree (two-sweep) -----------------------------------------------

class TestFreezeTree:
    def test_stops_root_and_descendants(self, mocker):
        mocker.patch("agent.containment._sigstop", return_value=True)
        mocker.patch("agent.containment._get_descendants", return_value=[20, 21])
        root_stopped, descendants, stopped = _freeze_tree(10)
        assert root_stopped is True
        assert descendants == [20, 21]
        assert set(stopped) == {20, 21}

    def test_second_sweep_catches_new_children(self, mocker):
        mocker.patch("agent.containment._sigstop", return_value=True)
        # first enumeration: [20]; second sweep: [20, 22] → 22 is new
        mocker.patch("agent.containment._get_descendants",
                     side_effect=[[20], [20, 22]])
        root_stopped, descendants, stopped = _freeze_tree(10)
        assert descendants == [20, 22]
        assert set(stopped) == {20, 22}

    def test_root_stop_failure_still_reports(self, mocker):
        mocker.patch("agent.containment._sigstop", return_value=False)
        mocker.patch("agent.containment._get_descendants", return_value=[])
        root_stopped, descendants, stopped = _freeze_tree(10)
        assert root_stopped is False
        assert stopped == []


# --- _sigkill ---------------------------------------------------------------

class TestSigkill:
    def test_success_then_reaped(self, mocker):
        # first call sends SIGKILL, subsequent os.kill(pid,0) raises → reaped
        mocker.patch("agent.containment.os.kill",
                     side_effect=[None, ProcessLookupError])
        mocker.patch("agent.containment.time.sleep")
        assert _sigkill(999) is True

    def test_already_dead_returns_true(self, mocker):
        mocker.patch("agent.containment.os.kill", side_effect=ProcessLookupError)
        assert _sigkill(999) is True

    def test_permission_denied_returns_false(self, mocker):
        mocker.patch("agent.containment.os.kill", side_effect=PermissionError)
        assert _sigkill(999) is False


# --- _kill_tree -------------------------------------------------------------

class TestKillTree:
    def test_kills_descendants_before_root(self, mocker):
        order = []
        def fake_kill(pid):
            order.append(pid)
            return True
        mocker.patch("agent.containment._sigkill", side_effect=fake_kill)
        root_killed, killed = _kill_tree(1, [2, 3])
        assert root_killed is True
        assert killed == [2, 3]
        # root (1) killed last
        assert order[-1] == 1
        assert order[:2] == [2, 3]


# --- _cgroup_network_isolate (cgroup-scoped, NOT uid-wide) -------------------

class TestCgroupNetworkIsolate:
    """
    The replacement for the buggy --uid-owner DROP. Isolation must be scoped to
    a dedicated cgroup holding ONLY the malicious tree, never to the owning UID.
    """

    def _setup(self, mocker, tmp_path, *, agent_pids=(424242, 1)):
        # cgroup v2 is "available"; mkdir/move land in tmp_path, not real sysfs.
        mocker.patch("agent.containment.CGROUP2_ROOT", tmp_path)
        mocker.patch("agent.containment._cgroup2_available", return_value=True)
        mocker.patch("agent.containment._agent_protected_pids",
                     return_value=set(agent_pids))
        moved: list[int] = []
        mocker.patch("agent.containment._move_into_cgroup",
                     side_effect=lambda d, pids: (moved.extend(pids), pids)[1])
        run = mocker.patch("agent.containment.subprocess.run")
        return moved, run

    def test_rule_is_cgroup_scoped_not_uid(self, mocker, tmp_path):
        moved, run = self._setup(mocker, tmp_path)
        iso = _cgroup_network_isolate(999, [1001, 1002])
        assert iso is not None
        # The scoping flaw is gone: no UID matching anywhere in the rule.
        assert "--uid-owner" not in iso["rule"]
        assert "owner" not in iso["rule"]
        # Matched on cgroup membership + tagged for surgical cleanup.
        assert "--path" in iso["rule"] and "rsentry-contain-999" in iso["rule"]
        assert "--comment" in iso["rule"]
        assert iso["comment"] == "rsentry-contain-999"
        # Only the malicious tree was moved into the cgroup.
        assert moved == [999, 1001, 1002]
        run.assert_called_once()

    def test_refuses_to_isolate_agent_own_tree(self, mocker, tmp_path):
        # pid 999 is the agent (or an ancestor) → must never self-isolate.
        _, run = self._setup(mocker, tmp_path, agent_pids=(999, 1))
        assert _cgroup_network_isolate(999, []) is None
        run.assert_not_called()

    def test_excludes_protected_pids_from_move(self, mocker, tmp_path):
        # A descendant that is actually the agent must be dropped from the move set.
        moved, _ = self._setup(mocker, tmp_path, agent_pids=(424242, 1, 1002))
        iso = _cgroup_network_isolate(999, [1001, 1002])
        assert iso is not None
        assert 1002 not in moved
        assert moved == [999, 1001]

    def test_skips_when_cgroup2_unavailable(self, mocker, tmp_path):
        mocker.patch("agent.containment.CGROUP2_ROOT", tmp_path)
        mocker.patch("agent.containment._cgroup2_available", return_value=False)
        mocker.patch("agent.containment._agent_protected_pids", return_value={1})
        run = mocker.patch("agent.containment.subprocess.run")
        assert _cgroup_network_isolate(999, []) is None
        run.assert_not_called()

    def test_iptables_failure_returns_none(self, mocker, tmp_path):
        self._setup(mocker, tmp_path)
        err = subprocess.CalledProcessError(1, "iptables")
        err.stderr = b"boom"
        mocker.patch("agent.containment.subprocess.run", side_effect=err)
        assert _cgroup_network_isolate(999, []) is None


# --- release_network_isolation (surgical cleanup — never iptables -F) --------

class TestReleaseNetworkIsolation:
    def test_deletes_only_tagged_rule(self, mocker, tmp_path):
        mocker.patch("agent.containment.CGROUP2_ROOT", tmp_path)
        cgdir = tmp_path / "rsentry-contain-999"
        cgdir.mkdir()
        run = mocker.patch("agent.containment.subprocess.run")
        r = ContainmentResult(999)
        r.cgroup_path = str(cgdir)
        r.isolation_comment = "rsentry-contain-999"
        assert release_network_isolation(r) is True
        assert r.isolation_released is True
        args = run.call_args[0][0]
        assert args[:3] == ["iptables", "-D", "OUTPUT"]   # delete, never flush
        assert "-F" not in args
        assert "--comment" in args and "rsentry-contain-999" in args

    def test_noop_without_comment(self, mocker):
        run = mocker.patch("agent.containment.subprocess.run")
        assert release_network_isolation(ContainmentResult(1)) is False
        run.assert_not_called()

    def test_idempotent(self, mocker, tmp_path):
        run = mocker.patch("agent.containment.subprocess.run")
        r = ContainmentResult(1)
        r.isolation_comment = "rsentry-contain-1"
        r.isolation_released = True
        assert release_network_isolation(r) is True
        run.assert_not_called()


# --- REGRESSION: sibling under same UID keeps network access -----------------

class TestSiblingNotIsolatedRegression:
    """
    Regression guard for the host-wide DoS bug: containing a malicious PID must
    NOT cut off a sibling process that merely shares the same UID.

    Old behaviour: `iptables --uid-owner 1000 -j DROP` dropped traffic for every
    UID-1000 process (the whole user session). New behaviour: only PIDs moved
    into the dedicated cgroup are matched, so the sibling — never moved — keeps
    network access.
    """

    def test_sibling_same_uid_retains_network(self, mocker, tmp_path):
        malicious_pid, malicious_child = 999, 1001
        sibling_pid = 1500            # same UID (1000), unrelated legitimate proc

        mocker.patch("agent.containment.CGROUP2_ROOT", tmp_path)
        mocker.patch("agent.containment._cgroup2_available", return_value=True)
        mocker.patch("agent.containment._agent_protected_pids", return_value={1})

        moved: list[int] = []
        mocker.patch("agent.containment._move_into_cgroup",
                     side_effect=lambda d, pids: (moved.extend(pids), pids)[1])
        run = mocker.patch("agent.containment.subprocess.run")

        iso = _cgroup_network_isolate(malicious_pid, [malicious_child])
        assert iso is not None

        # 1. The DROP rule matches cgroup membership, not a UID — so it can never
        #    blanket-block every process owned by UID 1000.
        assert "--uid-owner" not in iso["rule"]
        assert "--path" in iso["rule"]

        # 2. Only the malicious tree was placed in the cgroup the rule matches.
        assert moved == [malicious_pid, malicious_child]

        # 3. The sibling was never moved → not in the matched cgroup → still has
        #    network access. This is the exact failure the bug caused.
        assert sibling_pid not in moved
        assert sibling_pid not in iso["isolated_pids"]


# --- _capture_evidence ------------------------------------------------------

class TestCaptureEvidence:
    def test_creates_dir_mode_0700(self, mocker, tmp_path):
        # point a non-existent /proc pid so capture short-circuits cleanly
        out = tmp_path / "evid"
        evidence_dir, captured = _capture_evidence(424242, out)
        assert evidence_dir == out
        assert out.exists()
        # 0o700 — only owner can read forensic artifacts
        assert (out.stat().st_mode & 0o777) == 0o700
        assert captured == []  # /proc/424242 does not exist


# --- contain() orchestration ------------------------------------------------

class TestContainPipeline:
    def test_full_pipeline_order_and_result(self, mocker, tmp_path):
        order = []
        mocker.patch("agent.containment._freeze_tree",
                     side_effect=lambda pid: (order.append("freeze"), (True, [55], [55]))[1])
        mocker.patch("agent.containment._capture_evidence",
                     side_effect=lambda pid, d=None: (order.append("evidence"), (tmp_path, ["f1"]))[1])
        mocker.patch("agent.containment.os.geteuid", return_value=0)
        mocker.patch(
            "agent.containment._cgroup_network_isolate",
            side_effect=lambda pid, desc: (order.append("isolate"), {
                "rule": "RULE", "cgroup_path": "/sys/fs/cgroup/rsentry-contain-123",
                "comment": "rsentry-contain-123", "isolated_pids": [pid] + desc,
            })[1])
        release = mocker.patch("agent.containment.release_network_isolation",
                               side_effect=lambda r: (order.append("release"), True)[1])
        mocker.patch("agent.containment._kill_tree",
                     side_effect=lambda pid, desc: (order.append("kill"), (True, [55]))[1])
        mocker.patch("agent.containment.time.sleep")

        result = contain(123)
        # ordering: freeze → evidence → isolate → kill → release
        assert order[0] == "freeze"
        assert order[-1] == "release"
        assert order.index("isolate") < order.index("kill") < order.index("release")
        assert result.stopped is True
        assert result.iptables_rule == "RULE"
        assert result.cgroup_path == "/sys/fs/cgroup/rsentry-contain-123"
        assert result.killed is True
        assert result.descendants == [55]
        assert result.to_dict()["tree_size"] == 2
        release.assert_called_once()

    def test_skips_iptables_when_not_root(self, mocker, tmp_path):
        mocker.patch("agent.containment._freeze_tree", return_value=(True, [], []))
        mocker.patch("agent.containment._capture_evidence", return_value=(tmp_path, []))
        mocker.patch("agent.containment.os.geteuid", return_value=1000)
        iso = mocker.patch("agent.containment._cgroup_network_isolate")
        mocker.patch("agent.containment._kill_tree", return_value=(True, []))
        mocker.patch("agent.containment.time.sleep")
        result = contain(123)
        iso.assert_not_called()
        assert result.iptables_rule is None

    def test_skip_iptables_flag(self, mocker, tmp_path):
        mocker.patch("agent.containment._freeze_tree", return_value=(True, [], []))
        mocker.patch("agent.containment._capture_evidence", return_value=(tmp_path, []))
        mocker.patch("agent.containment.os.geteuid", return_value=0)
        iso = mocker.patch("agent.containment._cgroup_network_isolate")
        mocker.patch("agent.containment._kill_tree", return_value=(True, []))
        mocker.patch("agent.containment.time.sleep")
        contain(123, skip_iptables=True)
        iso.assert_not_called()

    def test_sigstop_total_failure_sets_error(self, mocker, tmp_path):
        mocker.patch("agent.containment._freeze_tree", return_value=(False, [], []))
        mocker.patch("agent.containment._capture_evidence", return_value=(tmp_path, []))
        mocker.patch("agent.containment.os.geteuid", return_value=1000)
        mocker.patch("agent.containment._kill_tree", return_value=(False, []))
        mocker.patch("agent.containment.time.sleep")
        result = contain(123)
        assert result.error == "SIGSTOP failed for entire tree"


# --- dry_run_contain --------------------------------------------------------

class TestDryRun:
    def test_no_kill_marks_dry_run(self, mocker, tmp_path):
        mocker.patch("agent.containment._capture_evidence", return_value=(tmp_path, []))
        kill = mocker.patch("agent.containment.os.kill")
        result = dry_run_contain(123)
        assert result.iptables_rule == "DRY_RUN"
        assert result.stopped is True
        assert result.killed is True
        kill.assert_not_called()  # dry run must never signal
