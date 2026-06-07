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
    _freeze_tree, _kill_tree, _iptables_drop, _capture_evidence,
    contain, dry_run_contain,
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


# --- _iptables_drop (TOCTOU UID read from /proc/PID/status) ------------------

class TestIptablesDrop:
    def _fake_status(self, mocker, uid):
        fake_path = mocker.patch("agent.containment.Path")
        fake_path.return_value.read_text.return_value = (
            f"Name:\tevil\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        return fake_path

    def test_drops_for_non_root_uid(self, mocker):
        self._fake_status(mocker, 1000)
        run = mocker.patch("agent.containment.subprocess.run")
        rule = _iptables_drop(999)
        assert rule is not None
        assert "--uid-owner" in rule and "1000" in rule
        run.assert_called_once()

    def test_skips_uid_zero(self, mocker):
        self._fake_status(mocker, 0)
        run = mocker.patch("agent.containment.subprocess.run")
        assert _iptables_drop(999) is None
        run.assert_not_called()  # never block root — would block the agent

    def test_missing_status_returns_none(self, mocker):
        fake_path = mocker.patch("agent.containment.Path")
        fake_path.return_value.read_text.side_effect = FileNotFoundError
        assert _iptables_drop(999) is None

    def test_iptables_binary_missing_returns_none(self, mocker):
        self._fake_status(mocker, 1000)
        mocker.patch("agent.containment.subprocess.run",
                     side_effect=FileNotFoundError)
        assert _iptables_drop(999) is None

    def test_iptables_failure_returns_none(self, mocker):
        self._fake_status(mocker, 1000)
        err = subprocess.CalledProcessError(1, "iptables")
        err.stderr = b"boom"
        mocker.patch("agent.containment.subprocess.run", side_effect=err)
        assert _iptables_drop(999) is None


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
        mocker.patch("agent.containment._iptables_drop",
                     side_effect=lambda pid: (order.append("iptables"), "RULE")[1])
        mocker.patch("agent.containment._kill_tree",
                     side_effect=lambda pid, desc: (order.append("kill"), (True, [55]))[1])
        mocker.patch("agent.containment.time.sleep")

        result = contain(123)
        # ordering: freeze → evidence → iptables → kill
        assert order[0] == "freeze"
        assert order[-1] == "kill"
        assert order.index("freeze") < order.index("kill")
        assert result.stopped is True
        assert result.iptables_rule == "RULE"
        assert result.killed is True
        assert result.descendants == [55]
        assert result.to_dict()["tree_size"] == 2

    def test_skips_iptables_when_not_root(self, mocker, tmp_path):
        mocker.patch("agent.containment._freeze_tree", return_value=(True, [], []))
        mocker.patch("agent.containment._capture_evidence", return_value=(tmp_path, []))
        mocker.patch("agent.containment.os.geteuid", return_value=1000)
        drop = mocker.patch("agent.containment._iptables_drop")
        mocker.patch("agent.containment._kill_tree", return_value=(True, []))
        mocker.patch("agent.containment.time.sleep")
        result = contain(123)
        drop.assert_not_called()
        assert result.iptables_rule is None

    def test_skip_iptables_flag(self, mocker, tmp_path):
        mocker.patch("agent.containment._freeze_tree", return_value=(True, [], []))
        mocker.patch("agent.containment._capture_evidence", return_value=(tmp_path, []))
        mocker.patch("agent.containment.os.geteuid", return_value=0)
        drop = mocker.patch("agent.containment._iptables_drop")
        mocker.patch("agent.containment._kill_tree", return_value=(True, []))
        mocker.patch("agent.containment.time.sleep")
        contain(123, skip_iptables=True)
        drop.assert_not_called()

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
