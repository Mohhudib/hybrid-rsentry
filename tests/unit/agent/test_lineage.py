"""
tests/unit/agent/test_lineage.py
Unit tests for agent/lineage.py
"""
import pytest, os
from unittest.mock import MagicMock, patch
import psutil
from agent.lineage import (
    ProcessLineage, _sha256_of_exe, _collect_ancestors,
    score_process, score_for_event,
    WEIGHT_SUSPICIOUS_PARENT, WEIGHT_SUSPICIOUS_PATH, WEIGHT_DEEP_ANCESTRY,
)

class TestProcessLineage:
    def test_to_dict_has_required_keys(self):
        l = ProcessLineage(1234); l.name="p"; l.exe="/bin/p"
        l.cmdline=["p"]; l.ancestors=[]; l.score=10.0; l.reasons=[]
        d = l.to_dict()
        for k in ["pid","name","exe","cmdline","ancestors","lineage_score","sha256","reasons"]:
            assert k in d
    def test_score_rounded(self):
        l = ProcessLineage(1); l.score=33.3333
        assert l.to_dict()["lineage_score"] == round(33.3333,2)
    def test_cmdline_joined(self):
        l = ProcessLineage(1); l.cmdline=["python3","-m","monitor"]
        assert l.to_dict()["cmdline"] == "python3 -m monitor"
    def test_initial_score_zero(self):
        assert ProcessLineage(1).score == 0.0
    def test_initial_reasons_empty(self):
        assert ProcessLineage(1).reasons == []

class TestSha256OfExe:
    def test_valid_file_returns_64char_hex(self, tmp_path):
        f = tmp_path/"exe"; f.write_bytes(b"binary")
        r = _sha256_of_exe(str(f))
        assert r and len(r)==64
    def test_nonexistent_returns_none(self):
        assert _sha256_of_exe("/no/such/file") is None
    def test_same_content_same_hash(self, tmp_path):
        f1=tmp_path/"a"; f2=tmp_path/"b"
        f1.write_bytes(b"same"); f2.write_bytes(b"same")
        assert _sha256_of_exe(str(f1)) == _sha256_of_exe(str(f2))
    def test_different_content_different_hash(self, tmp_path):
        f1=tmp_path/"a"; f2=tmp_path/"b"
        f1.write_bytes(b"aaa"); f2.write_bytes(b"bbb")
        assert _sha256_of_exe(str(f1)) != _sha256_of_exe(str(f2))

class TestCollectAncestors:
    def test_no_parent_empty_lists(self):
        m = MagicMock(); m.parent.return_value = None
        names, paths = _collect_ancestors(m)
        assert names == [] and paths == []
    def test_single_parent_captured(self):
        m = MagicMock()
        p = MagicMock(); p.name.return_value="sshd"; p.exe.return_value="/sbin/sshd"; p.parent.return_value=None
        m.parent.return_value = p
        names, paths = _collect_ancestors(m)
        assert "sshd" in names
    def test_access_denied_handled(self):
        m = MagicMock(); m.parent.side_effect = psutil.AccessDenied(0)
        names, paths = _collect_ancestors(m)
        assert names == []

class TestScoreForEvent:
    def test_returns_dict(self):
        assert isinstance(score_for_event(os.getpid()), dict)
    def test_required_keys(self):
        r = score_for_event(os.getpid())
        for k in ["lineage_score","process_name","exe","ancestors","sha256","reasons"]:
            assert k in r
    def test_nonexistent_pid_zero_score(self):
        r = score_for_event(99999999)
        assert r["lineage_score"] == 0.0
        assert "process_not_found" in r["reasons"]
    def test_score_is_float(self):
        assert isinstance(score_for_event(os.getpid())["lineage_score"], float)
    def test_ancestors_is_list(self):
        assert isinstance(score_for_event(os.getpid())["ancestors"], list)
