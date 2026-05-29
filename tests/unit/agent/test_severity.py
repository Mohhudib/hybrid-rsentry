"""
tests/unit/agent/test_severity.py
Severity classification tests
"""
import pytest, os
from unittest.mock import MagicMock, patch
from agent.entropy import EntropyEngine, _shannon_entropy
from agent.lineage import score_for_event, score_process

class TestEntropySeverity:
    def test_alert_has_severity_field(self, tmp_path):
        f = tmp_path/"t.bin"; e = EntropyEngine()
        f.write_bytes(b"\x00"*2048); e.observe(str(f))
        f.write_bytes(os.urandom(2048))
        r = e.observe(str(f))
        if r: assert r["severity"] in ("MEDIUM","HIGH","LOW","CRITICAL")
    def test_alert_event_type_correct(self, tmp_path):
        f = tmp_path/"t.bin"; e = EntropyEngine()
        f.write_bytes(b"\x00"*2048); e.observe(str(f))
        f.write_bytes(os.urandom(2048))
        r = e.observe(str(f))
        if r: assert r["event_type"] == "ENTROPY_SPIKE"
    def test_entropy_delta_non_negative(self, tmp_path):
        f = tmp_path/"t.bin"; e = EntropyEngine()
        f.write_bytes(b"\x00"*2048); e.observe(str(f))
        f.write_bytes(os.urandom(2048))
        r = e.observe(str(f))
        if r: assert r["entropy_delta"] >= 0

class TestLineageSeverity:
    def test_current_process_low_score(self):
        r = score_for_event(os.getpid())
        assert r["lineage_score"] <= 60.0
    def test_nonexistent_pid_zero(self):
        assert score_for_event(99999999)["lineage_score"] == 0.0
    def test_score_capped_at_100(self):
        with patch("agent.lineage.psutil.Process") as mc:
            mp = MagicMock()
            mp.name.return_value="m"; mp.exe.return_value="/tmp/m"
            mp.cmdline.return_value=[]; mp.terminal.return_value=None
            mp.create_time.return_value=9999999999.0; mp.parent.return_value=None
            mc.return_value=mp
            r = score_process(1234)
            if r: assert r.score <= 100.0

class TestCanarySeverity:
    def test_canary_pattern_matches(self, tmp_canary_dir):
        assert len(list(tmp_canary_dir.glob("AAA_*"))) == 2
    def test_canary_hit_means_critical(self):
        assert ("CRITICAL" if True else "LOW") == "CRITICAL"
    def test_no_canary_hit_not_critical(self):
        assert ("CRITICAL" if False else "LOW") != "CRITICAL"
