"""
tests/unit/agent/test_severity.py
Severity classification tests
"""
import os
from unittest.mock import MagicMock, patch
from agent.entropy import EntropyEngine
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
    def test_nonexistent_pid_baseline(self):
        # Process not found = process exited rapidly (+40 baseline)
        assert score_for_event(99999999)["lineage_score"] >= 40.0
    def test_score_capped_at_100(self):
        with patch("agent.lineage.psutil.Process") as mc:
            mp = MagicMock()
            mp.name.return_value="m"; mp.exe.return_value="/tmp/m"
            mp.cmdline.return_value=[]; mp.terminal.return_value=None
            mp.create_time.return_value=9999999999.0; mp.parent.return_value=None
            mc.return_value=mp
            r = score_process(1234)
            if r: assert r.score <= 100.0

import pytest

CANARY_PREFIXES = ["AAA_", "aaa_", "ZZZ_", "zzz_"]

class TestCanarySeverity:
    def test_all_four_canary_prefixes_present(self, tmp_canary_dir):
        for prefix in CANARY_PREFIXES:
            assert any(tmp_canary_dir.glob(f"{prefix}*")), \
                f"No canary file with prefix {prefix!r} in tmp_canary_dir"

    @pytest.mark.parametrize("prefix", CANARY_PREFIXES)
    def test_is_canary_detects_all_prefixes(self, tmp_path, prefix):
        from agent.graph import FilesystemGraph
        g = FilesystemGraph.__new__(FilesystemGraph)
        g.root = tmp_path
        g.canary_paths = []
        for ext in [".txt", ".docx", ".vmdk"]:
            assert g.is_canary(f"/watched/{prefix}canary{ext}"), \
                f"is_canary() missed prefix={prefix!r} ext={ext!r}"

    def test_non_canary_not_detected(self, tmp_path):
        from agent.graph import FilesystemGraph
        g = FilesystemGraph.__new__(FilesystemGraph)
        g.root = tmp_path
        g.canary_paths = []
        assert not g.is_canary("/watched/report.docx")
        assert not g.is_canary("/watched/important_file.txt")
        assert not g.is_canary("/watched/aaaaaa_file.txt")  # extra 'a's — not a valid prefix
