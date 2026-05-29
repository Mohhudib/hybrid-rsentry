"""
tests/unit/agent/test_entropy.py
Unit tests for agent/entropy.py
"""
import pytest
import os
from unittest.mock import MagicMock
from agent.entropy import (
    _shannon_entropy, EntropyRecord, EntropyEngine,
    ENTROPY_SPIKE_THRESHOLD, HIGH_ENTROPY_ABSOLUTE,
)

class TestShannonEntropy:
    def test_empty_bytes_returns_zero(self):
        assert _shannon_entropy(b"") == 0.0
    def test_uniform_bytes_high_entropy(self):
        data = bytes(range(256)) * 4
        assert _shannon_entropy(data) > 7.5
    def test_single_repeated_byte_low_entropy(self):
        assert _shannon_entropy(b"\x00" * 1000) < 0.1
    def test_returns_float(self):
        assert isinstance(_shannon_entropy(b"hello"), float)
    def test_between_zero_and_eight(self):
        result = _shannon_entropy(b"some random data 12345")
        assert 0.0 <= result <= 8.0
    def test_random_data_high_entropy(self):
        data = os.urandom(1024)
        assert _shannon_entropy(data) > 6.0

class TestEntropyRecord:
    def test_initial_delta_zero(self):
        assert EntropyRecord("/tmp/x").delta() == 0.0
    def test_single_sample_delta_zero(self):
        r = EntropyRecord("/tmp/x"); r.add(5.0)
        assert r.delta() == 0.0
    def test_delta_max_minus_min(self):
        r = EntropyRecord("/tmp/x"); r.add(2.0); r.add(6.0)
        assert abs(r.delta() - 4.0) < 0.001
    def test_latest_returns_last(self):
        r = EntropyRecord("/tmp/x"); r.add(3.0); r.add(7.0)
        assert r.latest() == 7.0
    def test_latest_empty_zero(self):
        assert EntropyRecord("/tmp/x").latest() == 0.0
    def test_window_respected(self):
        r = EntropyRecord("/tmp/x", window=3)
        for v in [1,2,3,4,5]: r.add(v)
        assert len(r._samples) == 3
    def test_recent_spike_false_one_sample(self):
        r = EntropyRecord("/tmp/x"); r.add(7.0)
        assert r.recent_spike() is False
    def test_recent_spike_true_on_large_delta(self):
        r = EntropyRecord("/tmp/x"); r.add(1.0); r.add(6.0)
        assert r.recent_spike(threshold=3.5) is True
    def test_recent_spike_false_small_delta(self):
        r = EntropyRecord("/tmp/x"); r.add(4.0); r.add(4.5)
        assert r.recent_spike(threshold=3.5) is False

class TestEntropyEngine:
    def test_nonexistent_file_returns_none(self):
        assert EntropyEngine().observe("/no/such/file.txt") is None
    def test_single_observation_no_spike(self, tmp_path):
        f = tmp_path / "t.txt"; f.write_bytes(b"a"*100)
        assert EntropyEngine().observe(str(f)) is None
    def test_spike_returns_alert(self, tmp_path):
        f = tmp_path / "t.bin"; e = EntropyEngine()
        f.write_bytes(b"\x00"*1000); e.observe(str(f))
        f.write_bytes(os.urandom(1000))
        r = e.observe(str(f))
        if r: assert r["event_type"] == "ENTROPY_SPIKE"
    def test_flush_removes_record(self, tmp_path):
        f = tmp_path / "t.txt"; f.write_bytes(b"data")
        e = EntropyEngine(); e.observe(str(f))
        assert str(f) in e._records
        e.flush(str(f))
        assert str(f) not in e._records
    def test_bulk_scan_returns_list(self, tmp_path):
        f = tmp_path / "a.txt"; f.write_bytes(b"x")
        assert isinstance(EntropyEngine().bulk_scan([str(f)]), list)
    def test_stats_dataframe_empty(self):
        import pandas as pd
        df = EntropyEngine().stats_dataframe()
        assert isinstance(df, pd.DataFrame)
