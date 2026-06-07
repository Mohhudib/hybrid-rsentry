"""
tests/unit/agent/test_adaptive.py
Unit tests for agent/adaptive.py — MarkovRepositioner
"""
from unittest.mock import MagicMock
from agent.adaptive import MarkovRepositioner

class TestObserve:
    def test_adds_state(self):
        r = MarkovRepositioner([]); r.observe("/a")
        assert "/a" in r._state_index
    def test_multiple_states(self):
        r = MarkovRepositioner([])
        r.observe("/a"); r.observe("/b"); r.observe("/c")
        assert len(r._state_index) == 3
    def test_n_obs_zero_with_one_event(self):
        r = MarkovRepositioner([]); r.observe("/a")
        assert r._n_observations == 0
    def test_n_obs_increments(self):
        r = MarkovRepositioner([])
        r.observe("/a"); r.observe("/b")
        assert r._n_observations == 1
    def test_counts_updated(self):
        r = MarkovRepositioner([])
        r.observe("/a"); r.observe("/b")
        assert r._counts.sum() == 1

class TestShouldReposition:
    def test_false_no_observations(self):
        assert MarkovRepositioner([]).should_reposition() is False
    def test_false_below_min(self):
        r = MarkovRepositioner([])
        for _ in range(3): r.observe("/a"); r.observe("/b")
        assert r.should_reposition() is False
    def test_true_strong_pattern(self):
        r = MarkovRepositioner([])
        for _ in range(20): r.observe("/a"); r.observe("/b")
        assert r.should_reposition() is True

class TestPredictedHotspots:
    def test_empty_before_min_obs(self):
        r = MarkovRepositioner([])
        r.observe("/a"); r.observe("/b")
        assert r.predicted_hotspots() == []
    def test_returns_list_after_enough(self):
        r = MarkovRepositioner([])
        for _ in range(10): r.observe("/a"); r.observe("/b")
        assert isinstance(r.predicted_hotspots(), list)
    def test_top_n_respected(self):
        r = MarkovRepositioner([])
        for _ in range(5):
            for d in ["/a","/b","/c","/d","/e"]: r.observe(d)
        assert len(r.predicted_hotspots(top_n=2)) <= 2

class TestReposition:
    def test_returns_list(self, tmp_path):
        c = tmp_path/"AAA_test.txt"; c.write_bytes(b"x")
        r = MarkovRepositioner([c])
        assert isinstance(r.reposition(), list)
    def test_returns_original_no_hotspots(self, tmp_path):
        c = tmp_path/"AAA_test.txt"; c.write_bytes(b"x")
        r = MarkovRepositioner([c])
        assert c in r.reposition()
    def test_updates_fs_graph(self, tmp_path):
        c = tmp_path/"AAA_test.txt"; c.write_bytes(b"x")
        r = MarkovRepositioner([c])
        fg = MagicMock()
        r.reposition(fs_graph=fg)
        assert hasattr(fg, "canary_paths")

class TestSummary:
    def test_returns_dict(self):
        assert isinstance(MarkovRepositioner([]).summary(), dict)
    def test_required_keys(self):
        s = MarkovRepositioner([]).summary()
        for k in ["n_states","n_observations","should_reposition","top_hotspots"]:
            assert k in s
    def test_initial_values(self):
        s = MarkovRepositioner([]).summary()
        assert s["n_states"] == 0
        assert s["n_observations"] == 0
        assert s["should_reposition"] is False


class TestMarkovGate:
    """Monitor.start() must not launch the Markov repositioner for the eBPF backend."""

    def test_ebpf_backend_skips_repositioner(self, tmp_path):
        import threading
        from unittest.mock import patch

        watch = tmp_path / "watch"
        watch.mkdir()

        started_targets = []

        original_start = threading.Thread.start

        def _capture_start(self_thread):
            started_targets.append(getattr(self_thread, '_target', None))

        with patch.object(threading.Thread, 'start', _capture_start):
            with patch('agent.monitor.Monitor._run_ebpf', return_value=None):
                with patch('agent.monitor.Monitor._heartbeat_loop', return_value=None):
                    with patch('agent.monitor._validate_watch_path', return_value=None):
                        import signal as _sig
                        with patch('signal.signal'):
                            from agent.monitor import Monitor
                            m = Monitor.__new__(Monitor)
                            m.backend = 'ebpf'
                            m.watch_path = str(watch)
                            m._stop_event = threading.Event()
                            m._repositioner = None
                            m._sim_fn = None
                            m._agent_client = None
                            m.start()

        reposition_targets = [
            t for t in started_targets
            if t is not None and getattr(t, '__name__', '') == '_reposition_loop'
        ]
        assert reposition_targets == [], \
            "eBPF backend must not start the Markov repositioner thread"
