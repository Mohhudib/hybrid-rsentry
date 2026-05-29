"""
tests/unit/sims/test_simulations.py
Safety and correctness tests for simulation scripts
"""
import pytest, inspect
import simulations.sim_dfs as sim_dfs
import simulations.sim_random as sim_random
import simulations.sim_depth as sim_depth

class TestImports:
    def test_sim_dfs_importable(self):
        assert hasattr(sim_dfs, "__file__")
    def test_sim_random_importable(self):
        assert hasattr(sim_random, "__file__")
    def test_sim_depth_importable(self):
        assert hasattr(sim_depth, "__file__")

class TestSafety:
    def test_no_sigstop_in_sims(self):
        for m in [sim_dfs, sim_random, sim_depth]:
            assert "SIGSTOP" not in inspect.getsource(m), f"{m.__name__} has SIGSTOP"
    def test_no_agent_monitor_import(self):
        for m in [sim_dfs, sim_random, sim_depth]:
            assert "agent.monitor" not in inspect.getsource(m)
    def test_no_canary_files_touched(self):
        import re
        for m in [sim_dfs, sim_random, sim_depth]:
            src = inspect.getsource(m)
            # Check no code actually opens/writes AAA_ files (comments allowed)
            code_lines = [l for l in src.splitlines() if not l.strip().startswith("#") and not l.strip().startswith('"""')]
            assert not any("open" in l and "AAA_" in l for l in code_lines), f"{m.__name__} opens canary files"
    def test_sim_dir_under_tmp(self):
        if hasattr(sim_dfs, "TEST_DIR"):
            assert str(sim_dfs.TEST_DIR).startswith("/tmp")
