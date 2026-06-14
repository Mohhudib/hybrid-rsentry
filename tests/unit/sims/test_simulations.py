"""
tests/unit/sims/test_simulations.py
Safety and correctness tests for simulation scripts
"""
import inspect
import re
import pytest
import simulations.sim_dfs as sim_dfs
import simulations.sim_random as sim_random
import simulations.sim_depth as sim_depth
import simulations.sim_akira as sim_akira
import simulations.sim_qilin as sim_qilin
import simulations.sim_lockbit as sim_lockbit
import simulations.sim_all as sim_all

_ALL_SIMS = [sim_dfs, sim_random, sim_depth, sim_akira, sim_qilin, sim_lockbit, sim_all]
_LEGACY_SIMS = [sim_dfs, sim_random, sim_depth]
_PROD_SIMS = [sim_akira, sim_qilin, sim_lockbit]

class TestImports:
    def test_sim_dfs_importable(self):
        assert hasattr(sim_dfs, "__file__")
    def test_sim_random_importable(self):
        assert hasattr(sim_random, "__file__")
    def test_sim_depth_importable(self):
        assert hasattr(sim_depth, "__file__")
    def test_sim_akira_importable(self):
        assert hasattr(sim_akira, "__file__")
    def test_sim_qilin_importable(self):
        assert hasattr(sim_qilin, "__file__")
    def test_sim_lockbit_importable(self):
        assert hasattr(sim_lockbit, "__file__")
    def test_sim_all_importable(self):
        assert hasattr(sim_all, "__file__")

class TestSafety:
    def test_no_sigstop_in_sims(self):
        for m in _ALL_SIMS:
            assert "SIGSTOP" not in inspect.getsource(m), f"{m.__name__} has SIGSTOP"
    def test_no_agent_monitor_import(self):
        # Sims must not import the live watchdog `agent.monitor` — importing it
        # pulls in containment side effects (SIGSTOP/iptables) and the real
        # monitor loop. The pure, side-effect-free DetectionEngine in
        # `agent.monitor_ebpf` is the designed validation target (session_09)
        # and is explicitly allowed, so match `agent.monitor` only when it is
        # NOT immediately followed by `_ebpf`.
        forbidden = re.compile(r"agent\.monitor(?!_ebpf)")
        for m in _ALL_SIMS:
            assert not forbidden.search(inspect.getsource(m)), \
                f"{m.__name__} imports the live agent.monitor watchdog"
    def test_no_canary_files_touched(self):
        for m in _LEGACY_SIMS:
            src = inspect.getsource(m)
            code_lines = [l for l in src.splitlines() if not l.strip().startswith("#") and not l.strip().startswith('"""')]
            assert not any("open" in l and "AAA_" in l for l in code_lines), f"{m.__name__} opens canary files"
    def test_sim_dir_under_tmp(self):
        if hasattr(sim_dfs, "TEST_DIR"):
            assert str(sim_dfs.TEST_DIR).startswith("/tmp")

class TestProductionSimProfiles:
    """Production sims must expose a PROFILE with the expected fields."""

    @pytest.mark.parametrize("mod,expected_mode", [
        (sim_akira,   "intermittent"),
        (sim_qilin,   "percent"),
        (sim_lockbit, "two_pass"),
    ])
    def test_profile_mode(self, mod, expected_mode):
        assert hasattr(mod, "PROFILE"), f"{mod.__name__} missing PROFILE"
        assert mod.PROFILE.mode == expected_mode, \
            f"{mod.__name__}.PROFILE.mode expected {expected_mode!r}, got {mod.PROFILE.mode!r}"

    @pytest.mark.parametrize("mod", _PROD_SIMS)
    def test_profile_has_ext_fn(self, mod):
        assert callable(mod.PROFILE.ext_fn), f"{mod.__name__}.PROFILE.ext_fn must be callable"
        ext = mod.PROFILE.ext_fn()
        assert isinstance(ext, str) and len(ext) > 0, \
            f"{mod.__name__}.PROFILE.ext_fn() must return a non-empty string"

    @pytest.mark.parametrize("mod", _PROD_SIMS)
    def test_uses_main_for_for_safe_orchestration(self, mod):
        src = inspect.getsource(mod)
        assert "main_for" in src, \
            f"{mod.__name__} should use sim_common.main_for() for git-repo guard, backup, and restore"
