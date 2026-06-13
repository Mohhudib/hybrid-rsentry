"""
test_simulations.py — smoke tests confirming all simulation modules are importable
and that sim_all references the correct family list.
"""
import importlib


def test_sim_common_importable():
    mod = importlib.import_module("simulations.sim_common")
    assert hasattr(mod, "populate_corpus")
    assert hasattr(mod, "run_attack")


def test_sim_lockbit_importable():
    mod = importlib.import_module("simulations.sim_lockbit")
    assert hasattr(mod, "PROFILE")


def test_sim_akira_importable():
    mod = importlib.import_module("simulations.sim_akira")
    assert hasattr(mod, "PROFILE")


def test_sim_qilin_importable():
    mod = importlib.import_module("simulations.sim_qilin")
    assert hasattr(mod, "PROFILE")


def test_sim_all_has_all_families():
    from simulations.sim_all import _FAMILY_MODULES
    family_names = [label for label, _ in _FAMILY_MODULES]
    assert "LockBit 5.0" in family_names
    assert "Akira" in family_names
    assert "Qilin" in family_names
    assert len(_FAMILY_MODULES) == 3


def test_sim_all_importable():
    mod = importlib.import_module("simulations.sim_all")
    assert hasattr(mod, "run_all")
    assert hasattr(mod, "main")
