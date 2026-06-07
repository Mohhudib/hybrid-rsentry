"""
tests/unit/agent/test_selftests.py

Bridges the two built-in --selftest harnesses into pytest so CI (`pytest tests/`)
actually runs them. Each _selftest() returns 0 on success / 1 on any failed
check; we capture its stdout to keep pytest output clean and assert 0.

These harnesses cover ~60 checks that no other pytest test exercises:
  - monitor_ebpf: severity chain, canary detection, velocity burst (two-pass),
    family profiling, noise suppression, seed_canaries, BPF source generation.
  - monitor: lineage/entropy adapters, send_event wiring, containment dry-run,
    whitelist membership.
"""
import io
from contextlib import redirect_stdout


def test_monitor_ebpf_selftest_passes():
    from agent import monitor_ebpf
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = monitor_ebpf._selftest()
    assert rc == 0, "monitor_ebpf --selftest reported failures:\n" + buf.getvalue()


def test_monitor_selftest_passes():
    # Slower (~2s): loads the dpkg known-good hash DB once.
    from agent import monitor
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = monitor._selftest()
    assert rc == 0, "monitor --selftest reported failures:\n" + buf.getvalue()
