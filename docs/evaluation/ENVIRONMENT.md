# Evaluation Environment

This document records the exact environment in which the three-axis evaluation
(efficacy, efficiency, robustness) was executed, for reproducibility and audit.

## Host / kernel

| Component | Value |
|-----------|-------|
| OS / distro | Kali GNU/Linux Rolling |
| Kernel | 6.19.14+kali-amd64 |
| Architecture | x86_64 |
| Virtualization | Oracle VirtualBox guest |
| vCPUs | 2 |
| RAM | 3.8 GiB |

The agent uses eBPF (kprobes on `vfs_write`/`vfs_rename`) and LSM hooks
(`file_permission`, `path_rename`), so a kernel with BPF + BPF-LSM support is
required. Kernel 6.19.x (Kali rolling) was used throughout.

## Python — two interpreters (by design)

The project deliberately uses two Python environments:

| Interpreter | Version | Role | Why |
|-------------|---------|------|-----|
| System python3 | 3.13.12 | The agent (`agent/monitor_ebpf.py`) | BCC/eBPF bindings are installed system-wide and only importable from the system interpreter |
| venv | 3.11.9 | Evaluation harness, runners, metrics | Isolated, pinned scientific stack (numpy/scipy) for the analysis code |

Commands that launch the agent under measurement use the venv python via
`sudo -E .../venv/bin/python` because the harness orchestrates the agent as a
subprocess; the agent's own eBPF layer is loaded through BCC available to the
runtime. Privileged runs use `sudo -E` so the `ABLATE_*` env vars and eval
side-channel paths pass through cleanly.

## Key library versions

| Library | Version | Used for |
|---------|---------|----------|
| numpy | 2.4.6 | percentiles (linear interp), bootstrap |
| scipy | 1.17.1 | Wilcoxon signed-rank, McNemar exact |
| psutil | 5.9.8 | agent CPU/RSS sampling (overhead axis) |
| bcc | 0.35.0 | eBPF program load (system python) |
| pytest | 9.0.3 | unit tests (219 passing) |

Full pinned dependency set: `requirements-frozen.txt` (93 packages, `pip freeze`
of the evaluation venv).

## High-entropy benign tools (efficacy specificity)

The `high_entropy` benign class cycles three real tools across its 30 trials
(`i % 3`): gzip, xz, gpg — producing ~8 bit/byte output that statistically
matches malicious encryption, yet yields FPR = 0.000.

| Tool | Version | Operation |
|------|---------|-----------|
| gzip | 1.13 | DEFLATE compression (`gzip -k`) |
| xz | 5.8.3 (XZ Utils) | LZMA compression (`xz -k`) |
| gpg | 2.4.9 (GnuPG) | symmetric encryption (`gpg -c`) — real encryption, same operation class as ransomware |

## Reproduction

```bash
# 1. evaluation venv (analysis stack)
python3.11 -m venv venv && ./venv/bin/pip install -r docs/evaluation/requirements-frozen.txt
# 2. system deps for the agent (eBPF)
sudo apt install -y bpfcc-tools python3-bpfcc   # provides bcc to system python3
# 3. run an axis (example: efficacy), privileged
sudo -E ./venv/bin/python -m tests.evaluation.efficacy.runner --n 30
./venv/bin/python -m tests.evaluation.efficacy.report
```

Each axis is resumable (re-run without clearing results to fill gaps) and prints a
completeness banner; trust the numbers only when it reports COMPLETE.
