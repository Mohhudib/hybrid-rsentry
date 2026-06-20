# Evaluation Log

Chronological record of the three-axis evaluation of Hybrid R-Sentry: what was
measured, the methodology decisions, the bugs surfaced and fixed, and the honest
limitations. Intended as an audit trail for the committee.

## Overview

The evaluation answers three questions, each its own axis:

| Axis | Question | Headline result | N |
|------|----------|-----------------|---|
| Efficacy | Does it detect ransomware without false positives? | Recall 1.000, FPR 0.000 | 30 |
| Efficiency | How fast, and what does it cost? | MTTD ~150 ms; overhead 1.70 µs/op | 30 |
| Robustness | Is every detection layer necessary? | All 4 layers necessary, Holm p=0.001 | 15 |

All raw trial data is archived under `docs/evaluation/` so every published
number can be recomputed from source.

## Common methodology

- **One trial = one labelled workload vs a fresh agent.** The agent is restarted
  per trial (no cross-trial state). External observation only (logs, /proc,
  iptables, cgroups) — the harness never reads agent internals.
- **Integrity guard.** Every runner wraps each trial in try/except, records
  failures (never silently drops), and reconciles recorded vs planned trials. A
  loud INCOMPLETE banner fires if any trial is missing or errored. Numbers are
  trusted only when the banner says COMPLETE.
- **Resumability.** Runs are keyed by sample_id; re-running fills gaps without
  redoing completed trials and without touching existing records.
- **Statistics.** Percentiles over means where distributions are skewed (latency);
  Wilson CIs for rates; bootstrap CIs for medians (Efron 1979); Wilcoxon
  signed-rank for paired non-normal samples (overhead); McNemar exact for paired
  binary outcomes (ablation); Holm-Bonferroni for family-wise error control.
  Effect size is always reported beside the p-value.

## Axis 1 — Efficacy

- N=30, 270 malicious + benign trials, COMPLETE 270/270.
- Recall 1.000 [0.969, 1.000], Precision 1.000, F1 1.000, FPR 0.000 [0.000, 0.025].
- All four malicious families detected 30/30; all five benign classes 0 false
  positives.
- **Specificity highlight:** the `high_entropy` benign class uses real gzip, xz,
  and gpg (cycled across the 30 trials). gpg -c is genuine symmetric encryption —
  the same operation class as ransomware — yet FPR stayed 0.000. This proves the
  system flags malicious BEHAVIOURS (non-sequential writes, suspicious renames,
  canary touches), not encryption or high entropy per se.
- **Integrity-guard save:** an early N=30 silently dropped 38 trials via a
  rm+resume that lost records while still reporting recall=1.000. This was caught,
  and the completeness/reconciliation guard was added so a dishonest denominator
  can never recur. The clean re-run is the archived result.

## Axis 2 — Efficiency

### Phase 1 — latency & damage (N=30, 120/120 malicious)

- rename families: MTTD p50 ~150 ms, 2 files touched before freeze.
- entropy_only: MTTD p50 ~1191 ms, 8 files — the entropy layer detects
  post-encryption, trading latency/damage for coverage.
- Pooled MTTD p50=156 ms vs mean=419 ms vs p95=1202 ms: the mean is inflated by
  the entropy tail; percentiles reveal what the mean hides.
- Stage breakdown: effective containment (freeze→isolate→kill) ~91 ms; the
  ~1021 ms kill→complete is post-neutralization cleanup, not time-critical.

### Phase 2 — resource overhead (paired OFF/audit/enforce, 29/30 rounds)

- Three-condition paired design isolates monitoring cost from LSM-enforcement
  cost. Per-operation µs is the headline (invariant to workload length).
- Monitoring: 1.70 µs/op (audit−off), Wilcoxon p<0.001.
- LSM enforcement: +0.12 µs/op (enforce−audit), p=0.005, CI [0.061, 0.178].
- Memory: ~476 MB RSS both modes (enforce <1 MB more).
- **Methodological finding:** LSM hooks run kernel-inline, charged to the
  workload's syscalls — so the cost lands in wall-time/system-CPU (significant),
  NOT in agent-process CPU (p=0.156). Measuring the right channel was essential;
  agent CPU alone would have wrongly shown "no cost".
- One round excluded (transient agent-readiness under background load), recorded
  by the integrity guard, not silently dropped.
- Two redesigns en route to a clean number: the benign churn was changed to a
  fixed 50-file round-robin O_APPEND (reused inodes avoid a /proc-fd scan storm
  that fresh-file churn caused), and workload length was raised so per-launch cost
  amortizes into a true steady-state measurement.

## Axis 3 — Robustness

- Controlled ablation: filesystem state byte-for-byte invariant across conditions
  (all four canary prefixes seeded + registered identically); only the gated
  layer's DECISION differs, via ABLATE_* env vars.
- Two-level decision gate (kernel compile-time + userspace contain sites); an
  ablated layer still emits its event with an ablated=<layer> marker for
  attribution, but drives no containment.
- Each malicious family isolates ONE behaviour, so each layer is proven necessary
  independently. A `canary_touch` and a `writeoffset_only` family were added to
  give the canary and write_offset layers their own necessity probes.
- N=15, 450 trials, COMPLETE 450/450, errored=0. Perfect necessity diagonal: each
  family drops to 0.000 ONLY under its own layer's ablation, 1.000 otherwise.
- All 4 detection layers NECESSARY: rename, write_offset, entropy, canary — each
  McNemar p<0.001, Holm p=0.001 (corrected across 24 contrasts). Off-diagonal
  contrasts correctly non-significant (p=1.000).
- **write_offset proof:** the `writeoffset_only` family encrypts an
  already-high-entropy file IN PLACE — entropy delta ~0, so the entropy layer is
  blind; only the non-sequential write pattern catches it. This proves
  write_offset covers a real attack class no other layer sees.
- **No backup / defence-in-depth** was observed because samples are deliberately
  pure (one behaviour each) to isolate necessity. Layers cover orthogonal
  behaviours → the multi-layer design is necessary, not redundant. Defence-in-depth
  against real multi-behaviour ransomware is an untested emergent property.
- Three production bugs fixed during bring-up: (1) an ablated layer's emitted
  event was counted as detection (fixed by defining detected = actual containment,
  the SIGSTOP pipeline line); (2) lost layer attribution under ablation (the true
  containing layer now stamps its name); (3) a per-trial agent-log fd leak causing
  EMFILE at scale (fixed by closing the parent fd + a reclaim settle interval).

## Honest limitations

- **mmap-based encryption** bypasses the vfs_write path entirely — a documented
  blind spot (expected false negative), not exercised in this corpus.
- **Pure single-behaviour samples** prove necessity but do not measure
  defence-in-depth against multi-behaviour ransomware.
- **Single host.** All runs on one Kali VM (2 vCPU, 3.8 GiB); absolute latency
  numbers are hardware-dependent, though the per-op overhead and the necessity
  results are not.

## Environment

See `ENVIRONMENT.md` for kernel, interpreters, and pinned library versions.
