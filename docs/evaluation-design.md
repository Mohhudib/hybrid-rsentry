# Hybrid R-Sentry — Evaluation Design Document

**Status:** Review checkpoint — methodology only, no implementation.
**System under test (SUT):** Hybrid R-Sentry autonomous detection/containment agent (eBPF/LSM backend, Kali Linux, kernel 6.x, BCC).
**Author scope:** Capstone evaluation across three axes — **Efficacy**, **Efficiency**, **Robustness**.

---

## 0. Preliminaries — definitions that bind all three axes

These are deliberately fixed *up front* because every metric depends on them. Items still open are flagged and collected in §7.

### 0.1 The unit of observation: a *trial*

A **trial** is one execution of one labeled workload (malicious *or* benign) against a freshly-prepared agent, observed externally. This mirrors the existing live tests (`tests/integration/test_live_*`): the test orchestrates and observes only from outside surfaces (agent log, `iptables -S OUTPUT`, `/proc/<pid>`, cgroup membership, files on disk). No agent internals are called.

### 0.2 Two distinct outcomes per trial — *Detection* vs *Containment*

The current pipeline is `detect → SIGSTOP → evidence → cgroup network isolation → SIGKILL → CONTAINMENT COMPLETE`. These are **separable** outcomes and conflating them is a construct-validity error:

| Outcome | Operational definition (external observable) | Log signature |
|---|---|---|
| **Detection (D)** | Agent emits a CRITICAL decision for the trial PID | `SIGSTOP pipeline: pid=… layer=…` line appears |
| **Containment (C)** | Full pipeline completes for the trial PID | `=== CONTAINMENT COMPLETE PID <pid>` line appears |

> **Primary efficacy metric is Detection.** Containment is reported as a secondary "response success" rate conditioned on detection: `P(C | D)`. *This split is an open question (§7-Q1) — confirm before implementation.*

### 0.3 Attack onset `t₀` (the MTTD anchor)

`t₀` ≝ timestamp of the **first malicious file-touching syscall** by the sim (the first `rename`/`write`/`open`-for-write on a corpus or canary file), recorded *by the sim itself* on `CLOCK_MONOTONIC`. Not process spawn (excludes Python interpreter warm-up, which is not part of "the attack"). *Open question §7-Q3.*

### 0.4 Layer attribution

The agent already tags each containment with the firing layer in the log (`layer=canary|rename|write_offset|execve`). Attribution rule for evaluation: **first layer to drive the PID to a CRITICAL decision wins** (the layer named on the first `SIGSTOP pipeline` line for that PID). All other layers that *would* have fired are recovered separately in the ablation study (§Robustness). *Open question §7-Q2 — entropy is currently an async severity enrichment, not an independent containing trigger; this materially affects whether "entropy" is an ablatable layer.*

### 0.5 Clock and instrumentation discipline (binds all timing)

- **Single clock domain:** `CLOCK_MONOTONIC` via `clock_gettime`. It is system-wide and comparable across processes on one host (unlike per-process CPU clocks), and immune to NTP/`CLOCK_REALTIME` step adjustments. The agent already writes monotonic timestamps for its heartbeat, establishing precedent.
- **Passive instrumentation only:** all timestamps are read from signals the SUT *already* emits (BPF `perf_submit` event `ts`, containment log lines) plus the sim's own `t₀`. We add **no probes to the hot path** — this is the primary defense against the Heisenberg/internal-validity threat (§Threats).
- **External observer:** measurement is done by a separate orchestrator process parsing log + `/proc` + `iptables`, never by the agent measuring itself.

---

# AXIS 1 — EFFICACY

## 1.1 Research question

> **Does Hybrid R-Sentry correctly distinguish ransomware behavior from benign system activity?** Specifically: when ransomware runs, does the agent detect/contain it (sensitivity), and when only benign activity runs — *including high-entropy benign work that mimics the encryption signature* — does the agent refrain from acting (specificity)?

## 1.2 Metrics — formal definitions

Confusion-matrix cells are assigned per trial from the Detection outcome (§0.2):

| Cell | Assigned when | Meaning |
|---|---|---|
| **TP** | trial is malicious **and** D fired | ransomware correctly detected |
| **FN** | trial is malicious **and** D did not fire | ransomware missed |
| **FP** | trial is benign **and** D fired | benign workload wrongly contained |
| **TN** | trial is benign **and** D did not fire | benign correctly ignored |

| Metric | Formula | Unit | "Good" for a security detector | Standard |
|---|---|---|---|---|
| Recall / Sensitivity / TPR | TP / (TP + FN) | ratio | → 1.0 — missing ransomware is catastrophic; recall is the priority metric | Sokolova & Lapalme 2009; MITRE Engenuity (analytic coverage) |
| Precision / PPV | TP / (TP + FP) | ratio | high — but secondary to recall in this domain | Sokolova & Lapalme 2009 |
| F1 | 2·(P·R)/(P+R) | ratio | high; harmonic mean balances the two | Sokolova & Lapalme 2009 |
| FPR | FP / (FP + TN) | ratio | → 0.0 — false containment of a real workload (e.g. a backup job) is a self-inflicted DoS | NIST SP 800-61 (incident cost), ROC convention |
| FNR | FN / (FN + TP) = 1 − Recall | ratio | → 0.0 | ROC convention |
| Specificity / TNR | TN / (TN + FP) = 1 − FPR | ratio | → 1.0 | ROC convention |
| Accuracy | (TP+TN)/(N) | ratio | reported but **de-emphasized** — misleading under class imbalance | Sokolova & Lapalme 2009 |
| Per-family detection rate | TPₖ / Nₖ for family *k* | ratio | → 1.0 per family; exposes a family the system is blind to that pooled recall would hide | MITRE Engenuity (per-technique reporting) |
| Benign-type FPR | FPⱼ / Nⱼ for benign class *j* | ratio | → 0.0 per class; **compression/encryption class is the headline number** | derived; ROC convention |

**Why each matters, briefly:** Recall and FNR quantify the *security failure* mode (missed ransomware). FPR/Specificity quantify the *operational failure* mode (containing a legitimate process — which, given the pipeline ends in SIGKILL + network isolation, is a serious incident in itself). Precision/F1 summarize the trade-off. Accuracy is included only for completeness and explicitly cautioned against (with ~50/50 malicious/benign trial balance it is less misleading, but class balance in the wild is extreme).

## 1.3 Dataset / ground truth

**Malicious (positive class).** `sim_akira`, `sim_qilin`, `sim_lockbit`, each parameterized (`--traversal`, `--max-files ≤ 10`, `--delay`). Ground truth = **label by construction**: the orchestrator launched a known sim, so the trial is malicious with certainty. No oracle ambiguity.

**Benign (negative class).** Diversity is the entire point: a benign set that doesn't exercise each layer's trigger surface produces an *optimistically low* FPR (construct threat). Required benign classes, ordered by difficulty:

| Benign class | Example workload | Layer(s) it stresses | Why included |
|---|---|---|---|
| **High-entropy (HARDEST)** | `gzip`/`xz`/`zip`/`tar.gz`, `gpg -c`, `ffmpeg` re-encode, copying already-compressed media | entropy delta + write-offset | This is the **adversarial benign** case — its byte-level signature is statistically indistinguishable from encryption (≈8 bits/byte). The headline FPR number. |
| Bulk file ops | `rsync`, `cp -r`, `git checkout`, large `make` build | rename/velocity + write | high write/rename volume mimics a campaign |
| Atomic editor saves | write-temp-then-rename (vim, VS Code, LibreOffice) | rename/extension + write-offset | the classic "rename to new name" benign pattern |
| Batch rename / log rotation | `rename`, `logrotate` | rename/extension | extension changes without encryption |
| Idle / normal | browser cache writes, light document edits | all (low intensity) | baseline; should be trivially TN |

Benign trials are also **labeled by construction**.

**Sample-size justification.** Two different N's, because efficacy and latency have different statistical needs (this distinction is itself a methodological point):

- *Per-sample file count* is capped at **≤10** (VM-hang guard) — this is a per-trial intensity bound, **not** the statistical N.
- *Detection-rate N (this axis):* **N ≈ 30 trials per family and per benign class.** Reasoning via the **rule of three** (Hanley & Lippman-Hand 1983): if an estimator sees 0 failures in *n* independent trials, the one-sided 95% upper bound on the failure probability is ≈ 3/n. At n=30, a clean 30/30 detection sweep yields "missed-detection rate ≤ 10% with 95% confidence," and the **Wilson score interval** (Wilson 1927) for 30/30 gives a two-sided 95% lower bound of ≈ 0.885. So N=30 is the smallest N that supports a defensible "≥ ~88% detection, ≥90% upper-bounded miss-safety" claim per family without overstating precision. Larger N tightens this; N=30 is the documented floor.

## 1.4 Experimental procedure

1. **Fresh agent per trial** (or per small block) to prevent state leakage (`blocked_pids` BPF map, lineage cache, per-PID cooldowns). *Cost/benefit is open — §7-Q6.*
2. Stand up the throwaway stub backend (absorbs telemetry so the synchronous contain-worker POST doesn't stall on retry back-off) — reuse the pattern already in `test_live_autonomous_agent.py`.
3. Launch the workload as a non-root UID (operator), via the symlinked-interpreter comm trick for sims (so `comm` ≠ `python3` and the safelist is not triggered).
4. Observe externally for a bounded window (RESPONSE_TIMEOUT ≈ 30 s); record D and C from the log, plus whether the canary survived (decoy intact ⇒ inline LSM deny worked).
5. Tear down surgically (SIGTERM agent, `iptables -D` of our own rule only — never `-F`, cgroup `rmdir`); assert chain restored to baseline.
6. Emit one JSON record per trial.

**Warm-up policy.** Discard the first *k* (≈3) trials after each agent start. Cold-start costs — BPF compile, the ~492k-entry dpkg lineage-hash prewarm, page cache, branch predictors — are not representative of steady-state operation and would inflate both MTTD and (via scheduler pressure) FP behavior. Standard benchmarking hygiene; warm-up runs are recorded but excluded from estimates.

**Confound control.** Quiescent host; pin agent and workload to isolated vCPUs (`taskset`/`cgroup`) where possible; disable CPU frequency scaling / turbo if exposed to the guest; gate each trial's start on a load-average threshold; record per-trial `loadavg`, free memory, and host noise so trials can be filtered post-hoc; consistent page-cache policy between trials (either always-drop or never-drop, recorded — not mixed).

## 1.5 Statistical treatment

- **Point estimates:** proportions (recall, precision, FPR, per-family/per-class rates).
- **Variability:** **Wilson 95% score intervals** for every proportion (correct for small N and for p near 0 or 1, where the normal approximation fails — exactly our regime). Bootstrap 95% CIs (Efron 1979, ≥10k resamples) for F1, which is a non-linear function of counts.
- **Reporting:** full confusion matrix (counts), then derived metrics each with CI. Per-family and per-benign-class breakdowns are mandatory; pooled numbers are secondary.
- **No NHST on this axis** unless comparing against a baseline detector; efficacy here is descriptive/estimation, not comparative. (Comparative significance lives in Robustness/ablation, §3.5.)

## 1.6 Threats to validity (Efficacy)

- **Internal:** trial-to-trial state leakage (BPF maps / caches) could let an earlier malicious PID's arming bleed into a later trial → fresh-agent mitigation; record agent restart boundaries. Observer log-parse race (reading the log before the line flushes) → child runs unbuffered (`-u`), bounded polling with a final post-exit read (already solved in the live tests).
- **External:** benign corpus is a *hand-built proxy* for "all legitimate Linux activity" — FPR generalizes only as far as the corpus is representative; we mitigate by deliberately over-weighting the hardest (high-entropy) class but cannot claim production FPR. Three sim families ≠ the ransomware universe; per-family recall must not be silently generalized to "ransomware."
- **Construct:** does "D fired" equal "detected ransomware"? It measures *the agent's decision*, which is the right construct for an autonomous agent — but a TP that fires for the *wrong reason* (e.g. canary luck rather than the behavioral signal we credit) inflates apparent capability; layer attribution (§0.4) + ablation (§3) disentangle this. Sim entropy comes from `os.urandom`/XOR, not a real cipher — defensible (AES output ≈ `urandom` entropy ≈ 8 bits/byte) but write *patterns* (mmap vs `write()`, partial vs full) may diverge from real malware (§Robustness evasion map addresses the mmap blind spot honestly).

---

# AXIS 2 — EFFICIENCY

## 2.1 Research question

> **How fast does the agent detect and neutralize an attack, and what does running it cost?** "Fast" is operationalized as time-to-detect and time-to-contain mapped onto the NIST incident-response lifecycle; "cost" is steady-state CPU/memory/IO overhead and hot-path function performance. The security significance of latency is **damage**: every millisecond before SIGSTOP is files the attacker may still rewrite.

## 2.2 Metrics — formal definitions

**Lifecycle metrics** (NIST SP 800-61 Rev 2 phases: *Detection & Analysis* → *Containment*):

| Metric | Formula | Unit | "Good" | Standard |
|---|---|---|---|---|
| **MTTD** (Mean/median Time To Detect) | `t_detect − t₀` | ms | as low as possible; sub-100ms is the target band for syscall-driven detection | NIST SP 800-61 (Detection & Analysis) |
| **MTTR** (Time To Respond/contain) | `t_complete − t_detect` | ms | low and *bounded* — the tail matters more than the mean | NIST SP 800-61 (Containment) |
| **End-to-end** | `t_complete − t₀` | ms | = MTTD + MTTR | derived |

**Pipeline stage decomposition** (consecutive deltas; the sum reconstructs end-to-end):

| Stage | Interval | Source timestamps |
|---|---|---|
| Detect | `t_detect − t₀` | sim `t₀` → first BPF event `ts` / first `SIGSTOP pipeline` line |
| Decide | `t_decide − t_detect` | event arrival → CRITICAL classification |
| Freeze | `t_sigstop − t_decide` | → `SIGSTOP sent to PID` |
| Evidence | `t_evidence − t_sigstop` | → evidence-captured log |
| Isolate | `t_isolate − t_evidence` | → `Network isolation applied: cgroup=` |
| Kill | `t_kill − t_isolate` | → `SIGKILL sent to PID` / `CONTAINMENT COMPLETE` |

Stage decomposition is what turns "it's slow" into "the *isolate* stage dominates because iptables/cgroup setup is the long pole" — actionable, publishable.

**Latency distribution metrics:** report **p50, p95, and p99** per stage and end-to-end, plus IQR.

> **Why percentiles, not the mean** (Google SRE; Dean & Barroso, "The Tail at Scale," CACM 2013): latency distributions are right-skewed and multi-modal (BPF buffer poll cadence, scheduler wakeups, iptables syscall variance). The mean is dragged by outliers and hides the worst case; for a *security* control the **tail is the risk** — p99 detection latency bounds how bad the slow case gets, which directly bounds files-lost. We lead with median (robust central tendency) and p95/p99 (tail), and report mean+stddev only for comparability with prior work.

**Resource overhead:**

| Metric | Formula | Unit | "Good" | Standard |
|---|---|---|---|---|
| CPU overhead | `mean(CPU%_on) − mean(CPU%_off)` | percentage points | low single digits at steady state | psutil methodology |
| Memory overhead | `RSS_on − RSS_off` | MB | bounded, non-growing (no leak across a run) | psutil |
| IO overhead | `ΔIO_counters_on − off` (read/write bytes, ops) | MB/s, ops/s | low | psutil |

**Micro-benchmark (hot-path functions):** ops/sec, min/median/mean/stddev via `pytest-benchmark` for the pure userspace functions on the critical path — Shannon entropy delta computation, behavioral score calc, rename/extension matcher, event dict construction/serialization. These are **root-free** and isolate algorithmic cost from kernel/scheduler noise.

## 2.3 Dataset / ground truth

Same malicious sims as Efficacy (latency is only meaningful on *detected* attacks → measured on TP trials). Ground truth for timing = the matched timestamp pairs above; correctness of the pairing is guaranteed by PID-scoped log lines.

**Sample size (latency-specific, ≠ efficacy N).** Tail percentiles need far more samples than a proportion:
- A single sample beyond p95 requires ≥20 trials; a *stable* p95 needs ~100; a credible **p99 needs several hundred**.
- Therefore: **N ≈ 100–200 timed trials per family** for latency, vs N=30 for detection rate. With N=30 we will report **p50 and p95 only, explicitly flagging p99 as under-powered.** Whether to invest the runtime (and VM-hang risk) for N≈200 to support p99 is **open — §7-Q5.**
- Per-stage variance also informs N: noisier stages (isolate) get the larger N.

## 2.4 Experimental procedure

- Timing extracted **passively** from emitted event `ts` + log lines on the shared `CLOCK_MONOTONIC` domain (§0.5). The sim writes `t₀` to a side channel (its own log line) the orchestrator reads.
- **Resource overhead = paired design:** run the identical benign+malicious workload mix twice — once **agent ON**, once **agent OFF** — sampling `psutil` for the agent PID and system-wide at fixed cadence (e.g. 10 Hz). Pairing controls for workload variance; the estimand is the *difference*.
- **Warm-up:** discard cold-start trials (BPF compile, lineage prewarm, JIT, cold page cache) — steady-state only, same rationale as §1.4. Micro-benchmarks use `pytest-benchmark`'s built-in warm-up/calibration.
- **Confound control:** as §1.4 (core pinning, frequency-scaling off, loadavg gating, recorded host noise). For micro-benchmarks additionally pin to one core and raise scheduling priority to suppress scheduler jitter.

## 2.5 Statistical treatment

- **Latency point estimate:** **median** (robust to skew), not mean.
- **Tail:** p95 (and p99 if powered), reported with **bootstrap 95% CIs** (percentile CIs from analytic formulas are unreliable; bootstrap is standard).
- **Spread:** IQR (matches median); stddev reported secondarily.
- **Overhead:** paired differences → **Wilcoxon signed-rank** test (psutil samples are not normal; non-parametric paired test) with the mean/median difference and 95% CI. α = 0.05.
- **Micro-bench:** `pytest-benchmark` native stats (OPS, min/median/IQR), compared across versions if regression-tracking.

## 2.6 Threats to validity (Efficiency)

- **Internal (the headline efficiency threat):** *instrumentation overhead changing the thing measured.* Adding timing probes to the detect→freeze hot path would inflate MTTD — so we add none; we reuse timestamps the system already emits and parse logs out-of-band. The residual risk is **log-flush latency** sitting between true event time and observable line time; we bound it by using the BPF event `ts` (kernel timestamp, taken at detection) rather than the userspace log write time for `t_detect`. Clock granularity/jitter of `CLOCK_MONOTONIC` under virtualization is a secondary internal threat (see External).
- **External:** a **VM clock is not a bare-metal clock** — virtualized timekeeping (paravirt clock, host scheduling of the guest vCPU) inflates and adds variance to all latencies; absolute numbers may not transfer to bare metal or cloud. Overhead measured on a quiescent single-tenant VM understates contention overhead on a busy production host. BCC/JIT version and kernel 6.x specifics bound generality.
- **Construct:** **latency is a proxy for damage.** The metric the defender actually cares about is *files irreversibly modified before freeze*; latency only predicts it. We therefore additionally report **files-touched-before-SIGSTOP** (directly observable: count of malicious file ops with `ts < t_sigstop`) as the construct-valid harm metric, and treat latency as the explanatory variable. MTTD/MTTR also assume the NIST phase boundaries map cleanly onto our pipeline stages — a modeling choice we state explicitly.

---

# AXIS 3 — ROBUSTNESS

## 3.1 Research question

> **Is the four-layer design *necessary*, or is one layer doing all the work?** And: **which known evasion techniques does each layer defeat?** This axis justifies the architecture itself — the central design claim is that no single signal suffices across the ransomware behavior space, and that the layers provide defense-in-depth where each covers another's blind spot.

## 3.2 Ablation study design

The four layers under test: **write-offset** (kprobe `vfs_write`, non-sequential rewrite), **rename/extension** (rename tracepoint + extension match), **entropy** (Shannon delta), **canary** (LSM inline deny).

**Design:** for each family, run the full malicious trial set under **5 configurations** — all-layers-on (baseline), and each layer individually disabled (leave-one-out). Measure per-family **detection-rate drop** = `Recall(all-on) − Recall(layer-k-off)`.

| Config | write-offset | rename | entropy | canary |
|---|---|---|---|---|
| Baseline | ✓ | ✓ | ✓ | ✓ |
| −write-offset | ✗ | ✓ | ✓ | ✓ |
| −rename | ✓ | ✗ | ✓ | ✓ |
| −entropy | ✓ | ✓ | ✗ | ✓ |
| −canary | ✓ | ✓ | ✓ | ✗ |

> **Prerequisite (open §7-Q4):** ablation requires **per-layer enable/disable toggles** that don't otherwise perturb the agent. These likely do not all exist today (e.g. canary can be suppressed by not seeding/registering; rename/write-offset need config gates).

### 3.2.1 Entropy is a conditional/enrichment layer for the current corpus (code-verified)

A read-only trace of `agent/monitor_ebpf.py` (the eBPF backend) resolves the §7-Q2 fork. Three findings change how the `−entropy` row must be read:

- **Entropy *can* independently contain — but only under a compound condition.** The single code path that contains under `layer=entropy` is `_handle_behavior()` (`monitor_ebpf.py:1560`, `_contain_q.put_nowait((pid, comm, "entropy"))`). It is **doubly gated**: (a) the kernel multi-signal `behavior_events` probe must fire first, **and** (b) a file sampled from `/proc/<pid>/fd` must read `entropy >= 6.5`. The async enrichment thread `_score_worker()` (`:1356-1388`) **never** contains — by its own docstring it "runs AFTER containment fires" and only recomputes severity/`entropy_delta` then `_emit`s.
- **No `ENTROPY_SPIKE` exists in the eBPF backend.** That event type lives only in the inotify backend (`monitor.py:325`) and `entropy.py`. In eBPF, entropy surfaces as a `_severity()` input (`:290-305`) or as a confirmation gate (below) — never as a standalone containing event.
- **For the current three sims, entropy is the sole detector of *nothing*.** LockBit (16-char-ext rename), Akira (`.akiranew` rename), and Qilin (in-place percent encryption) are each caught by the **rename** layer and/or the **entropy-free** write-offset detector (`observe_write_offset()` `:505-565` and the kernel `silent_enc` flag `:1128` are pure non-sequential-offset pattern, no entropy term) and/or **canary**. Disabling entropy therefore changes **severity grade and layer attribution**, not detection outcome.

**Consequence for the `−entropy` row:** by default it must be analyzed as a **severity-downgrade / attribution** effect (metric = "severity-grade change" or "fraction of trials whose attributed layer moves off `entropy`"), **not** a detection-rate drop — because for this corpus `Recall(−entropy) == Recall(baseline)` is the expected result.

**To demonstrate entropy as a *necessary detection* layer**, the corpus must include a new sample shaped to its unique coverage: **sequential-write, no-rename, high-entropy in-place encryption** — i.e. a workload that (1) does not rename (evades the rename layer), (2) writes sequentially so offsets advance normally (evades `observe_write_offset` and the kernel `silent_enc` pattern), (3) does not touch a canary, yet (4) trips the kernel behavioral score and produces files with `entropy >= 6.5`. Only against such a sample can the `−entropy` row produce a genuine recall drop. Adding this sample is proposed (see §7-Q9 sibling) but not yet in the sim set.

**Honest attribution-coupling caveats for the leave-one-out:**

- **(i) "Disable the entropy decision path" is not confined to one layer.** `observe_write()`'s burst→entropy branch (`:480-500`) emits `SILENT_ENCRYPTION` only when `entropy >= _ENTROPY_THRESHOLD`, but its caller tags the containment `layer=write_offset` (`:1495-1500`). So entropy already participates as a *confirmation gate inside the write-offset layer*; an entropy toggle either spans two attribution buckets or leaves this gate intact — state which, and report it.
- **(ii) The `layer=entropy` trigger cannot fire in isolation.** It is downstream of the kernel `behavior_events` signal, so the entropy path is inseparable from the behavioral-scoring machinery; "entropy alone" is not an independently exercisable configuration, and the `−entropy` ablation perturbs only the *userspace `entropy >= 6.5` decision*, not the kernel scorer that gates it.

## 3.3 Why ablation proves multi-layer necessity

The architecture's justification is **logical, not rhetorical**, and ablation is the proof:

- If disabling layer *k* causes **zero** recall drop for **every** family → layer *k* is redundant (publishable negative result; argues for simplification).
- If **each family's recall depends on a *different* primary layer** (drop is large for that family when its primary layer is off, ~0 otherwise) → the layers are **non-overlapping in coverage** ⇒ the multi-layer design is *necessary*, not gold-plating. This is the result the design predicts.
- If a family stays detected even with its primary layer off (because a backup layer catches it) → quantifies **defense-in-depth / graceful degradation**, the second core claim.

## 3.4 Layer-contribution analysis (primary vs backup per family)

Using §0.4 attribution (first-firing layer) under baseline, plus the leave-one-out drops, classify each (family, layer) cell as **Primary** (its removal collapses detection), **Backup** (fires only when the primary is absent), or **Inactive**. Hypothesized map (to be confirmed empirically):

| Family | Primary layer | Backup layer(s) | Rationale |
|---|---|---|---|
| LockBit (two-pass, 16-char ext rename) | rename/extension | write-offset, entropy | rename is the loud signal; in-place rewrite + high entropy back it up |
| Akira (intermittent/partial encrypt + rename) | entropy delta / write-offset | rename, canary | partial encryption defeats naive size/rename heuristics; entropy on partial reads catches it |
| Qilin (percent-based partial encrypt) | write-offset / entropy | rename | non-sequential partial writes are the tell |
| *Any family touching a decoy* | **canary (LSM inline deny)** | — | deterministic, behavior-independent; the floor of last resort |

## 3.5 Statistical treatment (Robustness)

Ablation is **comparative and paired** (same samples, layer on vs off):

- **McNemar's test** (1947) on the paired binary detection outcomes per (family, layer) — the correct test for paired nominal data, not a two-sample proportion test.
- Effect size = recall-drop with **Wilson CI** on the change.
- **Multiple-comparison correction:** 4 layers × 3 families = 12 paired tests ⇒ **Holm–Bonferroni** control of family-wise error at α = 0.05 (Holm preferred over plain Bonferroni for power). *Confirm choice — §7-Q10.*

## 3.6 Evasion resistance — technique → defeating layer

Mostly **analytical mapping** (a coverage argument), with **empirical confirmation** where a sim/variant can express the technique within the ≤10-file / no-real-cipher constraints. Honest about gaps.

| Evasion technique (MITRE-flavored) | Defeating layer | Mechanism | Empirically testable here? |
|---|---|---|---|
| Low-and-slow / rate-limited encryption (evade velocity) | **canary** + **entropy** | both are *state/rate-independent*: one decoy touch or one high-entropy rewrite suffices | Yes — sim `--delay` high |
| Rename-only / extension change, no encryption | **rename/extension** + **canary** | extension match doesn't need entropy | Yes |
| In-place silent encryption, **no rename** (no extension change) | **write-offset** + **entropy** | non-sequential rewrite of an existing inode is the signal | Yes — sim in-place mode |
| Partial / intermittent encryption (first N%) | **entropy delta** (partial reads) + **write-offset** | entropy engine reads partial content; doesn't require whole-file encryption | Yes |
| Process masquerading (`comm` spoof as `python3`/legit) | **canary** (comm-independent) + behavioral layers | canary deny is keyed on inode, not comm; interpreter no longer safelisted (BUG-2 fix) | Yes — symlink-comm trick |
| Operating outside `WATCH_PATH` | behavioral layers (system-wide eBPF) + **canary** | eBPF backend is system-wide, not path-scoped | Partial |
| Blinding/killing the agent | **fail-secure heartbeat** (LSM denies renames if heartbeat stale) | kernel-side deadman switch | Yes — stall heartbeat |
| **mmap-based encryption (bypass `vfs_write`)** | **KNOWN BLIND SPOT** — only caught if a rename/canary touch occurs; pure mmap+msync may evade write-offset | honest negative result | Test as expected-FN — §7-Q9 |

Reporting the mmap gap as an expected FN is what makes this a paper, not a marketing benchmark.

## 3.7 Threats to validity (Robustness)

- **Internal:** disabling a layer may have **side effects** beyond removing its signal (e.g. removing canary seeding also removes a class of file churn the behavioral layers might otherwise observe) — confounds the "clean" leave-one-out. Mitigate by toggling *only the decision path* of each layer while leaving its observation/seeding intact where possible, and documenting any unavoidable coupling. The entropy-is-not-an-independent-trigger issue (§3.2) is the largest internal threat to a clean ablation.
- **External:** ablation conclusions hold for *these three sims*; a fourth family with a novel TTP could redistribute primary/backup roles. The evasion map is partly analytical — untested rows are *claims*, labeled as such.
- **Construct:** "recall drop when layer off" measures **necessity within our sample**, which is the right construct for a *necessity* argument; it does **not** prove sufficiency against unseen malware. We claim necessity (each layer earns its place against tested behaviors) and defense-in-depth, not completeness.

---

# 4. File structure — `tests/evaluation/`

```
tests/evaluation/
├── README.md                     # how to run, root matrix, reproduction steps
├── conftest.py                   # pytest fixtures (no root): clock, paths, result writer
├── harness.py                    # shared orchestration: start/stop agent, stub backend,
│                                 #   launch workload, parse log lines, extract timestamps,
│                                 #   surgical teardown  (extends the existing live-test pattern)   [ROOT to run]
│
├── corpus/
│   ├── malicious_samples.py      # sim wrappers + param matrix (family, traversal, max-files, delay)
│   ├── benign_workloads.py       # benign class definitions + generators (compression, rsync, editor-save…)
│   └── manifest.json             # the labeled trial plan (sample_id → {label, family/class, params})
│
├── efficacy/
│   ├── test_confusion_matrix.py  # all trials → confusion cells                         [ROOT]
│   ├── test_per_family.py        # per-family detection rate                            [ROOT]
│   └── test_benign_fpr.py        # per-benign-class FPR (compression headline)          [ROOT]
│
├── efficiency/
│   ├── test_mttd_mttr.py         # lifecycle + per-stage latency, percentiles           [ROOT]
│   ├── test_resource_overhead.py # psutil paired ON/OFF                                 [ROOT]
│   └── bench_hotpath.py          # pytest-benchmark, pure functions                     [NO ROOT]
│
├── robustness/
│   ├── test_ablation.py          # 5-config leave-one-out matrix                        [ROOT]
│   ├── test_layer_contribution.py# primary/backup classification                        [ROOT]
│   └── test_evasion_map.py       # evasion→layer (empirical rows live; analytical rows asserted) [ROOT for live rows]
│
├── analysis/
│   ├── aggregate.py              # merge results/*.json → summary tables                 [NO ROOT]
│   ├── stats.py                  # Wilson CI, bootstrap, McNemar, Holm correction        [NO ROOT]
│   └── figures.py               # confusion matrix, latency CDFs, ablation heatmap       [NO ROOT]
│
├── results/                      # JSON outputs (gitignored)
└── report_schema.md              # documents every JSON schema below
```

### Root vs non-root summary

| Needs **root** (loads BPF / iptables / cgroup / starts eBPF agent) | **No root** |
|---|---|
| `harness.py`, all `efficacy/*`, `efficiency/test_mttd_mttr.py`, `efficiency/test_resource_overhead.py`, all `robustness/*` live rows | `bench_hotpath.py`, all of `analysis/*`, `conftest.py`, corpus generation (choose non-root benign tools; **exclude `apt`/`dpkg`-install benign** to keep benign trials non-root and reproducible) |

### JSON exports (schemas documented in `report_schema.md`)

| File | Produced by | Key fields |
|---|---|---|
| `results/trials_raw.json` | harness (every trial) | `sample_id, label, family/class, t0, t_detect, t_decide, t_sigstop, t_isolate, t_kill, t_complete, layer_fired, detected(bool), contained(bool), canary_survived, files_touched_before_freeze, agent_restart_id, host_loadavg` |
| `results/confusion_matrix.json` | efficacy | `TP,FP,TN,FN`, + `precision,recall,f1,accuracy,fpr,fnr,specificity` each `{point, wilson_lo, wilson_hi}` |
| `results/per_family_detection.json` | efficacy | per family: `n, tp, recall {point,ci}` |
| `results/benign_fpr_breakdown.json` | efficacy | per benign class: `n, fp, fpr {point,ci}`; compression flagged `headline:true` |
| `results/latency_pipeline.json` | efficiency | per stage + end-to-end: `n, p50, p95, p99(nullable), iqr, mean, sd`, each percentile with bootstrap CI; per family |
| `results/resource_overhead.json` | efficiency | `cpu_on/off, rss_on/off, io_on/off`, paired `delta {median, ci}`, Wilcoxon `p` |
| `results/hotpath_bench.json` | efficiency | per function: `ops, min, median, iqr, mean, sd` (pytest-benchmark native) |
| `results/ablation_matrix.json` | robustness | per (family,layer): `recall_on, recall_off, drop {point,ci}, mcnemar_p, holm_p, classification(primary/backup/inactive)` |
| `results/layer_contribution.json` | robustness | per family: `primary_layer, backup_layers[]` with evidence refs |
| `results/evasion_resistance.json` | robustness | per technique: `defeating_layer, tested(bool), outcome(defeated/evaded/expected-FN), evidence` |

---

# 5. Standards index (for the paper's References)

- **NIST SP 800-61 Rev 2** — Computer Security Incident Handling Guide → IR lifecycle, MTTD/MTTR framing.
- **MITRE Engenuity ATT&CK Evaluations (EDR)** → per-technique/per-family detection reporting, analytic-coverage framing; MITRE ATT&CK **T1486** (Data Encrypted for Impact), **T1490** (Inhibit System Recovery), **T1498** (self-protection guard framing).
- **Google SRE Book** (Beyer et al. 2016) + **Dean & Barroso, "The Tail at Scale," CACM 2013** → percentile-over-mean latency rationale.
- **Sokolova & Lapalme 2009** → classification-metric definitions; accuracy caveats under imbalance.
- **Wilson 1927** (score interval), **Hanley & Lippman-Hand 1983** (rule of three) → proportion CIs / zero-event bounds / N justification.
- **McNemar 1947** → paired ablation test; **Holm 1979** → multiple-comparison correction.
- **Efron 1979** → bootstrap CIs for percentiles and F1.
- **Shannon 1948** → entropy metric basis.

---

# 6. What this design deliberately does NOT do

- No real-cipher / real-ransomware execution (safety; sims only).
- No claim of production FPR or bare-metal latency (external validity limits stated, not hidden).
- No claim of completeness/sufficiency against unseen malware — only **necessity** (ablation) and **defense-in-depth**.
- No p99 latency claim unless N is raised to support it (under-powering stated, not glossed).

---

# 7. Open questions — confirm before implementation

1. **Detection definition (§0.2).** Primary efficacy metric = *Detection* (CRITICAL decision / first `SIGSTOP pipeline` line), with *Containment* (`CONTAINMENT COMPLETE`) reported as secondary `P(C|D)`? Or must full containment complete to count a TP? My recommendation: report both, headline = Detection.
2. **Layer attribution & entropy's status (§0.4, §3.2.1) — RESOLVED by code trace.** Confirm "first-firing layer wins." The entropy fork is now answered from the source: **verdict (c) conditional.** Entropy *can* independently contain via `_handle_behavior()` (`monitor_ebpf.py:1560`, `layer=entropy`) but only under a compound gate — kernel `behavior_events` fires **and** a sampled FD reads `entropy >= 6.5`; the enrichment thread `_score_worker()` never contains. **For the current LockBit/Qilin/Akira corpus, entropy is the sole detector of nothing** (all three are caught by rename and/or the entropy-free write-offset/canary layers), so the `−entropy` ablation row is a **severity-downgrade / attribution** measurement, not a detection-rate drop. Documented in §3.2.1 with attribution-coupling caveats (i) and (ii). **Decision needed:** accept entropy as a conditional/enrichment layer (analyze `−entropy` as severity-grade change), **or** authorize adding the new sequential-write/no-rename/high-entropy in-place sample (Q11) required to make entropy demonstrably *necessary* for detection.
3. **`t₀` definition (§0.3).** Anchor MTTD at *first malicious file-touching syscall* (my recommendation) vs process spawn vs first canary/corpus contact?
4. **Per-layer disable mechanism (§3.2).** Do toggles exist for write-offset / rename / entropy / canary that disable only the *decision path* without disturbing observation? If not, we need to add minimal config gates **before** ablation — acceptable to add as instrumentation, or keep agent untouched and ablate by another means?
5. **Latency N / p99 (§2.3).** Accept **p50+p95 only at N≈30** (fast, low VM-hang risk) — or invest in **N≈100–200** timed trials per family to support p99 (longer, riskier)?
6. **Agent lifecycle (§1.4).** Fresh agent **per trial** (clean state, slow) vs **per block** of k trials (faster, risks BPF-map/cache leakage)? Recommendation: fresh per trial for efficacy/ablation, per block acceptable for latency if state is reset.
7. **Benign corpus scope (§1.3).** Confirm the allowed benign tool list in the Kali VM, and confirm we **exclude root-requiring benign** (`apt`/`dpkg`-install) to keep benign trials non-root and reproducible.
8. **Files-lost as harm metric (§2.6).** Add `files_touched_before_freeze` as a first-class construct-valid metric alongside latency? (Recommended.)
9. **mmap blind spot (§3.6).** In scope to add an mmap-based sim variant as an **expected-FN** robustness probe (honest gap), or out of scope for the capstone?
10. **Stats choices (§3.5).** Confirm **McNemar + Holm–Bonferroni** at α=0.05 for ablation; **Wilcoxon signed-rank** for overhead; **Wilson** + **bootstrap** for CIs.
11. **Entropy-necessity sample (§3.2.1).** Authorize adding a new **sequential-write, no-rename, high-entropy in-place** sim sample — the only workload shape whose detection uniquely depends on the entropy layer (`_handle_behavior` `entropy >= 6.5`). Without it the `−entropy` ablation can only show a severity-grade change, never a recall drop. In scope for the capstone, or accept entropy as a documented conditional/enrichment layer?

---

# 8. Findings surfaced during harness bring-up

A methodological point worth stating in the paper: **building the evaluation
harness immediately surfaced a silent, security-critical bug in the production
containment path** — exactly the kind of defect a benchmark that only checks
"was it detected?" would miss. This is evidence that the harness measures
*response*, not just *detection* (§0.2), and that the detection/containment
split is not academic.

**F1 — Silent containment abort (production path).** During the first end-to-end
Akira trial, the agent SIGSTOP'd the malicious PID but never isolated or
SIGKILL'd it — and logged nothing. Two compounding defects:
- `agent/containment.py` `_capture_evidence()` called `psutil.Process.net_connections()`,
  which does not exist in **psutil < 6.0** (the agent venv runs 5.9.8; the system
  interpreter runs 7.1.0 — the version split is why it first looked
  environment-dependent). The `AttributeError` was not caught by the narrow
  `except (NoSuchProcess, AccessDenied)`, so `contain()` aborted **after SIGSTOP,
  before SIGKILL**.
- `agent/monitor_ebpf.py` `_contain_worker` used `except Exception: pass`, making
  the abort **completely silent**.

**Fixes (landed; 186/186 unit tests pass):** (1) version-robust connections API
resolved once at import; (2) `_capture_evidence` hardened to best-effort
per-accessor — any single psutil failure degrades that field to `"unavailable"`
and the pipeline always proceeds to SIGKILL; (3) `_contain_worker` now logs the
full traceback at ERROR (`logger.exception`) so a containment failure can never
again be silent.

**Validity implication.** A detector that *detects* but silently fails to
*contain* scores identically to a perfect system on a detection-only metric. The
efficacy axis must therefore report `P(C | D)` (§0.2) as a first-class number,
and the efficiency axis's stage decomposition (§2.2) is what makes such a
mid-pipeline abort observable. Recommend the paper cite this as motivation for
the detection-vs-containment separation.
