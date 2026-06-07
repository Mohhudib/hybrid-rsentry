# Session 09 — Defense Validation (ransomware simulations exercise session_08 hardening)

**Date:** 2026-06-07
**Scope:** `simulations/sim_common.py`, `simulations/sim_akira.py`,
`simulations/sim_qilin.py`, `simulations/sim_lockbit.py`. Read-only against
`agent/monitor_ebpf.py` (DetectionEngine) and `agent/graph.py` (canary engine).
**Goal:** Extend each of the three family simulations so it safely exercises the
matching session_08 detection feature, then prove the defense fires with **zero
real files harmed**. Each family committed separately.

## Result

| Family | Defense exercised | Signal asserted | Status | Files harmed |
|---|---|---|---|---|
| AKIRA | #1 write-offset analysis | `SILENT_ENCRYPTION` (HIGH, PID frozen) | ✓ TRIGGERED | 0 |
| QILIN | #2 entropy-ext filter + #3 realistic canaries | `PROCESS_ANOMALY` + canary realism | ✓ TRIGGERED | 0 |
| LOCKBIT5 | #4 backup-destruction + #5 per-PID rate limit | `BACKUP_DESTRUCTION` (CRITICAL) + rate-limit wired | ✓ TRIGGERED | 0 |

`python -m agent.monitor_ebpf --selftest` → **ALL PASS** (unchanged; no engine
code was modified).

> **Validation model.** session_08 implements every rule twice: the kernel BPF
> program (enforcement) and a userspace `DetectionEngine` method (the
> unit-testable *source of truth*). These simulations run without root/BCC, so
> each one performs the **real, safe file operation** inside a sandbox **and**
> feeds the identical event into the userspace DetectionEngine, asserting the
> correct signal. Kernel-only enforcement (the per-PID rate limiter) is
> validated by asserting the generated BPF source carries the map/helper/define
> wired into the hot-path handlers (same approach as the engine selftest).

---

## Safety harness (`sim_common.py` → `Sandbox`)

All three `--validate-defense` runs go through one guarded context manager. The
safety invariants are enforced by the harness, not left to each simulation:

- **Sentinel-gated.** The directory must carry a `.rsentry_sandbox` sentinel.
  A pre-existing non-empty directory *without* the sentinel is refused, so the
  harness can never be pointed at real user data. It also refuses any path
  inside a git repo (canary/rename corruption guard, per Hard Rule #1).
- **Hard in-sandbox assertion.** `Sandbox.assert_inside(path)` resolves the real
  path and raises `SandboxViolation` if it is not under the sandbox root. Every
  file operation in every step goes through it (verified: `assert_inside('/etc/passwd')`
  raises).
- **Backup + restore + integrity audit.** `arm()` snapshots a SHA-256 of every
  file and copies the whole tree; on exit the tree is restored from the backup
  and `audit()` re-hashes every baseline file, raising if a single byte differs.
  A botched restore can never pass silently. `files_harmed=0` in each result is
  this audit's output.
- **No real cipher, no real backup deletion, no unbounded threads.** The
  destructive core of each technique is replaced with a non-harmful equivalent
  that produces the *same detection signal* (random bytes, `echo`, a bounded
  thread pool).

The synthetic corpus is throwaway generated files (`corpus_NNN.docx` …), never
real data. After each run the sandbox was confirmed restored to the original
corpus with no encrypted extensions or canary files left behind.

---

## 1 — AKIRA → SILENT_ENCRYPTION (Defense #1, write-offset analysis)

**Technique reproduced (safe):** Akira's intermittent encryption is a
read-modify-write storm whose write offsets jump around the file instead of
advancing sequentially. `_skip_step_writes()` opens a sandbox file `r+b` and
writes `os.urandom(4096)` at offset 0, seeks **+10 KB**, writes again, repeats
(8 writes). No cipher, no key, no rename, no extension change — in-place, exactly
like silent encryption.

**Validation:** the identical `(offset, length)` stream is replayed into
`observe_write_offset()`. The first write per inode is the baseline; each
subsequent non-sequential write increments the counter until
`_NONSEQ_THRESHOLD` (5) trips.

```
[AKIRA] ✓ defense=#1 write-offset analysis signal=SILENT_ENCRYPTION -> TRIGGERED
[AKIRA]   files_harmed=0
[AKIRA]   writes_issued=8
[AKIRA]   non_sequential_writes=5
[AKIRA]   pid_frozen=True
[AKIRA]   severity=HIGH
[AKIRA]   entropy_delta=6.965
[AKIRA]   pattern=non_sequential
```

SILENT_ENCRYPTION emitted at the 5th non-sequential write, HIGH severity, PID
added to `_frozen_pids` (the in-kernel block mirror). Commit `1add3d6`.

---

## 2 — QILIN → entropy-ext filter + realistic canaries (Defenses #2 / #3)

**Technique reproduced (safe):** rename each sandbox file to a **7-char** random
alphanumeric extension (e.g. `.a1b2c3d`), built from distinct chars so its
Shannon entropy is `log2(7)=2.81 ≥` the 2.5-bit detector floor. The old filter
required 8–16 chars; the new entropy filter is length-independent, so a 7-char
extension is still flagged. A recon **pre-scan** `stat()`s every file (including
canaries) before renaming.

**Validation:**
- *Defense #2* — `_looks_encrypted()` flagged **24/24** renamed files; the
  velocity-gated `observe_rename()` emitted `PROCESS_ANOMALY`.
- *Defense #3* — canaries placed by the production `graph.FilesystemGraph`
  engine are non-empty and backdated, so a size/age-sampling recon skips none.

```
[QILIN] ✓ defense=#2 entropy-ext filter + #3 realistic canaries signal=ENCRYPTED_RENAME / canary-realism -> TRIGGERED
[QILIN]   files_harmed=0
[QILIN]   ext_len=7
[QILIN]   short_ext_flagged=24/24
[QILIN]   rename_signal=PROCESS_ANOMALY
[QILIN]   canaries_placed=30
[QILIN]   canary_min_size_b=20983       # >= 20 KB (Defense #3: non-empty)
[QILIN]   canary_min_age_days=35.5      # >= 30 days backdated (Defense #3: aged)
[QILIN]   canaries_skipped_by_recon=0   # recon cannot filter them out
```

Commit `dfba192`.

---

## 3 — LOCKBIT5 → backup-destruction + bounded burst (Defenses #4 / #5)

**Technique reproduced (safe):**
- *Defense #4* — run a **harmless** subprocess
  `echo vssadmin delete shadows /all /quiet`. `echo` only prints its arguments
  (`returncode=0`, no shadow copy touched), but the argv carries the
  backup-destruction keywords. The same argv is fed to `observe_execve()`.
- *Defense #5* — a **bounded** `ThreadPoolExecutor(max_workers=10)` (capped 8–12,
  no unbounded spawning) renames sandbox files to 16-char extensions: a
  controlled burst that models a rate-limit-worthy flood without flooding the
  host.

**Validation:**

```
[LOCKBIT5] ✓ defense=#4 backup-destruction + #5 per-PID rate limit signal=BACKUP_DESTRUCTION / rate-limit -> TRIGGERED
[LOCKBIT5]   files_harmed=0
[LOCKBIT5]   echo_stdout=vssadmin delete shadows /all /quiet
[LOCKBIT5]   echo_returncode=0
[LOCKBIT5]   echo_destructive=False
[LOCKBIT5]   exec_signal=BACKUP_DESTRUCTION
[LOCKBIT5]   exec_keywords=['vssadmin']
[LOCKBIT5]   parent_frozen=True
[LOCKBIT5]   burst_workers=10
[LOCKBIT5]   burst_renames=10
[LOCKBIT5]   burst_signal=PROCESS_ANOMALY
[LOCKBIT5]   burst_family=lockbit5
[LOCKBIT5]   kernel_rate_limit_wired=True
```

`observe_execve()` emitted CRITICAL `BACKUP_DESTRUCTION` and froze the **parent**
PID (the would-be ransomware). The bounded burst produced a
lockbit5-profiled `PROCESS_ANOMALY`, and the generated BPF source was confirmed
to carry `BPF_PERCPU_HASH(rate_state…)`, `#define RATE_LIMIT`, `__rate_limited`,
wired into ≥4 hot-path handlers. Commit `07c03f2`.

> **Why rate limiting is asserted, not observed.** The rate limiter
> (`RATE_LIMIT` = 500 events/ms) is implemented **only** in the kernel
> per-CPU map; there is no userspace mirror to call. As with the session_08
> selftest, validation confirms the enforcement code is present and wired. A
> live `sudo -E` run on a BCC host would exercise the actual throttling.

---

## How to reproduce

```bash
source venv/bin/activate
PYTHONPATH=. python -m simulations.sim_akira   --validate-defense --target /tmp/rsentry_sandbox_a
PYTHONPATH=. python -m simulations.sim_qilin   --validate-defense --target /tmp/rsentry_sandbox_q
PYTHONPATH=. python -m simulations.sim_lockbit --validate-defense --target /tmp/rsentry_sandbox_l
```

Each prints a `✓ … TRIGGERED` banner and `files_harmed=0`. The legacy attack
path (no `--validate-defense`) is unchanged and still drives a running sensor.

## Follow-ups / not done

- Kernel-side enforcement (inline `blocked_pids`, `bpf_send_signal`, LSM
  `-EPERM`, per-PID rate throttling) was **not** loaded/verified here — no
  root/BCC in this environment. Recommend a `sudo -E python -m agent.monitor`
  smoke test on a BCC host (kernel ≥6.19, BCC ≥0.35) running each
  `--validate-defense` simulation to confirm the live kernel path.
