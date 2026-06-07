# Session 08 — Defensive Detection Hardening (eBPF sensor + canary engine)

**Date:** 2026-06-07
**Scope:** `agent/monitor_ebpf.py`, `agent/graph.py` (and a latent-bug fix in `monitor_ebpf.py` exposed by the work). `agent/monitor.py` was read for context only.
**Goal:** Add 6 defensive detection improvements, each committed separately, with agent selftests run after every change.

## Result

| Suite | Checks passing | Status |
|---|---|---|
| `python -m agent.monitor_ebpf --selftest` | 93 | ALL PASS |
| `python -m agent.monitor --selftest` | 16 | ALL PASS |

0 failures across both suites after every commit.

> **Note on BPF C verification:** the selftests run without root/BCC, so they exercise the **userspace** detection logic directly and assert the generated BPF C source (via `build_bpf()`) is well-formed and contains the expected maps/helpers/hooks. The kernel programs themselves are not loaded/verified in this environment — that requires `sudo -E` on a BCC-equipped host (kernel ≥6.19, BCC ≥0.35). All BPF C was checked for unresolved f-string placeholders and brace balance in every `(enforce, lsm)` variant.

---

## Commits

```
858169a feat(ebpf): write-offset tracking → SILENT_ENCRYPTION + PID freeze (1/6)
c5d9946 feat(ebpf): entropy-based ransomware-extension filter (2/6)
cac2197 feat(agent): realistic canary content + backdated mtimes (3/6)
e2e4ffb feat(ebpf): block backup-destruction tooling at execve (4/6)
63064dd feat(ebpf): per-PID per-CPU rate limiting (5/6)
5471052 feat(ebpf): fail-secure agent heartbeat (6/6)
```

---

## 1 — Write-offset tracking → SILENT_ENCRYPTION + PID freeze

**Why:** In-place ransomware encrypts files without renaming or changing the
extension, so rename/extension heuristics miss it. The tell is the *access
pattern*: a read-modify-write storm whose write offsets jump around the file
instead of advancing sequentially.

**Kernel:** new `BPF_HASH(write_offset, u64 inode → struct woff_t{last_end, nonseq})`.
`kprobe__vfs_write` reads the write offset (`PT_REGS_PARM4`) and length
(`PT_REGS_PARM3`); when `offset != previous_end` it increments a per-inode
non-sequential counter. After `NONSEQ_THRESH` (5) consecutive non-sequential
writes it sets `blocked_pids[pid]` inline, flags `write_event.silent_enc`, and
submits the event regardless of the burst threshold.

**Userspace:** `DetectionEngine.observe_write_offset()` mirrors the logic as the
unit-testable source of truth — emits `SILENT_ENCRYPTION` (HIGH) and adds the
PID to `_frozen_pids` / `_active_pids`. `_handle_write` honours the kernel
`silent_enc` flag, arms `blocked_pids`, and queues containment.

**Tests:** sequential writes never alert; a non-sequential storm trips
SILENT_ENCRYPTION; PID frozen; self-PID/ignored-comm suppression; BPF source carries the map + flag.

---

## 2 — Entropy-based ransomware-extension filter

**Why:** The old filter flagged any 8–16 char alphanumeric extension — both too
narrow (misses short random extensions) and length-coupled.

**Change:** `_looks_encrypted()` now flags any alphanumeric extension whose
**Shannon entropy ≥ 2.5 bits/char**, regardless of length (new `_shannon_entropy()`
helper). Normal extensions stay below the line (`.docx`≈2.0, `.pdf`≈1.58,
`.xlsx`≈1.5, `.jpg`≈2.0); random ransomware extensions clear it (6-char
distinct≈2.585, 16-char≈4.0). Known `_ENC_SUFFIXES` and `_BENIGN_SUFFIXES`
short-circuits are unchanged.

> Entropy floor reminder: a string of N distinct chars has max entropy log2(N);
> to reach 2.5 you need ≥6 distinct chars, so the shortest detectable random
> extension is 6 chars — still shorter than the old 8-char minimum.

**Tests:** `.docx`/`.pdf`/`.xlsx`/`.jpg` not flagged; high-entropy 6/8/16-char
flagged; `.enc` still flagged; `.bak`/low-entropy-repeat not flagged; helper edge cases.

### Latent bug fixed in the same commit (exposed by variable-length fixtures)

`observe_rename()` called `_profile_family(dst_path, list(self._velocity[pid]))`
— passing the **velocity timestamp deque (floats)** where the function expects
**file paths**. `Path(<float>)` raises `TypeError`. This crashed on *any*
encrypted rename whose extension was not exactly 16 chars and not `.akira`
(those hit early returns in `_profile_family`). It was masked only because the
old selftest fixtures used 16-char extensions. The new variable-length
extensions surfaced it. **Fix:** track a per-PID `_path_history` deque of
destination paths and feed *that* to the ESXi heuristic. This was a real
production crash path in the rename perf-buffer callback, not just a test issue.

---

## 3 — Realistic canary content + backdated mtimes (`graph.py`)

**Why:** Canaries were 28-byte plaintext stubs with fresh mtimes — trivially
skippable by ransomware that samples file size/type or sorts targets by age.

**Change:** `place_canaries()` now writes 20–100 KB of realistic bytes starting
with a genuine **PDF (`%PDF-1.7…`) or DOCX/OOXML (`PK\x03\x04…`) magic header**
(`_canary_content()`), then backdates atime/mtime **30–400 days** via
`os.utime()` (`_backdate()`). Prefix/naming/cleanup-glob behaviour unchanged
(suffix kept `.txt` so the existing cleanup glob still matches).

**Verification:** direct check (graph.py has no selftest) — 30 canaries placed,
sizes 22–98 KB, ages 53–371 days, valid magic headers, correct prefixes. Agent
selftests still green.

---

## 4 — Block backup-destruction tooling at execve

**Why:** Spawning `vssadmin` / `bcdedit` / `wbadmin` / `shadowcopy` is an
unambiguous ransomware pre-encryption step (destroy recovery points).

**Kernel:** `sys_enter_execve` reads the exec filename + `argv[1]` and runs an
in-kernel substring matcher `__is_backup_destruct()` over them. On match it
arms `blocked_pids` for both child and parent, `bpf_send_signal(SIGKILL)`s the
child inline, and submits an `exec_event`. New LSM hook
`bprm_check_security` returns **-EPERM** for any blocked PID. Kill/block runs
only in **enforce** mode; audit still detects + emits.

**Userspace:** `observe_execve()` (source of truth) emits CRITICAL
`BACKUP_DESTRUCTION` and marks the **parent** frozen; `_handle_exec` SIGKILLs
the parent (the ransomware that spawned the tool).

**Tests:** each keyword detected (incl. inside a path arg); benign argv / empty
argv / self-PID → no alert; parent marked + frozen; BPF source has the matcher,
`bpf_send_signal(SIGKILL)`, and `bprm_check_security`; audit build detects but does not kill.

---

## 5 — Per-PID per-CPU rate limiting

**Why:** A flooding/runaway process could saturate the perf buffers and the
userspace score queue.

**Change:** new `BPF_PERCPU_HASH(rate_state, u32 → struct rate_t{win_ms, count})`
+ `__rate_limited()` helper. Any PID exceeding **RATE_LIMIT (500) events per
millisecond** is throttled (handler returns early). Gated at the top of all
four hot-path handlers: rename, unlink, openat, vfs_write. Per-CPU map avoids
hot-path spinlock contention.

**Tests:** source asserts the percpu map, `RATE_LIMIT` define, helper, per-ms
window, and that the check is wired into ≥4 handlers.

---

## 6 — Fail-secure agent heartbeat

**Why:** If the agent crashes, the system should not be left silently
unprotected.

**Change:** new `BPF_ARRAY(heartbeat, u64, 1)` + `__heartbeat_stale()`. A daemon
thread writes a fresh timestamp every second; both LSM hooks (`path_rename`,
`bprm_check_security`) return **-EPERM** when the heartbeat is stale **>2s**.
`hb==0` is treated as not-yet-initialized (allow) so startup doesn't brick
before the first pulse.

### ⚠️ Deliberate deviation from the literal spec (clock domain)

The task said *"Python thread writes `time.time_ns()`"*. The in-kernel
comparator is `bpf_ktime_get_ns()`, which is **CLOCK_MONOTONIC** (ns since
boot). Wall-clock `time.time_ns()` is a different clock domain — comparing the
two would make the heartbeat read as **permanently stale**, so the LSM hooks
would deny *every* rename and exec system-wide and brick the host. There is no
stable BPF helper for wall-clock ns to compare against.

**Resolution:** the writer uses `time.clock_gettime_ns(time.CLOCK_MONOTONIC)`,
which matches the kernel clock, so the staleness math is valid. The behavioural
intent — *write a timestamp every second, deny when stale, fail-secure on agent
death* — is fully preserved; only the clock **source** was corrected. This is
documented in the code and the commit message.

### Operational caveat

This gate is intentionally aggressive: while active (enforce+lsm), an agent
crash denies **all** renames/execs system-wide until the agent restarts. That
is the requested fail-secure posture, but operators should be aware before
enabling `lsm=bpf` enforcement on production hosts.

---

## Architecture pattern used throughout

Every detection rule is implemented twice on purpose:
- **Kernel (BPF C in `build_bpf()`)** — the fast inline enforcement path
  (`blocked_pids`, `bpf_send_signal`, LSM `-EPERM`).
- **Userspace (`DetectionEngine` methods)** — the unit-testable *source of
  truth* that re-derives/enriches the decision and emits the event.

The userspace mirror is what the selftests exercise; the kernel side is the
enforcement actuator. New maps/structs/helpers were added as hoisted plain
Python strings interpolated into the `build_bpf()` f-string to avoid
PEP-701 brace-doubling pitfalls (same convention as the pre-existing
`_lsm_hook`).

## Follow-ups / not done

- BPF programs were not loaded/verified (no root/BCC here). Recommend a
  `sudo -E python -m agent.monitor --mode enforce` smoke test plus the existing
  simulations on a BCC host to confirm the new maps/probes load and the verifier
  accepts the unrolled `__is_backup_destruct` matcher and percpu rate logic.
