# Project Context — Development History

This folder documents everything that was built, fixed, and decided during the development of Hybrid R-Sentry from the first session to the latest. It is meant for collaborators, future contributors, and for picking up exactly where the project left off.

## Sessions

| File | Date | What happened |
|---|---|---|
| [session_01_initial_setup.md](session_01_initial_setup.md) | 2026-04-17 | Initial Kali deployment — 9 environment problems hit and fixed |
| [session_02_security_audit.md](session_02_security_audit.md) | 2026-05-12 | Security audit — 3 real vulnerabilities fixed, CVEs removed |
| [session_03_documentation.md](session_03_documentation.md) | 2026-05-12 | CONTRIBUTING guide, README security section, CLAUDE.md created |
| [session_04_full_review.md](session_04_full_review.md) | 2026-05-22 | Full code review — 6 logic/config bugs found and fixed |
| [session_05_github_cleanup.md](session_05_github_cleanup.md) | 2026-05-22 | GitHub audit — broken LICENSE fixed, dead wiki links removed, 9 PRs closed |
| [session_06_full_code_review.md](session_06_full_code_review.md) | 2026-06-06 | Full codebase review — 4 parallel review agents across backend/agent/frontend/sims, dead code and improvement findings |
| [session_07_ransomware_benchmark.md](session_07_ransomware_benchmark.md) | 2026-06-07 | Ransomware detection benchmark — Akira, Qilin, LockBit 5.0 against the eBPF DetectionEngine |
| [session_07_test_results.md](session_07_test_results.md) | 2026-06-07 | Full automated test sweep results and coverage analysis |
| [session_08_hardening.md](session_08_hardening.md) | 2026-06-07 | 6 defensive detection hardening improvements added to the eBPF sensor and canary engine |
| [session_09_defense_validation.md](session_09_defense_validation.md) | 2026-06-07 | Ransomware simulations exercised against session 08's hardening to validate the defenses |
| [session_10_pipeline_test.md](session_10_pipeline_test.md) | 2026-06-07 | Full end-to-end live integration test — Docker stack, FastAPI, Celery, Postgres, Redis, WebSocket, plus full pytest suite |
| [session_dev_log_jun13.md](session_dev_log_jun13.md) | 2026-06-13 | Full cleanup, feature sprint, and hardening session — 66 commits in one session |
## Project Reference

| File | Contents |
|---|---|
| [project_architecture.md](project_architecture.md) | Full stack, components, data flow, .env reference |
| [startup_guide.md](startup_guide.md) | Correct startup commands (the ones that actually work) |
