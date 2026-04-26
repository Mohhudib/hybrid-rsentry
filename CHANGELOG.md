# Changelog

All notable changes to Hybrid R-Sentry are documented here.

---

## [1.0.0] — 2026-04-27

### Added
- **Detection Engine** — Shannon entropy analysis, process lineage scoring, canary file monitoring
- **Markov Chain Repositioner** — adaptive canary placement based on filesystem access patterns
- **Auto-Containment Pipeline** — SIGSTOP → evidence capture → iptables DROP → SIGKILL
- **AI Threat Analyst** — LLM-powered event and alert classification with dual API key rotation
- **System Health Check** — AI analysis of recent activity patterns
- **Auto-ACK** — automatically acknowledges alerts classified as Benign or LOW risk
- **Live Dashboard** — React 18 with real-time WebSocket feed (3 Redis pub/sub channels)
- **Alert Management** — per-alert ACK, bulk acknowledge, live count badges
- **Host Risk Gauge** — radial score that recalculates after every acknowledgement
- **False Positive Suppression** — whitelist system for browsers, package managers, system paths, archives
- **Celery Workers** — AI analysis, WebSocket push, host risk scoring, auto-ACK tasks
- **REST API** — events, alerts (`/counts` endpoint), hosts, containment endpoints
- **Docker Compose** — PostgreSQL + Redis infrastructure
- **GitHub Wiki** — 10-page documentation covering architecture, detection engine, containment, API reference, and more
- **Dependabot** — weekly dependency scanning for pip, npm, and Docker

### Known Limitations
- Alembic migrations not yet implemented (uses `create_all` on startup)
- Reports page is a placeholder
- GitHub Actions CI/CD pipeline not yet configured
- No authentication layer on the backend API
