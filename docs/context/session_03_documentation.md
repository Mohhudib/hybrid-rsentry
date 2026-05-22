# Session 03 — Documentation

**Date:** 2026-05-12  
**Goal:** Write documentation for contributors and team members.  
**Commits:** `011e3dd` (CONTRIBUTING), `b92a3cd` (README security section), `da7afcf` (CLAUDE.md)

---

## What was created

### CONTRIBUTING.md — 7-step forking guide
Added a complete guide for external contributors:
1. Fork the repo on GitHub
2. Clone your fork locally
3. Add the upstream remote (`git remote add upstream ...`)
4. Set up the environment (`setup.sh`)
5. Create a branch (`git checkout -b feature/your-feature`)
6. Make changes and commit
7. Open a pull request

Also added a "Keeping Your Fork in Sync" section covering `fetch upstream → merge → push origin`.

---

### README.md — Security section
Added a "Security" section before Contributing with:
- Table of 3 fixed vulnerabilities (CVEs, scope, fix detail)
- Explanation of why the 26 Dependabot npm alerts are not runtime risk
- Link to SECURITY.md
- Updated Environment Variables table to include `POSTGRES_PASSWORD`
- Note that `DATABASE_URL` is now required with no default

---

### CLAUDE.md — Team debugging context file
Created at project root. Auto-loaded by Claude Code every time any team member opens the repo.

Contains:
- 5-process architecture table
- Startup sequence (all 5 terminals)
- Key file map (what each file does)
- Required `.env` variables with descriptions
- Hard rules (things that have broken the project before, must never be done)
- Known issues and their exact fixes
- Alert severity logic table
- Safe diagnostic commands (docker exec psql, redis-cli subscribe, curl)
- Debugging approach reminder (identify which terminal the error is in first)

Team members not using Claude Code should paste the file contents at the start of any AI chat session for the same context.
