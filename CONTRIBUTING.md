# Contributing to Hybrid R-Sentry

Thank you for your interest in contributing. This document explains how to get started.

---

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/hybrid-rsentry.git`
3. Run the setup script: `bash setup.sh`
4. Copy and configure your environment: edit `.env` with your API keys and paths
5. Start infrastructure: `docker compose up -d`

---

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable releases only |
| `develop` | Active development — base all PRs here |
| `feature/your-feature` | New features |
| `fix/your-fix` | Bug fixes |

Always branch off `develop`, never `main`.

---

## Making Changes

- Keep changes focused — one feature or fix per PR
- If touching `agent/` code, test that it does not generate false positive alerts on a live system
- If adding new environment variables, add them to `.env.example` with a placeholder value
- Update the [Wiki](https://github.com/Mohhudib/hybrid-rsentry/wiki) if you change any behaviour

---

## Commit Style

Use short, descriptive prefixes:

```
feat: add new detection module
fix: resolve false positive on /tmp writes
docs: update API reference
chore: bump asyncpg to 0.31.0
refactor: simplify lineage scorer
```

---

## Pull Requests

- Open PRs against `develop`
- Fill in the PR template fully
- PRs that introduce new false positives will not be merged

---

## Reporting Bugs

Use the [Bug Report](https://github.com/Mohhudib/hybrid-rsentry/issues/new?template=bug_report.md) issue template.

## Suggesting Features

Use the [Feature Request](https://github.com/Mohhudib/hybrid-rsentry/issues/new?template=feature_request.md) issue template.

---

## Contact

For questions or security vulnerabilities: **mohammadhudib960@gmail.com**
