# Known Code Issues

These issues were found by `ruff` during CI setup on 2026-05-25.
They are currently ignored in CI (`--ignore E712,F401,F841`) so the pipeline stays green.
Each one should be fixed in a dedicated cleanup pass.

---

## F401 — Unused imports

| File | Line | Import |
|------|------|--------|
| `agent/client.py` | 8 | `uuid` |
| `agent/client.py` | 10 | `typing.Any` |
| `agent/entropy.py` | 6 | `math` |
| `agent/lineage.py` | 8 | `pathlib.Path` |
| `agent/monitor.py` | 8 | `sys` |
| `agent/monitor.py` | 14 | `watchdog.events.FileClosedEvent` |
| `agent/monitor.py` | 15 | `watchdog.events.FileCreatedEvent` |
| `agent/monitor.py` | 16 | `watchdog.events.FileDeletedEvent` |
| `agent/monitor.py` | 17 | `watchdog.events.FileModifiedEvent` |
| `agent/monitor.py` | 18 | `watchdog.events.FileMovedEvent` |
| `backend/models/__init__.py` | 1 | `Base` (re-export — use `Base as Base`) |
| `backend/models/__init__.py` | 1 | `get_db` (re-export — use `get_db as get_db`) |
| `backend/models/__init__.py` | 1 | `engine` (re-export — use `engine as engine`) |
| `backend/models/__init__.py` | 3 | `Host` (re-export — use `Host as Host`) |
| `backend/models/__init__.py` | 3 | `Event` (re-export — use `Event as Event`) |
| `backend/models/__init__.py` | 3 | `Alert` (re-export — use `Alert as Alert`) |
| `backend/models/__init__.py` | 3 | `Evidence` (re-export — use `Evidence as Evidence`) |
| `backend/models/__init__.py` | 4 | `EventCreate` (re-export — use `EventCreate as EventCreate`) |
| `backend/models/__init__.py` | 4 | `AlertCreate` (re-export — use `AlertCreate as AlertCreate`) |
| `backend/models/__init__.py` | 4 | `EvidenceCreate` (re-export — use `EvidenceCreate as EvidenceCreate`) |
| `backend/routers/events.py` | 15 | `AlertResponse` |
| `backend/routers/hosts.py` | 4 | `uuid` |
| `backend/workers/tasks.py` | 15 | `Event` |

**Fix:** Remove each unused import, or for `backend/models/__init__.py` re-exports use the explicit `X as X` form to declare them intentional.

---

## F841 — Unused variables

| File | Line | Variable | Context |
|------|------|----------|---------|
| `agent/containment.py` | 190 | `rule` | String built but never used — only `cmd` list is passed to subprocess |
| `backend/services/ai_analyst.py` | 128 | `e` | `except AuthenticationError as e` — `e` is never logged or re-raised |

**Fix:**
- `containment.py:190` — delete the `rule = ...` line entirely.
- `ai_analyst.py:128` — change to `except AuthenticationError` (drop `as e`).

---

## E712 — Equality comparison to `False` (SQLAlchemy ORM)

| File | Line | Code |
|------|------|------|
| `backend/workers/tasks.py` | 122 | `Alert.acknowledged == False` |
| `backend/workers/tasks.py` | 229 | `Alert.acknowledged == False` |
| `backend/workers/tasks.py` | 271 | `Alert.acknowledged == False` |
| `backend/workers/tasks.py` | 307 | `Alert.acknowledged == False` |

**Note:** These are SQLAlchemy ORM column comparisons, not plain Python boolean checks.
`== False` is valid and intentional here — SQLAlchemy overloads `==` to generate SQL `WHERE acknowledged = FALSE`.
The correct long-term fix is to add `# noqa: E712` to each line, or configure ruff to ignore E712 globally in a `ruff.toml`.

---

## ESLint — Fixed

| File | Line | Issue | Status |
|------|------|-------|--------|
| `frontend/src/components/FileSystemTree.jsx` | 1 | `useRef` imported but never used | **Fixed** (commit `6f0c77a`) |
