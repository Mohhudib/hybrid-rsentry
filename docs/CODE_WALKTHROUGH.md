# Hybrid R-Sentry — Complete Code Walkthrough

Every file, every significant block, fully explained. What it does, why it exists, and how it connects to everything else.

---

## System Architecture — The Big Picture

```
┌────────────────────────────────────────────────────────────────┐
│                          KALI LINUX                            │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                     Agent Layer                          │  │
│  │                                                          │  │
│  │  ┌────────────────┐        ┌──────────────────────────┐  │  │
│  │  │  monitor.py    │  OR    │  monitor_ebpf.py          │  │  │
│  │  │  (inotify /    │        │  (TRACEPOINT_PROBE,       │  │  │
│  │  │   watchdog)    │        │   velocity burst,         │  │  │
│  │  │                │        │   family profiling,       │  │  │
│  │  │                │        │   BCC 0.35, kernel 6.19+) │  │  │
│  │  └───────┬────────┘        └────────────┬─────────────┘  │  │
│  │          └─────────────┬───────────────┘                 │  │
│  │                        ▼                                 │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │  │
│  │  │lineage.py│  │ adaptive.py  │  │containment.py     │  │  │
│  │  │ (psutil) │  │(Markov chain)│  │(SIGSTOP→evidence→ │  │  │
│  │  └──────────┘  └──────────────┘  │ iptables→SIGKILL) │  │  │
│  │  ┌──────────┐  ┌──────────────┐  └───────────────────┘  │  │
│  │  │exceptions│  │entropy.py    │                          │  │
│  │  │(whitelist)│  │(Shannon LRU) │                          │  │
│  │  └──────────┘  └──────────────┘                          │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │  HTTP POST /api/events             │
│  ┌─────────────────────────▼────────────────────────────────┐  │
│  │               backend/ (FastAPI)                         │  │
│  │  main.py → routers/events.py → routers/alerts.py         │  │
│  │         → routers/hosts.py  → routers/ws.py              │  │
│  │         → workers/tasks.py  → services/ai_analyst.py     │  │
│  └──────┬───────────────────────────────┬────────────────────┘  │
│         │  PostgreSQL (persist)          │  Redis pub/sub        │
│  ┌──────▼───────────────────────────────▼────────────────────┐  │
│  │         frontend/ (React 19, Vite 5 — SIEM layout)        │  │
│  │  App.jsx: TopBar + StatusBar                               │  │
│  │    → AlertsPage (FacetRail + histogram + D3 graph)        │  │
│  │    → AIAnalystPage → HostsPage → ReportsPage              │  │
│  └────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

**Full event journey:**
1. File changes on disk → `watchdog` (inotify) OR `TRACEPOINT_PROBE` (eBPF) fires
2. Sensor routes event through `monitor.py` / `monitor_ebpf.py` — entropy, lineage, extension check
3. Monitor scores it → sends HTTP POST to backend
4. `events.py` persists to PostgreSQL → fires Celery tasks
5. Celery: pushes to Redis pub/sub, runs AI analysis, updates risk score
6. `ws.py` listens to Redis → broadcasts over WebSocket
7. `App.jsx` receives WebSocket message → updates React state → SIEM dashboard re-renders

---

## BACKEND

---

### `backend/models/schemas.py` — The Data Foundation

**Role:** Defines every database table (SQLAlchemy ORM) and every API shape (Pydantic). Every other file imports from here. Nothing can be stored or transmitted without going through these definitions.

---

```python
class EventType(str, PyEnum):
    CANARY_TOUCHED = "CANARY_TOUCHED"
    ENTROPY_SPIKE = "ENTROPY_SPIKE"
    PROCESS_ANOMALY = "PROCESS_ANOMALY"
    COMBINED_ALERT = "COMBINED_ALERT"
    CONTAINMENT_TRIGGERED = "CONTAINMENT_TRIGGERED"
    CONTAINMENT_COMPLETE = "CONTAINMENT_COMPLETE"
    HEARTBEAT = "HEARTBEAT"

class Severity(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
```

**Why enums?** `str, PyEnum` makes these both a Python enum AND a plain string — so PostgreSQL stores them as readable text (`"CRITICAL"` not `2`) and JSON serialization works without extra conversion. The `EventType` values map exactly to what the agent sends and what the frontend displays.

---

```python
class Host(Base):
    __tablename__ = "hosts"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id      = Column(String(255), unique=True, nullable=False, index=True)
    last_seen    = Column(DateTime(timezone=True), ...)
    is_contained = Column(Boolean, default=False)
    risk_score   = Column(Float, default=0.0)
    events       = relationship("Event", back_populates="host", lazy="dynamic")
    alerts       = relationship("Alert", back_populates="host", lazy="dynamic")
```

**Why two IDs?** `id` is the internal UUID primary key (never exposed to humans). `host_id` is the human-readable string from `.env` (e.g. `"ATOMIC"`). `lazy="dynamic"` means SQLAlchemy returns a query object rather than loading all related rows into memory — critical when a host has thousands of events.

---

```python
class Event(Base):
    __tablename__ = "events"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id       = Column(String(255), ForeignKey("hosts.host_id"), ...)
    event_type    = Column(Enum(EventType), nullable=False)
    severity      = Column(Enum(Severity), nullable=False)
    pid           = Column(Integer, nullable=True)
    lineage_score = Column(Float, default=0.0)
    entropy_delta = Column(Float, default=0.0)
    canary_hit    = Column(Boolean, default=False)
    details       = Column(JSON, nullable=True)
    alert         = relationship("Alert", back_populates="event", uselist=False)
```

**Why `details` as JSON?** Different event types carry different extra data. A `MARKOV_REPOSITION` carries `{moved: [...], hotspots: [...]}`. A `CONTAINMENT_TRIGGERED` carries `{pid, process_name}`. Using a JSON column means we don't need a separate table for each event type. `uselist=False` on `alert` means one Event maps to at most one Alert (1:1 relationship).

---

```python
class Alert(Base):
    __tablename__ = "alerts"
    id           = Column(UUID(as_uuid=True), primary_key=True, ...)
    event_id     = Column(UUID(as_uuid=True), ForeignKey("events.id"), unique=True)
    severity     = Column(Enum(Severity), nullable=False)
    acknowledged = Column(Boolean, default=False)
    created_at   = Column(DateTime(timezone=True), ...)
    resolved_at  = Column(DateTime(timezone=True), nullable=True)
    evidence     = relationship("Evidence", back_populates="alert", lazy="dynamic")
```

**Why is `event_id` unique?** One event can only produce one alert — prevents duplicate alerts from retries or race conditions. `resolved_at` is null until the alert is acknowledged, either manually or by AI/containment auto-ack. The `acknowledged` flag is the primary field the frontend filters on.

---

```python
class Evidence(Base):
    __tablename__ = "evidence"
    alert_id      = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), ...)
    pid           = Column(Integer, nullable=True)
    evidence_dir  = Column(Text, nullable=True)
    files         = Column(JSON, nullable=True)
    iptables_rule = Column(Text, nullable=True)
    raw_data      = Column(JSON, nullable=True)
```

**Role:** Stores the forensic evidence captured during containment. `evidence_dir` is the path under `/tmp/rsentry_evidence/` where `/proc/PID/` artifacts were copied. `files` is the list of captured file paths. `iptables_rule` is the exact command that was run to block the process's network traffic.

---

```python
class EventCreate(BaseModel):
    host_id:       str
    timestamp:     datetime
    event_type:    EventType
    severity:      Severity
    lineage_score: float = Field(ge=0.0, le=100.0, default=0.0)
    entropy_delta: float = Field(ge=0.0, le=8.0, default=0.0)
    canary_hit:    bool = False
    details:       dict[str, Any] = Field(default_factory=dict)
```

**Why Pydantic?** FastAPI uses `EventCreate` to validate the HTTP request body from the agent. `Field(ge=0.0, le=8.0)` means FastAPI will reject any event where entropy is outside 0–8 before the endpoint code even runs — data integrity enforced at the boundary. The `EventResponse` and other `*Response` classes add `class Config: from_attributes = True` so SQLAlchemy ORM objects can be serialized directly.

**Connects to:** Every other backend file imports `Severity`, `EventType`, `Event`, `Alert`, `Host`, `Evidence` from here.

---

### `backend/main.py` — FastAPI Entry Point

**Role:** Creates the FastAPI application, connects all routers, sets up CORS, creates database tables on startup, and exposes the AI health check endpoint.

---

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured.")
    yield
    await engine.dispose()
    logger.info("Database engine disposed.")
```

**Why lifespan?** FastAPI's modern way to run startup/shutdown code. `create_all` creates all tables defined in `schemas.py` if they don't already exist — this is why you don't need to run migrations manually every time. After `yield` is the shutdown code: `engine.dispose()` closes all database connections cleanly.

---

```python
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173",
).split(",")

app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, ...)
```

**Why CORS?** The React frontend runs on `localhost:3000` and the backend on `localhost:8000` — different ports = different origins = browser blocks the requests by default. CORS middleware tells the browser "this API allows requests from React's dev server." `allow_credentials=True` is needed for cookies/auth headers.

---

```python
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(hosts.router)
app.include_router(ws.router)
```

**Why routers?** Each router owns its own URL prefix (`/api/events`, `/api/alerts`, etc.) and is defined in a separate file. `include_router` plugs them all into the single app. This keeps files small and focused.

---

```python
class HealthCheckRequest(BaseModel):
    events: list[dict] = []

@app.post("/api/ai/health")
async def ai_health_check(body: HealthCheckRequest):
    from backend.workers.tasks import analyze_health_ai
    analyze_health_ai.delay(body.events[:100])
    return {"status": "analysis_queued"}
```

**Why is this in main.py, not a router?** It's a single endpoint that doesn't fit neatly into any router category. It accepts up to 100 recent events, fires a Celery task to analyze them asynchronously, and immediately returns — the result arrives later via WebSocket. `[:100]` caps the payload to prevent the AI from being sent thousands of events.

**Connects to:** `database.py` (engine), all four routers, `tasks.py` (via the health endpoint).

---

### `backend/routers/events.py` — Event Ingestion Pipeline

**Role:** The most important backend file. Receives every detection event from the agent, persists it, decides whether to create an alert, and fires all downstream tasks.

---

```python
ALERT_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}

async def _upsert_host(db: AsyncSession, host_id: str) -> Host:
    result = await db.execute(select(Host).where(Host.host_id == host_id))
    host = result.scalar_one_or_none()
    if host is None:
        host = Host(host_id=host_id)
        db.add(host)
    host.last_seen = datetime.now(timezone.utc)
    await db.flush()
    return host
```

**Why `_upsert_host`?** The agent sends a `host_id` string with every event. This function ensures that host record exists before the event foreign key is created — if the host isn't in the DB yet, it creates it. `last_seen` is updated on every event so `HostsPage` can show "last seen X ago." `flush()` writes to DB within the current transaction without committing, so the host ID exists for the event's foreign key.

---

```python
sub_type = (payload.details or {}).get("sub_type", "")
is_internal = (
    sub_type == "MARKOV_REPOSITION" or
    (sub_type == "moved" and payload.pid == 0)
)
```

**Why this check?** The Markov chain repositioner moves canary files on purpose — those moves would normally trigger CRITICAL alerts because a canary was touched. `is_internal` identifies these benign internal events so they don't create false alert records. `pid == 0` is the signature of an internal move (no real process ID, since the repositioner itself did it).

---

```python
event = Event(
    host_id=payload.host_id,
    timestamp=payload.timestamp,
    event_type=payload.event_type,
    severity=payload.severity,
    pid=payload.pid,
    ...
)
db.add(event)
await db.flush()

alert: Optional[Alert] = None
if payload.severity in ALERT_SEVERITIES and not is_internal:
    alert = Alert(
        event_id=event.id,
        host_id=payload.host_id,
        severity=payload.severity,
    )
    db.add(alert)
    await db.flush()

await db.commit()
```

**Flow:** Every event is always persisted (even LOW severity heartbeats). Alerts are only created for CRITICAL/HIGH/MEDIUM and only if not internal. `flush()` without `commit()` writes to DB transaction memory so IDs are generated, then `commit()` makes it permanent. This two-step flush/commit pattern ensures the alert's `event_id` foreign key points to a real event.

---

```python
push_event_ws.delay(...)

if alert:
    push_alert_ws.delay(...)
    update_host_risk.delay(payload.host_id)
    analyze_event_ai.delay(str(event.id), { ... event data dict ... })
elif is_internal and payload.severity in ALERT_SEVERITIES:
    publish_markov_analysis.delay(str(event.id))

if payload.event_type == EventType.CONTAINMENT_COMPLETE:
    auto_ack_containment.delay(payload.host_id)
    update_host_risk.delay(payload.host_id)
```

**Why `.delay()`?** `.delay()` is Celery's way of sending a task to the background worker queue. The HTTP response returns immediately while Celery handles the heavy work (database queries, NVIDIA API calls, Redis publishes). If the NVIDIA API takes 5 seconds, the agent's HTTP POST still returns in milliseconds. `publish_markov_analysis.delay` pushes a pre-built Benign AI analysis to the WebSocket for Markov events, so they appear in the AI Analyst panel without making a real API call.

**Connects to:** `schemas.py` (models), `tasks.py` (all delay calls), `database.py` (session).

---

### `backend/routers/alerts.py` — Alert Management

**Role:** CRUD for alerts. The frontend AlertsPage, the AI auto-ack system, and the containment pipeline all interact through here.

---

```python
@router.get("/counts")
async def alert_counts(db: AsyncSession = Depends(get_db)):
    counts = {}
    for sev in Severity:
        result = await db.execute(
            select(func.count()).select_from(Alert).where(
                Alert.acknowledged == False,
                Alert.severity == sev,
            )
        )
        counts[sev.value] = result.scalar_one()
    total_result = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.acknowledged == False)
    )
    counts["TOTAL"] = total_result.scalar_one()
    return counts
```

**Why a separate `/counts` endpoint?** The standard `GET /api/alerts` has a `limit` parameter — if you request 50 alerts and there are 200, the count you'd get from `len(response)` would be 50, not 200. `StatsBar.jsx` uses this endpoint to get exact counts for the dashboard stat cards without needing to load every alert record.

---

```python
@router.patch("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    alert.acknowledged = True
    alert.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    from backend.workers.tasks import update_host_risk
    update_host_risk.delay(alert.host_id)
    return alert
```

**Why call `update_host_risk` after ACK?** The risk score is calculated from unacknowledged alert counts. When you ACK an alert, the risk should drop. Without this call, the host's risk score wouldn't update until the next event arrived.

---

```python
@router.post("/{alert_id}/analyze")
async def analyze_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    # ... builds event_data dict from the alert's linked event ...
    from backend.workers.tasks import analyze_alert_ai
    analyze_alert_ai.delay(str(alert.event_id or alert_id), event_data)
    return {"queued": True, "alert_id": str(alert_id)}
```

**Why re-fetch the event?** An alert stores only `event_id`, `host_id`, and `severity` — not the full event details needed for AI analysis. This endpoint joins across to the Event table to get the full context (file path, process name, entropy, lineage score) before sending it to Celery.

---

```python
@router.get("/{alert_id}/forensic-export")
async def forensic_export(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    # Returns full alert + all evidence as JSON
```

**Why?** Incident response. After containment, security teams need a structured export of everything: what happened, what evidence was captured, what network rules were applied. This endpoint bundles it into a single JSON payload that can be saved or forwarded to a SIEM.

**Connects to:** `tasks.py` (for `update_host_risk` and `analyze_alert_ai`), `schemas.py` (Alert, Evidence models).

---

### `backend/routers/hosts.py` — Host Inventory & Risk

**Role:** Manages the host registry, serves risk summaries, and exposes contain/release endpoints.

---

```python
@router.get("/{host_id}/risk")
async def host_risk_summary(host_id: str, db: AsyncSession = Depends(get_db)):
    alert_counts = {}
    for sev in Severity:
        count_result = await db.execute(
            select(func.count()).select_from(Alert).where(
                Alert.host_id == host_id,
                Alert.severity == sev,
                Alert.acknowledged == False,
            )
        )
        alert_counts[sev.value] = count_result.scalar_one()

    recent_critical = ...  # last 5 CRITICAL events

    return {
        "host_id": host_id,
        "risk_score": host.risk_score,
        "is_contained": host.is_contained,
        "open_alerts": alert_counts,
        "recent_critical_events": [...],
    }
```

**Why not just use `host.risk_score`?** The stored `risk_score` is a cached float updated by Celery. This endpoint returns the full breakdown: how many open alerts at each severity level, plus the 5 most recent CRITICAL events with file paths and timestamps. The `HostsPage` component uses this to show context beyond just a number.

---

```python
@router.post("/{host_id}/contain")
async def contain_host(host_id: str, db: AsyncSession = Depends(get_db)):
    host.is_contained = True
    await db.commit()
    return {"status": "contained", "host_id": host_id}

@router.delete("/{host_id}/contain")
async def release_host(host_id: str, db: AsyncSession = Depends(get_db)):
    host.is_contained = False
    await db.commit()
    return {"status": "released", "host_id": host_id}
```

**Important distinction:** These endpoints mark the host as contained *in the dashboard only* — they do NOT run any actual containment commands on the endpoint. Real containment (SIGSTOP/kill/iptables) happens in `agent/containment.py`. These are administrative flags so the analyst can track which machines are under investigation.

**Connects to:** `schemas.py` (Host, Event, Alert models), `HostsPage.jsx`.

---

### `backend/routers/ws.py` — WebSocket + Redis Pub/Sub

**Role:** The live data bridge. Connects each browser session to a WebSocket that mirrors Redis pub/sub channels. Every alert, event, and AI result arrives at the frontend this way.

---

```python
ALERT_CHANNEL = "rsentry:alerts"
EVENT_CHANNEL = "rsentry:events"
AI_CHANNEL    = "rsentry:ai"

class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def broadcast(self, message: dict):
        data = json.dumps(message)
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
```

**Why track `dead` separately?** You can't remove from a list while iterating it. Collecting dead connections and removing them after the loop is safe. A connection goes "dead" when the browser tab closes — the send raises an exception, which we catch silently.

---

```python
@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.subscribe(ALERT_CHANNEL, EVENT_CHANNEL, AI_CHANNEL)

    async def redis_reader():
        async for message in pubsub.listen():
            if message["type"] == "message":
                payload = json.loads(message["data"])
                await manager.broadcast(payload)

    reader_task = asyncio.create_task(redis_reader())
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    finally:
        reader_task.cancel()
        await pubsub.unsubscribe(...)
        await redis.aclose()
```

**Why two concurrent tasks?** One async task (`redis_reader`) blocks waiting for Redis messages. Another loop blocks waiting for WebSocket messages from the client. `asyncio.create_task` runs both concurrently on the same event loop thread. When the WebSocket disconnects, the `finally` block cancels the Redis reader to prevent memory leaks. Subscribing to all 3 channels means one WebSocket connection carries all live data types.

---

```python
async def publish_to_channel(channel: str, data: dict) -> None:
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis.publish(channel, json.dumps(data))
    finally:
        await redis.aclose()
```

**Why create a new Redis connection per publish?** This function is called from Celery worker processes (via `tasks.py`). Each Celery worker is a separate process — sharing a Redis connection between processes is unsafe. Creating and closing a connection per call is correct here because the sync Redis client in `tasks.py` does this too.

**Connects to:** `tasks.py` (which calls `publish_to_channel` indirectly), `App.jsx` (`useWebSocket` hook connects here).

---

### `backend/workers/tasks.py` — Celery Background Tasks

**Role:** The async work engine. All tasks that would make the HTTP response slow (AI calls, DB queries, Redis publishes) are offloaded here. Runs in a completely separate process from FastAPI.

---

```python
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"

def _env(key: str, default: str = "") -> str:
    value = os.getenv(key, "")
    if value:
        return value
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{key}=") and not line.startswith("#"):
                return line[len(f"{key}="):].strip().strip('"').strip("'")
    return default
```

**Why read .env manually?** Celery workers are started with `PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker`. When run with `sudo -E`, environment variables from the shell are preserved. But without `python-dotenv`, the `.env` file isn't loaded automatically. This function checks `os.getenv` first (env vars win), then falls back to parsing `.env` directly — no dependency needed, works in all startup modes.

---

```python
celery_app = Celery(
    "rsentry",
    broker=_env("REDIS_URL", "redis://localhost:6379/0"),
    backend=_env("REDIS_URL", "redis://localhost:6379/0"),
)
```

**Why Redis as both broker and backend?** The broker receives task messages (a task queue). The backend stores task results. Using the same Redis instance for both is fine for this project scale. Celery uses different key namespaces so they don't conflict.

---

```python
_engine = None
_SessionLocal = None

def _get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        db_url = _env("DATABASE_URL")
        _engine = create_async_engine(db_url, poolclass=NullPool)
        _SessionLocal = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine, _SessionLocal
```

**Why `NullPool`?** Celery uses `fork()` to spawn worker processes. PostgreSQL connections cannot be safely inherited across a `fork()` — the connection state becomes corrupted. `NullPool` disables connection pooling entirely: every task opens a fresh connection and closes it when done. More overhead per task, but completely safe in forked workers. This was a hard bug to find — the fix is here.

---

```python
def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
```

**Why create a new event loop?** Celery task functions are synchronous (`def`, not `async def`). SQLAlchemy async requires an event loop. `asyncio.run()` would fail if there's already a loop running (which there sometimes is in Celery). Creating and closing a fresh loop per task is the safe pattern for Python 3.13 + Celery fork workers.

---

```python
@celery_app.task(name="push_alert_ws")
def push_alert_ws(alert_id, host_id, severity, event_type):
    r = _redis()
    r.publish("rsentry:alerts", json.dumps({
        "type": "new_alert",
        "alert_id": alert_id,
        "host_id": host_id,
        "severity": severity,
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))
```

**Why publish to Redis instead of calling `ws.py` directly?** `ws.py` runs inside the FastAPI process. `tasks.py` runs in a Celery worker process. You cannot call functions across process boundaries. Redis pub/sub is the inter-process communication channel. Celery publishes → Redis delivers → `ws.py` receives → broadcasts over WebSocket.

---

```python
@celery_app.task(name="update_host_risk")
def update_host_risk(host_id: str):
    async def _inner():
        _, SessionLocal = _get_engine()
        async with SessionLocal() as db:
            result = await db.execute(
                select(Alert.severity, func.count(Alert.id))
                .where(Alert.host_id == host_id, Alert.acknowledged == False)
                .group_by(Alert.severity)
            )
            rows = result.all()
            weights = {
                Severity.CRITICAL: 40,
                Severity.HIGH: 20,
                Severity.MEDIUM: 10,
                Severity.LOW: 2,
            }
            score = min(sum(weights.get(sev, 0) * count for sev, count in rows), 100.0)
            # ... save score to host record
    _run(_inner())
```

**The risk formula:** One CRITICAL alert = 40 points. One HIGH = 20. One MEDIUM = 10. Capped at 100. So 3 unacknowledged CRITICAL alerts puts the host at 100/100. Acknowledging alerts reduces the score. This is called after every new event that creates an alert AND after every acknowledgment.

---

```python
@celery_app.task(name="analyze_event_ai")
def analyze_event_ai(event_id: str, event_data: dict):
    result = ai_analyst.analyze_event(event_data)
    r = _redis()
    r.publish("rsentry:ai", json.dumps({
        "type": "ai_analysis",
        "event_id": event_id,
        **result,
    }))
    if result.get("risk_level") == "LOW" or result.get("threat_type") == "Benign":
        auto_ack_by_event.delay(event_id)
```

**Auto-ack logic:** If the AI says it's benign or low risk, it's not worth the analyst's attention — auto-acknowledge the alert. This keeps the alerts list clean. Only genuinely suspicious findings stay active.

---

```python
@celery_app.task(name="publish_markov_analysis")
def publish_markov_analysis(event_id: str):
    _redis().publish("rsentry:ai", json.dumps({
        "type": "ai_analysis",
        "event_id": event_id,
        "threat_type": "Benign",
        "technique": "Markov Chain Repositioning",
        "behavior_summary": "Internal Markov chain module repositioned canary files...",
        "risk_level": "LOW",
        "confidence": "HIGH",
    }))
```

**Why a fake AI result?** Markov repositioning events look like canary moves to the AI — they'd get analyzed as potential threats and waste API credits. Instead of calling NVIDIA, we publish a pre-written Benign result directly to the WebSocket. The frontend sees it identically to a real AI analysis.

---

```python
@celery_app.task(name="auto_ack_containment")
def auto_ack_containment(host_id: str):
    # Acknowledges all CRITICAL alerts for this host
    # Then publishes alerts_acked to WebSocket
```

**When is this called?** When the agent sends a `CONTAINMENT_COMPLETE` event. At that point the threat is neutralized — the process was killed, network was blocked, evidence was captured. There's no need for the analyst to manually acknowledge all the CRITICAL alerts that triggered containment.

**Connects to:** `ai_analyst.py` (calls analyze functions), `ws.py` (publishes to Redis channels), `schemas.py` (ORM models).

---

### `backend/services/ai_analyst.py` — NVIDIA AI Integration

**Role:** Wraps the NVIDIA API (OpenAI-compatible endpoint) with rate limiting, two independent API keys, and structured JSON response parsing.

---

```python
MODEL_NAME = "meta/llama-3.1-70b-instruct"
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
_RATE_DELAY = 3.0

_RATE_KEY_EVENTS = "rsentry:nvidia_last_call_events"
_RATE_KEY_ALERTS = "rsentry:nvidia_last_call_alerts"
```

**Why two rate keys?** Two API keys: `NVIDIA_API_KEY` for live event analysis, `NVIDIA_API_KEY_ALERTS` for manual alert analysis. Each has its own Redis rate limit key so they're completely independent. If the live events key is on cooldown, the alerts key can still fire, and vice versa. This doubles effective throughput.

---

```python
_RATE_LIMIT_LUA = """
local key = KEYS[1]
local delay = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local last = redis.call('GET', key)
if last then
    local elapsed = now - tonumber(last)
    if elapsed < delay then
        return tostring(delay - elapsed)
    end
end
redis.call('SET', key, tostring(now), 'EX', 30)
return '0'
"""
```

**Why a Lua script?** Redis executes Lua scripts atomically — nothing else can run between the `GET` check and the `SET` claim. Without atomicity, two concurrent Celery workers could both read "no recent call" and both proceed simultaneously, exceeding the rate limit. The Lua script makes the check-and-claim operation indivisible.

---

```python
def _rate_limit(redis_key: str):
    r = _get_redis()
    script = r.register_script(_RATE_LIMIT_LUA)
    while True:
        wait_str = script(keys=[redis_key], args=[str(_RATE_DELAY), str(time.time())])
        wait = float(wait_str)
        if wait <= 0:
            break
        time.sleep(wait)
```

**How it works:** Call the Lua script. If return is `'0'`, the slot was claimed — proceed. If return is `'2.3'`, wait 2.3 seconds and try again. This is a busy-wait loop but with intelligent sleep durations — it never waits longer than necessary.

---

```python
SYSTEM_PROMPT = """You are a cybersecurity AI analyst embedded in a ransomware detection system...
Respond ONLY with valid JSON in this exact format:
{
  "threat_type": "...",
  "technique": "...",
  "language_or_tool": "...",
  "behavior_summary": "...",
  "risk_level": "CRITICAL | HIGH | MEDIUM | LOW",
  "recommendation": "...",
  "confidence": "HIGH | MEDIUM | LOW"
}
Be concise. Never add text outside the JSON block."""
```

**Why strict JSON instruction?** LLMs often add explanation text before or after JSON. The `re.search(r'\{.*\}', text, re.DOTALL)` in `_call_nvidia` handles the case where the model wraps its JSON in text, but instructing the model to output JSON only reduces parsing failures. `temperature=0.1` makes the model deterministic and structured rather than creative.

---

```python
def build_prompt(event: dict) -> str:
    # ...
    if sub_type == "MARKOV_REPOSITION":
        lines.append("CONTEXT: This is an INTERNAL SYSTEM EVENT. The Markov chain module repositioned canary files... classify as Benign with LOW risk.")
    if sub_type == "moved":
        lines.append("CONTEXT: A canary file was moved. ... If pid==0 and process==unknown it is the Markov chain.")
```

**Why these context hints?** The AI doesn't know what R-Sentry is. Without context, it would classify a Markov reposition as a ransomware canary evasion technique — a false positive. The prompt explicitly tells it what these internal events mean so it classifies correctly.

---

```python
def analyze_event(event: dict) -> dict:
    try:
        _rate_limit(_RATE_KEY_EVENTS)
        result = _call_nvidia(_get_client_events(), build_prompt(event))
        return result
    except Exception as exc:
        return {"analysis_failed": True, "reason": str(exc)[:120]}

def analyze_alert(event: dict) -> dict:
    # Same but uses _RATE_KEY_ALERTS and _get_client_alerts()
```

**Why return `analysis_failed` instead of raising?** These functions are called inside Celery tasks. An exception in a Celery task causes the task to be retried (by default). Returning a failure dict lets the caller decide — in `tasks.py`, `analyze_event_ai` checks `result.get("analysis_failed")` and skips publishing if true, rather than flooding Redis with error messages.

**Connects to:** `tasks.py` (calls `analyze_event`, `analyze_alert`, `analyze_system_health`), Redis (rate limit keys), NVIDIA API.

---

## AGENT

---

### `agent/exceptions.py` — False-Positive Whitelist

**Role:** Prevents the monitor from alerting on legitimate high-entropy operations. Without this, installing packages, browsing the web, or running git would all trigger alerts.

---

```python
WHITELISTED_PATH_PREFIXES = [
    os.path.expanduser("~/.cache/"),
    os.path.expanduser("~/.mozilla/"),
    "/var/cache/apt/",
    "/var/lib/docker/",
    "/tmp/",
    ...
]

WHITELISTED_EXTENSIONS = {
    ".zip", ".gz", ".bz2", ".7z", ".rar",
    ".gpg", ".pgp", ".enc",
    ".jpg", ".jpeg", ".png",
    ".mp3", ".mp4", ".mkv",
    ".pyc", ".so", ".db",
    ...
}
```

**Why these paths?** `~/.cache/mozilla/` is Firefox's cache — it writes heavily and produces high entropy (compressed web content). `/var/cache/apt/` is package installation. `/var/lib/docker/` is container images. All of these involve compressed/encrypted files by design — they're not threats.

**Why whitelist `.so` files?** Shared library files are binary — high entropy naturally. Compiling or installing software creates/modifies `.so` files constantly. Same for `.pyc` (compiled Python), `.db` (SQLite), `.gpg` (intentionally encrypted).

---

```python
def is_whitelisted(path: str, process_name: str = "") -> bool:
    if is_whitelisted_path(path):
        return True
    if process_name and is_whitelisted_process(process_name):
        return True
    return False
```

**How it's used:** In `monitor.py`, before processing any event: `if not canary_hit and is_whitelisted(src_path): return`. Canary hits bypass the whitelist entirely — if a canary was touched, it's always a CRITICAL alert regardless of path.

**Connects to:** `monitor.py` (imported and called in `_handle_event`).

---

### `agent/lineage.py` — Process Ancestry Scorer

**Role:** Scores how suspicious a process is based on who spawned it, where it lives on disk, and behavioral signals. Returns a 0–100 score.

---

```python
SUSPICIOUS_PARENT_NAMES = {
    "nc", "ncat", "netcat",
    "mshta", "wscript", "cscript",
    "xterm", "rxvt",
}

BENIGN_PARENTS = {
    "systemd", "init", "sshd", "cron",
    "bash", "sh", "zsh", "fish",
    "python", "python3",
    "code", "firefox", "chromium",
    "nautilus", "dolphin",
}
```

**Why separate lists?** If a process is spawned by `nc` (netcat), that's very suspicious. If spawned by `bash`, that's normal — everything on Linux is spawned by a shell. The `BENIGN_PARENTS` list subtracts 15 points from the score for known-safe parents, reducing false positives from normal terminal work.

---

```python
SUSPICIOUS_SPAWN_PATHS = [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/proc/",
]
```

**Why these paths?** Legitimate software installs to `/usr/`, `/opt/`, or user home directories. Malware often executes from `/tmp/` (world-writable, no execution restrictions by default) or `/dev/shm/` (in-memory filesystem, no disk trace). A process whose executable lives in `/tmp/` gets +25 points immediately.

---

```python
def score_process(pid: int) -> Optional[ProcessLineage]:
    # ...
    score = 0.0

    # 1. Suspicious parent (+30)
    if immediate_parent.lower() in SUSPICIOUS_PARENT_NAMES:
        score += WEIGHT_SUSPICIOUS_PARENT

    # Benign parent reduces score (-15)
    if immediate_parent.lower() in BENIGN_PARENTS:
        score = max(0.0, score - 15)

    # 2. Suspicious spawn path (+25)
    for sp in SUSPICIOUS_SPAWN_PATHS:
        if exe_lower.startswith(sp):
            score += WEIGHT_SUSPICIOUS_PATH

    # 3. Deep ancestry chain (+15)
    if len(lineage.ancestors) > 5:
        score += WEIGHT_DEEP_ANCESTRY

    # 4. Unreadable executable (+10)
    if lineage.sha256 is None:
        score += WEIGHT_HASH_MISMATCH * 0.5

    # 5. No controlling TTY (+5)
    if proc.terminal() is None:
        score += WEIGHT_NO_TTY

    # 6. Rapid spawn (< 2 seconds old) (+5)
    if age < 2.0:
        score += WEIGHT_RAPID_SPAWN

    lineage.score = min(score, 100.0)
```

**Why SHA-256 check?** If the executable file can't be read (returns `None`), it might be running from memory or a locked file — suspicious. A readable, hashable executable gets half the penalty removed.

**Why "no TTY"?** Legitimate terminal commands run under a TTY (terminal). Background processes spawned programmatically (malware, reverse shells) often have no controlling terminal. Combined with other signals, `no_tty` adds to the picture.

**Connects to:** `monitor.py` (calls `score_for_event(pid)`).

---

### `agent/containment.py` — The 4-Step Kill Pipeline

**Role:** Executed when a CRITICAL event fires. Freezes the process, preserves evidence, blocks its network traffic, then kills it. Each step is its own function.

---

```python
def _sigstop(pid: int) -> bool:
    os.kill(pid, signal.SIGSTOP)
```

**Why SIGSTOP first?** `SIGSTOP` pauses the process without killing it. This prevents it from encrypting more files, deleting evidence, or alerting its C2 server during the evidence collection phase. The process is frozen in place — it can't run any code until we're ready.

---

```python
def _capture_evidence(pid: int) -> tuple[Optional[Path], list[str]]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = EVIDENCE_BASE / f"pid_{pid}_{ts}"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    proc_artifacts = ["cmdline", "environ", "maps", "status", "stat",
                      "io", "fd", "net/tcp", "net/tcp6", "net/udp"]

    for artifact in proc_artifacts:
        src = proc_dir / artifact
        # ... copy to evidence_dir ...
```

**What each artifact contains:**
- `cmdline` — exact command line that launched the process (often reveals malware scripts)
- `environ` — environment variables (may contain credentials, C2 URLs)
- `maps` — memory map (shows loaded libraries, injected code regions)
- `status` / `stat` — process state, PID, PPID, UID
- `io` — bytes read/written (shows how much data was encrypted)
- `fd` — open file descriptors (which files it had open)
- `net/tcp` / `net/udp` — active network connections (C2 communication)

Then `psutil` captures a structured summary: open files, active connections, memory usage. All written to `/tmp/rsentry_evidence/pid_NNNN_TIMESTAMP/`.

---

```python
def _iptables_drop(pid: int) -> Optional[str]:
    proc = psutil.Process(pid)
    uid = proc.uids().real
    cmd = ["iptables", "-I", "OUTPUT", "1", "-m", "owner",
           "--uid-owner", str(uid), "-j", "DROP"]
    subprocess.run(cmd, check=True, capture_output=True, timeout=5)
```

**Why UID-based, not PID-based?** `iptables` can't filter by PID — but it can by UID (user ID). The rule blocks all outbound traffic from the process's user account. This is broad (also blocks other processes running as the same user) but effective — it cuts the network connection before the kill. Requires root. If not root, this step is skipped with a warning.

---

```python
def _sigkill(pid: int) -> bool:
    os.kill(pid, signal.SIGKILL)
    for _ in range(10):
        time.sleep(0.1)
        try:
            os.kill(pid, 0)  # test if still alive
        except ProcessLookupError:
            break  # confirmed dead
```

**Why `SIGKILL` not `SIGTERM`?** `SIGTERM` is politely asking a process to exit — malware can ignore it (by catching the signal). `SIGKILL` is sent by the kernel and cannot be caught or ignored. The loop after kill confirms the process is actually gone by sending signal 0 (a no-op that just checks existence) every 100ms.

---

```python
def contain(pid: int, skip_iptables: bool = False) -> ContainmentResult:
    result.stopped = _sigstop(pid)
    time.sleep(0.05)  # give OS time to freeze
    result.evidence_dir, result.evidence_files = _capture_evidence(pid)
    if not skip_iptables and os.geteuid() == 0:
        result.iptables_rule = _iptables_drop(pid)
    result.killed = _sigkill(pid)
    return result
```

**The 50ms sleep:** After SIGSTOP, the kernel needs a tiny moment to actually freeze the process — without it, the process might still execute a few more instructions during evidence capture. 50ms is enough.

**Connects to:** `monitor.py` (calls `contain(pid)` on CRITICAL events), `events.py` (containment result is sent to backend via `client.send_containment_complete`).

---

### `agent/adaptive.py` — Markov Chain Canary Repositioner

**Role:** Learns which directories get accessed most frequently and moves canary files there — maximizing the chance that ransomware will trigger a canary hit.

---

```python
class MarkovRepositioner:
    def __init__(self, canary_paths: list[Path]):
        self.canary_paths = list(canary_paths)
        self._state_index: dict[str, int] = {}
        self._transitions: Optional[np.ndarray] = None
        self._counts: Optional[np.ndarray] = None
        self._last_state: Optional[int] = None
        self._n_observations: int = 0
```

**The state machine:** Each unique directory path is a "state." The system records transitions: "after accessing directory A, directory B was accessed next." This builds a count matrix where `_counts[i][j]` = how many times accessing directory `i` was followed by accessing directory `j`.

---

```python
def observe(self, directory: str) -> None:
    idx = self._ensure_state(directory)
    if self._last_state is not None:
        self._counts[self._last_state, idx] += 1
        self._transitions = None  # mark dirty
    self._last_state = idx
```

**Why mark `_transitions = None`?** The probability matrix (transitions) is derived from the count matrix. When counts change, the cached probability matrix is stale. Setting it to `None` means the next call to `_transition_matrix()` will recompute it. This lazy recomputation avoids running normalization math on every single directory access.

---

```python
def _compute_transitions(self) -> np.ndarray:
    row_sums = self._counts.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1  # avoid division by zero
    return self._counts / row_sums
```

**Row normalization:** Each row in the count matrix is divided by its total to produce probabilities. `_counts[i]` = [3, 1, 0] becomes `[0.75, 0.25, 0.0]`. This means: given we're in state `i`, there's a 75% chance the next access is state 0. Rows with zero counts (never visited) divide by 1 to avoid NaN.

---

```python
def predicted_hotspots(self, top_n: int = 5) -> list[str]:
    eigenvalues, eigenvectors = np.linalg.eig(T.T)
    idx = np.argmin(np.abs(eigenvalues - 1.0))
    stationary = np.real(eigenvectors[:, idx])
    stationary = np.abs(stationary)
    stationary /= stationary.sum()
    ranked = np.argsort(stationary)[::-1]
    return [idx_to_state[i] for i in ranked[:top_n]]
```

**Stationary distribution:** For a Markov chain, the stationary distribution π represents the long-run probability of being in each state. It satisfies `π = π × T`. To find it, we compute the eigenvector of `T^T` with eigenvalue 1 (the left eigenvector of T). The directories with highest stationary probability are where the filesystem activity will converge over time — exactly where canaries should be placed.

---

```python
def reposition(self, fs_graph=None) -> list[Path]:
    hotspots = self.predicted_hotspots(top_n=len(self.canary_paths))
    for i, canary in enumerate(self.canary_paths):
        target_dir = Path(hotspots[i % len(hotspots)])
        new_path = target_dir / canary.name
        shutil.move(str(canary), str(new_path))
```

**`i % len(hotspots)`:** If there are more canaries than hotspots, cycle through the hotspot list. `canary.name` preserves the `AAA_*.txt` filename so the filesystem graph still recognizes it as a canary after the move.

**Connects to:** `monitor.py` (creates `MarkovRepositioner`, calls `observe()` on every event, triggers `reposition()` every 300 seconds).

---

### `agent/monitor.py` — The Main Orchestrator

**Role:** The top-level agent process. Starts watchdog, runs heartbeat and reposition loops, and dispatches every filesystem event through the full detection pipeline.

---

```python
WATCH_PATH = os.getenv("WATCH_PATH", "/home")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
HOST_ID = os.getenv("HOST_ID", "kali-endpoint-01")
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
REPOSITION_INTERVAL = int(os.getenv("REPOSITION_INTERVAL", "300"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

COMBINED_CRITICAL = 70.0
COMBINED_HIGH = 40.0
```

**Why read from environment?** All config is injected via `.env` (loaded with `sudo -E` in the startup command). This means you can change watch path, host ID, or thresholds without touching code. `DRY_RUN=true` lets you test the detection logic without actually killing processes.

---

```python
def _combined_score(lineage_score: float, entropy_delta: float) -> float:
    entropy_norm = min(entropy_delta / 8.0, 1.0) * 100
    return lineage_score * 0.6 + entropy_norm * 0.4
```

**The scoring formula:** Entropy 0–8 is normalized to 0–100. Then combined score = 60% lineage + 40% entropy. Lineage is weighted higher because a suspicious process ancestry is a stronger signal than entropy alone (many benign operations produce high entropy). Score ≥ 70 → CRITICAL. Score ≥ 40 → HIGH.

---

```python
def _handle_event(self, event_type: str, src_path: str, pid: int = 0):
    canary_hit = self.fs_graph.is_canary(src_path)

    if not canary_hit and is_whitelisted(src_path):
        return
```

**Order matters:** Canary hit check runs first. If a whitelisted path (like `/tmp/`) happens to contain a canary file, the canary hit still fires. The whitelist only applies to non-canary events.

---

```python
    lineage_data = score_for_event(pid) if pid else {
        "lineage_score": 0.0, "process_name": "unknown", ...
    }
    lineage_score = lineage_data["lineage_score"]

    entropy_alert = self.entropy_engine.observe(src_path) if not canary_hit else None
    entropy_delta = entropy_alert["entropy_delta"] if entropy_alert else 0.0

    parent_dir = str(Path(src_path).parent)
    self.repositioner.observe(parent_dir)
```

**Three parallel analyses:** lineage (who did this?), entropy (how suspicious is the file change?), Markov observation (record this access for future repositioning). The entropy engine isn't called for canary hits because we already know the severity is CRITICAL — no need to compute entropy.

---

```python
    if canary_hit:
        final_event = "CANARY_TOUCHED"
        severity = "CRITICAL"
    elif entropy_alert and lineage_score >= 40:
        final_event = "COMBINED_ALERT"
        severity = "CRITICAL" if score >= COMBINED_CRITICAL else "HIGH"
    elif entropy_alert:
        final_event = "ENTROPY_SPIKE"
        severity = entropy_alert.get("severity", "MEDIUM")
    elif lineage_score >= 40:
        final_event = "PROCESS_ANOMALY"
        severity = "CRITICAL" if score >= COMBINED_CRITICAL else "HIGH"
    else:
        return  # Low-signal, skip
```

**Decision tree:** Canary hit always wins (CRITICAL, no further analysis needed). Both signals together = COMBINED_ALERT (highest confidence threat). Entropy alone = ENTROPY_SPIKE. Lineage alone = PROCESS_ANOMALY. Nothing significant = silently drop the event (prevents noise).

---

```python
def _trigger_containment(self, pid, process_name, file_path, ...):
    with self._lock:
        if pid in self._contained_pids:
            return
        self._contained_pids.add(pid)
```

**Why the lock?** Multiple filesystem events can fire for the same process almost simultaneously (modify, modify, modify on several files). The lock ensures containment is triggered exactly once per PID even if three events arrive in rapid succession. `_contained_pids` is checked before containment runs.

---

```python
class Monitor:
    def __init__(self, watch_path: str = WATCH_PATH, auto_contain: bool = True):
        self.fs_graph = FilesystemGraph(root=watch_path)
        self.entropy_engine = EntropyEngine()
        self.client = AgentClient(backend_url=BACKEND_URL, host_id=HOST_ID)
        canaries = self.fs_graph.place_canaries(strategy=CANARY_STRATEGY)
        self.repositioner = MarkovRepositioner(canary_paths=canaries)
```

**Initialization order:** The `FilesystemGraph` walks the directory tree and places canary files (named `AAA_*.txt`) in strategic locations. The Markov repositioner is seeded with these initial canary paths. All modules share the same `client` object for sending events to the backend.

---

```python
    def _reposition_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(REPOSITION_INTERVAL)
            if self.repositioner.should_reposition():
                old_paths = [str(p) for p in self.repositioner.canary_paths]
                self.repositioner.reposition(fs_graph=self.fs_graph)
                new_paths = [str(p) for p in self.repositioner.canary_paths]
                self.client.send_event(
                    event_type="HEARTBEAT",
                    details={
                        "sub_type": "MARKOV_REPOSITION",
                        "moved": [{"from": o, "to": n} for o, n in zip(old_paths, new_paths)],
                        "hotspots": summary.get("top_hotspots", []),
                    },
                    severity="LOW",
                )
```

**Why send a HEARTBEAT with sub_type MARKOV_REPOSITION?** The backend sees this event type, identifies it as internal, skips creating an alert, and sends `publish_markov_analysis` to the WebSocket instead of calling NVIDIA. The frontend shows the move in the Tactical Response Log with a special purple "Adaptive Canary Reposition" label.

---

```python
    def start(self):
        self.observer.schedule(self.handler, self.watch_path, recursive=True)
        self.observer.start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._reposition_loop, daemon=True).start()
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())
```

**Why daemon threads?** Daemon threads are automatically killed when the main thread exits — they don't prevent the process from shutting down. If they were non-daemon, pressing Ctrl+C might leave zombie heartbeat threads running.

**Connects to:** `lineage.py`, `containment.py`, `adaptive.py`, `exceptions.py`, `entropy.py`, `graph.py`, `client.py` (AgentClient HTTP poster).

---

### `agent/monitor_ebpf.py` — eBPF Kernel Sensor

**Role:** An alternative sensor backend (`SENSOR_BACKEND=ebpf`) that attaches BPF probes to kernel rename syscall tracepoints, providing lower-latency, higher-fidelity detection than userspace inotify. Requires kernel ≥ 6.19 and `python3-bpfcc`.

---

```python
BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    struct event_t ev = {};
    bpf_probe_read_user_str(ev.newname, sizeof(ev.newname), args->newname);
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""
```

**Why `TRACEPOINT_PROBE` not `kprobe`?** Tracepoints are stable kernel ABI — they don't change between kernel versions the way internal function names do. `kprobe` on `__x64_sys_rename` would break if the kernel refactors that symbol. Tracepoints on `syscalls:sys_enter_renameat2` are guaranteed stable.

**Why `BPF_PERF_OUTPUT` not `BPF_RINGBUF`?** BCC 0.35 (the version in Kali's apt repo) doesn't fully support `BPF_RINGBUF`. Using `BPF_PERF_OUTPUT` + `open_perf_buffer` ensures compatibility.

---

```python
RANSOMWARE_FAMILIES = {
    'LockBit5': {
        'ext_len': 16,
        'two_pass': True,
        'velocity': 50,
    },
    'Akira': {
        'ext': '.akiracrypt',
        'intermittent': True,
    },
    'ESXi': {
        'targets': ['.vmdk', '.vmx', '.vmem'],
    },
}
```

**Family profiling:** Each known ransomware family has a signature profile. LockBit 5.0 generates 16-character random extensions and does two passes over files. Akira appends `.akiracrypt` intermittently. ESXi-targeting variants focus on `.vmdk`/`.vmx` files. Family identification escalates severity immediately.

---

```python
BEHAVIORAL_WEIGHTS = {
    'rapid_del_write':    35,  # Signal 1a: ≥2 del/sec + concurrent writes
    'rapid_del_write_5+': 10,  # Signal 1b: Signal 1a AND files_deleted > 5
    'rename_velocity':    25,  # Signal 2:  ≥3 renames in window
    'total_ops_deleted':  15,  # Signal 3:  total_ops>15 && deleted>3
    'child_spawn_files':  10,  # Signal 5:  execve + file ops pattern
    'hyper_fast_burst':   15,  # Signal 6:  ≥20 del/sec && files_deleted≥5
                               #            (LockBit/Qilin speed gap fix)
}
```

**5-syscall behavioral scoring:** The `proc_profile` BPF map accumulates per-process counters across 5 syscall hooks (`openat`, `vfs_write`, `unlink`, `rename`, `execve`). Each signal contributes to a 0–100 score. `SCORE_ALERT=50` → submit `behavior_event` to userspace; `SCORE_BLOCK=70` → immediately write PID into `blocked_pids` BPF map.

**Signal 6 (hyper-fast burst):** Closes the speed gap for LockBit/Qilin, which use a *create-new + delete-original* pattern (not `os.rename()`), so the rename velocity tracker never fires. At 2000+ del/sec they only scored 60 (Signals 1a+1b+3), below `SCORE_BLOCK`. Signal 6 pushes the score to 75, allowing `__handle_unlink` to call `blocked_pids.update()` directly without waiting for a userspace round-trip.

**`_handle_behavior` entropy gate:** The Python callback fires when a `behavior_event` arrives. It now contains when `entropy >= 6.5` **or** `ev.score >= 70`. The score-only path handles ultra-fast families that delete files faster than the 1 ms perf poll can sample entropy from open file descriptors.

---

```python
# BPF LSM hook — registered when lsm=bpf is active
# canary_inodes BPF map populated at startup
# Blocks rename -EPERM at kernel boundary
# blocked_pids map prevents all future renames by the PID
```

**BPF LSM canary blocking:** With `lsm=bpf` kernel boot param, `LSM_PROBE(path_rename)` checks the `canary_inodes` map. If the source inode is a canary, the rename returns `-EPERM` in nanoseconds — before any bytes are overwritten. The PID is added to `blocked_pids` to prevent further attempts. Without `lsm=bpf`, detection still works via the perf ring buffer but blocking happens in userspace after observation.

**`IGNORE_COMMS` (40+ processes):** Docker, Redis, Postgres, Celery, uvicorn, git, apt, npm, Firefox, gnome-shell, systemd, and more are filtered in the perf event callback before any scoring. Benign batch operations (rsync, dpkg, npm, rm) are suppressed in the `unlink` hook specifically.

**Markov disabled in eBPF mode:** `monitor.py` skips the Markov repositioner when `SENSOR_BACKEND=ebpf` — the eBPF `proc_profile` map tracks directory access patterns at the kernel level, making userspace Markov tracking redundant.

**Run modes:**
- `sudo -E python3 -m agent.monitor_ebpf` — normal operation
- `python3 -m agent.monitor_ebpf --selftest` — unit-tests DetectionEngine (no kernel, no sudo)
- `python3 -m agent.monitor_ebpf --print-bpf` — print compiled BPF C program
- `sudo -E python3 -m agent.monitor_ebpf --mode audit` — alert only, no SIGSTOP

**Connects to:** `client.py` (same AgentClient used by `monitor.py`), `containment.py` (contain() callback on CRITICAL), `entropy.py` (entropy_fn passed as callback for behavioral event verification). Activated via `SENSOR_BACKEND=ebpf` in `.env`.

---

## SIMULATIONS

---

### `simulations/sim_common.py` — Shared Simulation Engine

**Role:** Provides the reusable building blocks that all attack simulation scripts import. Decouples the mechanics of corpus creation, backup/restore, and attack execution from the specific behavior of each ransomware family.

---

```python
class Profile:
    name: str
    extensions: list[str]   # file types to target
    skip_ext: list[str]     # extensions to leave alone
    encrypt_pct: float      # fraction of corpus to encrypt (0.0–1.0)
    two_pass: bool          # LockBit-style: rename then encrypt
```

**Why a `Profile`?** Each ransomware family has different targeting preferences. LockBit 5.0 encrypts everything (100%) in two passes; Akira is intermittent (partial corpus, unpredictable order); Qilin targets a percentage with a single pass. `Profile` captures these differences without duplicating logic.

---

```python
def populate_corpus(target_dir, count=50):
    """Creates count synthetic document files in target_dir."""

def backup_corpus(target_dir) -> dict:
    """Snapshots the corpus before simulation for restore."""

def restore_corpus(target_dir, snapshot: dict):
    """Restores files to their pre-simulation state."""
```

**Why backup/restore?** Simulations run against real directories. Without restore, a simulation would permanently rename or destroy documents in `WATCH_PATH`. The backup takes a dict of `{path: bytes}` before running and the restore writes them back — non-destructive testing.

---

```python
def run_attack(profile: Profile, target_dir: str, agent_client=None):
    """
    Executes the attack pattern defined by profile.
    Measures: files touched before detection, latency ms, FP rate.
    """
```

**Measurement harness:** `run_attack` wraps the attack loop with timing. It posts a sentinel event to the agent client at the moment it begins, and records timestamps at each rename — so the detection latency (time from first file encrypted to CRITICAL alert) can be computed from backend events.

**Connects to:** `sim_lockbit.py`, `sim_akira.py`, `sim_qilin.py` (all import Profile and run_attack). Used as a module: `from simulations.sim_common import Profile, run_attack, populate_corpus`.

---

### `simulations/sim_lockbit.py` — LockBit 5.0 Simulation

**Role:** Mimics LockBit 5.0's characteristic two-pass encryption pattern to validate detection performance against the most sophisticated known ransomware family.

---

**How LockBit 5.0 works (and how this simulates it):**
1. **Pass 1 (rename):** Every file in the corpus is renamed from `document.pdf` → `document.pdf.XXXXXXXXXXXXXXXX` (16-char random extension). This triggers the eBPF `rename` hook and extension detection layer.
2. **Pass 2 (encrypt):** Each renamed file is opened and its bytes overwritten with high-entropy random data. This triggers the entropy analysis layer.

The two-pass approach is designed to evade simple extension-rename detectors — by the time the extension is applied, the file is already encrypted.

**Detection target:** The system should detect the threat (CRITICAL alert) within 3 files encrypted, latency < 500 ms, zero false positives, 100% coverage.

**Usage:**
```bash
cd ~/hybrid-rsentry
source venv/bin/activate
python -m simulations.sim_lockbit
```

---

### `simulations/sim_akira.py` — Akira Simulation

**Role:** Simulates Akira's intermittent encryption pattern — it randomly skips files (targeting ~60% of the corpus) and uses the `.akiracrypt` extension.

**Why intermittent matters:** Intermittent encryption evades systems that require a sustained burst of events. Akira's design makes it harder for velocity-based detection (e.g., "X renames per second") to trigger. The eBPF `proc_profile` behavioral score and lineage scorer must accumulate enough signal from the subset of files it does touch.

---

### `simulations/sim_qilin.py` — Qilin Simulation

**Role:** Simulates Qilin's percent-based approach — encrypts a configurable fraction of the corpus in a single pass with a fixed extension.

**Why percent-encryption matters:** Qilin is designed for maximum damage before detection. It tries to encrypt as much as possible in the first wave. The canary layer (any canary hit = CRITICAL) must fire before the `encrypt_pct` threshold is reached.

---

## TESTS

---

### `tests/unit/` — 71-Test Unit Suite

**Role:** Isolated unit tests for the three most critical agent modules — `entropy.py`, `lineage.py`, and `adaptive.py` — plus severity classification logic. No live services required; all external dependencies are mocked.

**Run:**
```bash
pip install -r requirements-dev.txt
pytest tests/unit/ -v
# or with coverage:
pytest tests/unit/ --cov=agent.entropy --cov=agent.lineage --cov=agent.adaptive --cov-report=term-missing
```

**Coverage:** 89% across the three modules. Coverage gate (75%) is enforced in CI.

---

**Key test areas:**

| Module | What's tested |
|---|---|
| `test_entropy.py` | Shannon entropy calculation accuracy; delta threshold firing (3.5 bits MEDIUM, 5.0 HIGH); partial read (65 KB cap); memory cap (5 000-file LRU eviction); rolling window correctness |
| `test_lineage.py` | Scoring signal weights (suspicious parent +30, spawn path +25, etc.); dpkg hash MATCH/MISMATCH/UNKNOWN verdicts; rapid process exit (+40 baseline); SHA-256 LRU cache hits |
| `test_adaptive.py` | Markov transition probability calculation; repositioning threshold (≥70%, 10 min observations); `_is_safe_target()` blocks `.git/`, `/proc/`, `/sys/`, `/dev/`, `/run/` |
| `test_severity.py` | Combined score formula (`lineage×0.6 + entropy×0.4`); CRITICAL/HIGH/MEDIUM boundary conditions |
| `test_simulation_safety.py` | Verifies simulation scripts don't leave corrupted state after backup/restore cycle |

---

### `tests/test_lockbit.py` — LockBit 5.0 4-Metric Evaluation

**Role:** End-to-end validation of detection performance against the LockBit 5.0 simulation. This is the capstone test that proves the system meets its design targets.

---

```python
TARGETS = {
    'files_before_detection': 3,   # Must detect within first 3 files encrypted
    'latency_ms':            500,  # Alert must fire in < 500 ms
    'false_positive_rate':     0,  # Zero false positives
    'coverage_pct':          100,  # 100% of corpus files detected
}
```

**Why these 4 metrics?** They map to real-world damage constraints:
- **Files < 3:** An attacker who encrypts only 2 files before being caught causes negligible damage.
- **Latency < 500 ms:** In 500 ms, LockBit can encrypt hundreds of files. Sub-500ms detection stops the attack before significant damage.
- **FP rate = 0%:** False positives erode operator trust. Even one false CRITICAL containment is a denial-of-service on the endpoint.
- **Coverage = 100%:** Every file touched by the simulation must appear in the detection events — no blind spots.

**All 4 targets are met as of v2.1.0.**

**Connects to:** `simulations/sim_lockbit.py` (runs the simulation), backend HTTP client (queries `/api/events` to measure detection timing), `agent/entropy.py` + `agent/lineage.py` (the modules under test).

---

## FRONTEND

---

### `frontend/src/App.jsx` — Root Component & State Hub

**Role:** The top-level React component. Owns all shared state: which page is active, the WebSocket connection, and all AI analysis results. Passes state down as props to child pages.

---

```javascript
const AI_EXPIRY_MS = 4 * 60 * 1000;       // 4 minutes
const AI_PENDING_TIMEOUT_MS = 45 * 1000;   // 45 seconds
const AI_TRIGGER_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM']);
```

**Why these constants?** AI analyses expire after 4 minutes so the panel doesn't fill up with stale results from hours ago. Pending analysis cards (spinner) expire after 45 seconds in case Celery is down and the result never arrives. Only CRITICAL/HIGH/MEDIUM events trigger the pending card — LOW events don't go to AI.

---

```javascript
const [aiAnalyses, setAiAnalyses] = useState([]);
const [aiHealth, setAiHealth] = useState(null);
const [aiNewIds, setAiNewIds] = useState(new Set());
const [aiTimestamps, setAiTimestamps] = useState({});
const aiTimestampsRef = useRef({});
const [aiPendingEvents, setAiPendingEvents] = useState({});
const [latestAiResult, setLatestAiResult] = useState(null);
```

**Why lift AI state to App.jsx?** If AI state lived in `AIAnalystPage`, it would be lost every time you navigate away. By lifting it to `App.jsx` (which always renders), switching from AI Analyst to Alerts and back preserves all the analysis cards. The 4-minute expiry prevents infinite accumulation.

**Why `aiTimestampsRef`?** The expiry `setInterval` needs to read current timestamps to decide what to remove. If the interval's closure captured the `aiTimestamps` state value, it would be stale (the value at interval creation time). A `useRef` updates synchronously and the interval always reads the latest value without being listed as a dependency.

---

```javascript
const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_alert') setLiveAlert(msg);
    if (msg.type === 'new_event') {
        setLiveEvent(msg);
        if (AI_TRIGGER_SEVERITIES.has(msg.severity)) {
            setAiPendingEvents(prev => ({
                ...prev,
                [msg.event_id]: { ...msg, _addedAt: Date.now() },
            }));
        }
    }
    if (msg.type === 'ai_analysis' && msg.event_id) {
        setAiPendingEvents(prev => { const next = {...prev}; delete next[msg.event_id]; return next; });
        setAiAnalyses(prev => {
            if (prev.find(a => a.event_id === msg.event_id)) return prev;
            return [msg, ...prev].slice(0, 100);
        });
        // ...
        setLatestAiResult({ ...msg, _receivedAt: Date.now() });
    }
    if (msg.type === 'health_analysis') {
        setAiHealth({ ...msg, timestamp: new Date().toISOString() });
    }
}, []);
```

**The WebSocket message router:** Each message type routes to a different state update. When `ai_analysis` arrives, it removes the pending spinner card (the analysis is done) and adds the result card. `slice(0, 100)` caps the list at 100 analyses. `setLatestAiResult` notifies `AlertsPage` to refresh immediately when a new AI result comes in.

---

```javascript
useEffect(() => {
    const t = setInterval(() => {
        const cutoff = Date.now() - AI_EXPIRY_MS;
        setAiAnalyses(prev => prev.filter(a => {
            const ts = aiTimestampsRef.current[a.event_id];
            return ts ? new Date(ts).getTime() > cutoff : true;
        }));
        const pendingCutoff = Date.now() - AI_PENDING_TIMEOUT_MS;
        setAiPendingEvents(prev => {
            const next = { ...prev };
            Object.keys(next).forEach(id => {
                if (next[id]._addedAt < pendingCutoff) delete next[id];
            });
            return next;
        });
    }, 15000);
    return () => clearInterval(t);
}, []);
```

**Expiry interval runs every 15 seconds.** Removes analysis cards older than 4 minutes and pending spinner cards older than 45 seconds. The empty dependency array `[]` means this interval is created once and never restarted — the `aiTimestampsRef` trick ensures it always reads current data.

---

```javascript
const renderPage = () => {
    switch (page) {
        case 'dashboard':  return <Overview liveAlert={liveAlert} liveEvent={liveEvent} connected={connected} />;
        case 'alerts':     return <AlertsPage liveEvent={liveEvent} newAlert={liveAlert} liveAiResult={latestAiResult} />;
        case 'ai':         return <AIAnalystPage analyses={aiAnalyses} health={aiHealth} pendingEvents={aiPendingEvents} ... />;
        // ...
    }
};

return (
    <div style={{ background: 'var(--bg)' }} className="min-h-screen flex flex-col">
        <TopBar activePage={page} onNavigate={setPage} connected={connected} alertCount={...} />
        <div className="flex-1 overflow-hidden">
            {renderPage()}
        </div>
        <StatusBar connected={connected} />
    </div>
);
```

**Layout (SIEM redesign):** Full-screen dark background (`--bg: #131519`). `TopBar` sits at the top with horizontal nav — 6 tabs, live alert badge. `StatusBar` anchors the bottom (agents reporting, EPS, WS connection status, last refreshed, cluster label). Main content fills the space between them. Navigation state (`page`) is a string — switching tabs re-renders the page component.

**Connects to:** `useWebSocket` hook (establishes WS connection), `TopBar`, `StatusBar`, all page components (passes shared state as props).

---

### `frontend/src/components/TopBar.jsx` — Horizontal Navigation

**Role:** The top navigation bar that replaced the old Sidebar. Displays the brand logo, 6 nav tabs, a live CRITICAL alert count badge, and right-side controls.

---

```javascript
const TABS = [
    { id: 'dashboard', label: 'Overview',   icon: 'fa-gauge-high' },
    { id: 'alerts',    label: 'Alerts',     icon: 'fa-bell' },
    { id: 'hosts',     label: 'Hosts',      icon: 'fa-server' },
    { id: 'filesystem',label: 'Detections', icon: 'fa-radar' },
    { id: 'ai',        label: 'AI Analyst', icon: 'fa-brain' },
    { id: 'reports',   label: 'Reports',    icon: 'fa-file-pdf' },
];
```

**Why horizontal nav?** The SIEM redesign (matching a Kibana/Elastic-style layout) puts navigation at the top to free up horizontal space for the 3-column Alerts page layout. Icons are Font Awesome 6.5.1 loaded via CDN in `index.html`.

**Alert badge:** Shows the count of unacknowledged CRITICAL alerts. Fetches from `/api/alerts/counts` and refreshes when `liveAlert` changes — so the badge updates instantly when a new CRITICAL alert arrives via WebSocket.

**Connects to:** `App.jsx` (receives `activePage`, `onNavigate`, `connected`, `alertCount`).

---

### `frontend/src/components/StatusBar.jsx` — Bottom Status Bar

**Role:** Persistent bottom bar showing the operational state of the whole system: agents reporting, events-per-second, WebSocket connection status, last refreshed timestamp, and cluster label.

---

```javascript
// Polls /api/hosts for agent count every 10 seconds
// Computes EPS from last 100 events in a 60-second window
// connected prop drives the WS status dot (green pulse / red)
```

**Why a status bar?** In a real SIEM, the bottom bar gives the analyst an at-a-glance health view without cluttering the main content area. The EPS (events per second) shows whether the agent is actively sending data — if it drops to 0, the agent may have crashed.

**Connects to:** `App.jsx` (receives `connected`), `/api/hosts`, `/api/events`.

---

### `frontend/src/components/MetricsStrip.jsx` — 6 Live Metrics

**Role:** A horizontal strip of 6 metric tiles on the Alerts page: open alerts, CRITICAL count, HIGH count, active hosts, events-per-second, and unique event types in the last hour.

---

```javascript
// Fetches from /api/alerts/counts and /api/hosts
// Refreshes every 5 seconds + immediately on liveAlert/liveEvent changes
```

**Why `/api/alerts/counts` instead of `alerts.length`?** The alert list has a fetch limit. The `/counts` endpoint returns exact totals from the database with no pagination — the numbers are always accurate even when there are thousands of alerts.

**Connects to:** `AlertsPage.jsx` (rendered inside), `/api/alerts/counts`, `/api/hosts`.

---

### `frontend/src/components/FileSystemGraph.jsx` — D3 Force-Directed Graph

**Role:** An Obsidian-style interactive force-directed graph that visualizes filesystem relationships. Replaces the static text tree in detail contexts (DetailFlyout, EventDetailModal).

---

```javascript
const simulation = d3.forceSimulation(nodes)
    .force('link',   d3.forceLink(links).id(d => d.id).distance(60))
    .force('charge', d3.forceManyBody().strength(-120))
    .force('center', d3.forceCenter(width/2, height/2))
    .force('radial', d3.forceRadial(0, width/2, height/2)
        .strength(d => d.id === selectedNodeId ? 0.8 : 0));
```

**Why `forceRadial` for the selected node?** When the user clicks an alert, the associated file path becomes the `selectedNodeId`. The radial force pulls that node toward the center with strength 0.8, while all other nodes have strength 0. This makes the selected node "gravity anchor" to the center while the rest of the graph floats around it.

**Node types and colors:**
- Root directory: large circle, `var(--accent)` (blue)
- Selected path node: `var(--accent)` with glow filter
- Canary hit: `var(--crit)` (red) with glow
- Canary file: `#22d3ee` (cyan)
- Alert node: `var(--high)` (orange)
- High entropy: `#eab308` (yellow)
- Normal: `#4b5563` (gray)

**Interactions:** Drag nodes (d3.drag), scroll to zoom (d3.zoom), hover for tooltip (path, alert count, entropy, canary status). Auto-fits the graph after the simulation settles (checks energy < threshold for 3 ticks).

**Live event injection:** When `liveEvent` prop changes, adds the new node without a full refetch — the simulation restarts with the new node, which flies in from its initial position.

**Connects to:** `DetailFlyout.jsx`, `EventDetailModal.jsx` (rendered inside both), `/api/events?limit=200`.

---

### `frontend/src/components/TacticalResponseLog.jsx` — Live Event Feed

**Role:** The scrolling log of all detection events with color-coded procedure names, entropy bars, Markov move details, and NEW badges.

---

```javascript
const PROCEDURES = {
    CANARY_TOUCHED:        { name: 'Immediate Isolation Protocol',  color: '#f87171', icon: '🛡' },
    ENTROPY_SPIKE:         { name: 'Entropy Containment Response',  color: '#fbbf24', icon: '📈' },
    COMBINED_ALERT:        { name: 'Multi-Vector Threat Response',  color: '#f43f5e', icon: '⚡' },
    CONTAINMENT_COMPLETE:  { name: 'Containment Verified',          color: '#22c55e', icon: '✅' },
    MARKOV_REPOSITION:     { name: 'Adaptive Canary Reposition',    color: '#818cf8', icon: '🔄' },
    // ...
};
```

**Why map event types to procedure names?** Raw event types like `ENTROPY_SPIKE` are technical strings. Procedure names like "Entropy Containment Response" communicate security intent — they describe what R-Sentry is doing in response, not just what was detected.

---

```javascript
function getProcedure(event) {
    if (event.event_type === 'HEARTBEAT' && event.details?.sub_type === 'MARKOV_REPOSITION') {
        return PROCEDURES.MARKOV_REPOSITION;
    }
    return PROCEDURES[event.event_type] || { name: event.event_type, color: '#6b7280', icon: '•' };
}
```

**Why special-case HEARTBEAT + MARKOV_REPOSITION?** Markov repositions are sent as `HEARTBEAT` events with `details.sub_type === 'MARKOV_REPOSITION'`. Without this check, they'd display as plain heartbeats. The fallback `{ name: event.event_type }` handles any future event types gracefully.

---

```javascript
// Live WS event injection
useEffect(() => {
    if (!liveEvent || liveEvent.type !== 'new_event') return;
    const synth = { id: liveEvent.event_id, ...liveEvent data... };
    setEvents((prev) => {
        if (prev.find((e) => e.id === synth.id)) return prev;
        return [synth, ...prev];
    });
    setNewIds((prev) => new Set([...prev, synth.id]));
    setTimeout(() => setNewIds(...remove id...), 5000);
}, [liveEvent]);
```

**Why inject the WS event before the API refresh?** The API poll runs every 10 seconds. If a CRITICAL event fires, the user shouldn't wait 10 seconds to see it. The WS message is injected directly into the events list immediately, with a NEW badge. The dedup check (`prev.find(e => e.id === synth.id)`) prevents the event from appearing twice when the 10-second poll eventually catches it.

**Connects to:** `App.jsx` (receives `liveEvent`), `/api/events` (polls every 10 seconds).

---

### `frontend/src/components/FileSystemTree.jsx` — Filesystem Visualization

**Role:** Renders a live tree of all file paths that have generated events, with canary zones highlighted in cyan and alert paths in red.

---

```javascript
function buildTree(events) {
    const root = createNode('');
    for (const event of events) {
        const parts = event.file_path?.replace(/^\//, '').split('/').filter(Boolean);
        // ... builds nested object tree from path parts
        // Marks nodes as canary if file_path contains canary filename
        // Increments alertCount for nodes with alert severity
    }
    return root;
}
```

**Why build from events, not from the filesystem directly?** The frontend has no filesystem access — it's a browser. The event database acts as a proxy for filesystem activity. Every file that was ever touched by a detection event appears in the tree. Files that were never suspicious don't clutter it.

---

```javascript
useEffect(() => {
    if (!newEvent?.file_path) return;
    const parts = newEvent.file_path.replace(/^\//, '').split('/').filter(Boolean);
    const paths = new Set(parts.map((_, i) => '/' + parts.slice(0, i+1).join('/')));
    setFlashPaths(paths);
    setTimeout(() => setFlashPaths(new Set()), 3000);
}, [newEvent]);
```

**Flash effect:** When a new event arrives over WebSocket, every path segment in that file's path gets added to `flashPaths`. The `TreeRow` component uses this set to add a `animate-ping` yellow dot next to flashing path segments for 3 seconds. This shows exactly which directory branch the new event affected.

---

```javascript
const legend = [
    { color: 'bg-cyan-400',  label: 'Canary zone' },
    { color: 'bg-red-500',   label: 'Alert / hit' },
    { color: 'bg-yellow-400',label: 'Entropy > 3.5' },
    { color: 'bg-gray-600',  label: 'Normal' },
];
```

**Entropy threshold in display:** 3.5 out of 8.0 is the visual warning threshold (yellow dot). This matches the detection threshold in `entropy.py` — entropy above 3.5 starts triggering alerts, so visual warning at the same level is consistent.

**Connects to:** `App.jsx` (receives `newEvent`, `connected`), `/api/events?limit=500`.

---

### `frontend/src/pages/AIAnalystPage.jsx` — AI Analyst

**Role:** Displays the stream of AI analysis cards in real-time. State is managed entirely by `App.jsx` — this page is almost purely presentational.

---

```javascript
export default function AIAnalystPage({
    connected, analyses, health, newIds, timestamps, pendingEvents, onHealthUpdate
}) {
```

**Why all props, no local state for analyses?** The AI state must survive navigation. `App.jsx` owns it and passes it down. `AIAnalystPage` just renders what it receives. This is the "lifting state up" React pattern applied to cross-page persistence.

---

```javascript
function PendingCard({ event }) {
    return (
        <div className="animate-pulse">
            <div className="w-3 h-3 border-2 border-indigo-400 border-t-transparent animate-spin" />
            <p>Analyzing…</p>
            <p>{event.severity}</p>
            <p>{event.file_path || event.event_type}</p>
        </div>
    );
}
```

**Why pending cards?** After a CRITICAL/HIGH/MEDIUM event fires, there's a delay before the AI result arrives (rate limiting + NVIDIA API latency). The pending card fills that gap — the user sees "Analyzing…" immediately instead of wondering if the AI is working.

---

```javascript
const runHealthCheck = async () => {
    if (healthPendingRef.current) return;
    healthPendingRef.current = true;
    setHealthLoading(true);
    const { data: events } = await getEvents({ limit: 100 });
    await axios.post(`${API_URL}/api/ai/health`, { events });
    setHealthLoading(false);
    healthPendingRef.current = false;
};
```

**Why `healthPendingRef`?** Prevents double-clicking "Run Health Check" from firing two API calls. A `useState` would also work but a ref update doesn't trigger a re-render — no flicker between disabled states. The result arrives via WebSocket (`health_analysis` message → `App.jsx` updates `aiHealth` → passed as `health` prop here).

**Connects to:** `App.jsx` (receives all state as props), `/api/ai/health`, `/api/events`.

---

### `frontend/src/pages/AlertsPage.jsx` — 3-Column SIEM Layout

**Role:** The main alert triage page, redesigned as a Kibana-style 3-column SIEM layout. Left column is `FacetRail` (filter panel, toggled open/closed via a sliders button in the search bar), center column has `MetricsStrip` + `AlertsHistogram` + `AlertsTable` + query bar, right column is `DetailFlyout` (conditionally mounted only when an alert row is clicked).

---

```javascript
export default function AlertsPage({ newAlert, liveAiResult, liveEvent }) {
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [facetFilters, setFacetFilters] = useState({});
    const [flyoutOpen, setFlyoutOpen] = useState(false);

    // Three refresh triggers: interval, newAlert, liveAiResult
    const fetchAlerts = useCallback(async () => { ... }, [facetFilters]);
    useEffect(() => { if (newAlert) fetchAlerts(); }, [newAlert, fetchAlerts]);
    useEffect(() => { if (liveAiResult) fetchAlerts(); }, [liveAiResult, fetchAlerts]);
```

**Three-column layout:**

```
┌─────────────┬──────────────────────────────┬─────────────────┐
│  FacetRail  │   MetricsStrip               │  DetailFlyout   │
│  (filters)  │   AlertsHistogram            │  (on row click) │
│             │   QueryBar                   │                 │
│  host_id    │   AlertsTable                │  Summary        │
│  severity   │   (sortable, row clickable)  │  Entity         │
│  event_type │                              │  MITRE          │
│  ...        │                              │  FileSystemGraph│
│             │                              │  Raw JSON       │
└─────────────┴──────────────────────────────┴─────────────────┘
```

**Why 3 columns?** Mirrors how real SOC dashboards work — filters on the left narrow the alert set, the center shows the data, the right shows details without a full navigation away. Keeps context (the full alert list) visible while drilling into a specific alert.

**FacetRail** (`FacetRail.jsx`) — builds filter groups from real alert data (unique host IDs, severities, statuses). Selecting a facet value adds it to `facetFilters`. A sliders toggle button in the query bar hides/shows the rail; an X button inside the rail also closes it. Each group is collapsible, with a search input to narrow visible field groups.

**DetailFlyout** (`DetailFlyout.jsx`) — renders only when `selected` is non-null (`{selected && <DetailFlyout … />}`). Contains 5 tabs:
- **Summary** — severity badge, event type, timestamps, score breakdown
- **Entity** — host ID, process name, PID, file path
- **MITRE** — ATT&CK technique mapping for the event type
- **Filesystem** — `FileSystemGraph` D3 force graph centered on the alert's file path
- **Raw** — full JSON of the alert + event data

**Connects to:** `App.jsx` (receives `newAlert`, `liveAiResult`, `liveEvent`), `FacetRail`, `MetricsStrip`, `AlertsHistogram`, `AlertsTable`, `DetailFlyout`, `/api/alerts`, `/api/events`.

---

```javascript
const handleAnalyze = async (id) => {
    setAnalyzing(id);
    try {
        await analyzeAlert(id);  // POST /api/alerts/{id}/analyze
    } catch (err) {
        console.error('Analyze failed:', err);
    } finally {
        setAnalyzing(null);
    }
};
```

**On-demand analysis:** The backend queues a Celery task, which calls NVIDIA, which publishes the result over WebSocket. The button shows "Analyzing…" while the request is in-flight, then resets. The actual result appears in `AIAnalystPage` (the analysis cards) and the alert may auto-acknowledge if AI says Benign.

**Connects to:** `App.jsx` (receives `newAlert`, `liveAiResult`), `/api/alerts`, `/api/alerts/{id}/acknowledge`, `/api/alerts/{id}/analyze`.

---

### `frontend/src/pages/HostsPage.jsx` — Host Cards with Risk Score

**Role:** Displays each monitored host as a card with a radial risk score gauge, alert breakdown, and contain/release button.

---

```javascript
const RISK_COLOR = (score) => {
    if (score >= 80) return '#ef4444';  // red
    if (score >= 50) return '#f97316';  // orange
    if (score >= 25) return '#eab308';  // yellow
    return '#22c55e';                   // green
};
```

**Color thresholds match the backend:** The backend's `update_host_risk` task uses weights: CRITICAL=40, HIGH=20, MEDIUM=10. One CRITICAL alert puts the host at 40 (yellow). Two CRITICAL puts it at 80 (red). The color thresholds reflect how serious the alert burden is.

---

```javascript
const fetchAll = async () => {
    const { data: hostList } = await getHosts({ limit: 50 });
    setHosts(hostList);
    const results = await Promise.allSettled(hostList.map((h) => getHostRisk(h.host_id)));
    const map = {};
    hostList.forEach((h, i) => {
        if (results[i].status === 'fulfilled') map[h.host_id] = results[i].value.data;
    });
    setRiskMap(map);
};
```

**Why `Promise.allSettled` not `Promise.all`?** `Promise.all` rejects if any single request fails — one bad host would break the whole page. `Promise.allSettled` waits for all requests and marks each as fulfilled or rejected. Hosts whose risk fetch failed just show `—` in the stats instead of crashing the page.

---

```javascript
<RadialBarChart
    cx="50%" cy="50%"
    innerRadius="55%" outerRadius="100%"
    data={[{ value: score, fill: color }]}
    startAngle={90} endAngle={-270}
>
    <RadialBar dataKey="value" background={{ fill: '#374151' }} />
</RadialBarChart>
```

**The risk gauge:** A Recharts radial bar that sweeps from 12 o'clock (90°) clockwise all the way around (-270° = same as 90° + 360°). The background fill (`#374151`) shows the full circle in dark gray; the colored bar fills proportional to the score. A score of 50 fills exactly half the circle.

**Connects to:** `App.jsx` (no props needed — fetches its own data), `/api/hosts`, `/api/hosts/{id}/risk`, `/api/hosts/{id}/contain`.

---

## END-TO-END FLOW — One Full Event Cycle

**Scenario: User opens a document in `/home/mohammad/Documents/` while ransomware is running in the background.**

```
1. watchdog fires FileModifiedEvent for /home/mohammad/Documents/report.pdf
   └─ monitor.py: _handle_event("modified", "/home/mohammad/Documents/report.pdf", pid=4721)

2. is_whitelisted("/home/mohammad/Documents/report.pdf") → False (not a cached/browser path)

3. score_for_event(4721) → lineage_score=35.0 (process spawned from /tmp/, no TTY)
   entropy_engine.observe(report.pdf) → entropy_delta=4.2 (high — file was encrypted)
   repositioner.observe("/home/mohammad/Documents/") → updates Markov counts

4. combined_score = 35.0*0.6 + (4.2/8*100)*0.4 = 21 + 21 = 42.0

5. entropy_alert exists, lineage_score(35) < 40 → ENTROPY_SPIKE, severity=MEDIUM

6. client.send_event(event_type="ENTROPY_SPIKE", severity="MEDIUM", ...)
   └─ HTTP POST to /api/events

7. events.py: ingest_event()
   └─ _upsert_host("ATOMIC")           → host record created/updated
   └─ is_internal = False              → it's a real event
   └─ event = Event(...)               → persisted to PostgreSQL
   └─ MEDIUM in ALERT_SEVERITIES       → alert = Alert(...) persisted
   └─ db.commit()

8. Celery tasks fired:
   └─ push_event_ws.delay(...)         → Redis "rsentry:events" channel
   └─ push_alert_ws.delay(...)         → Redis "rsentry:alerts" channel
   └─ update_host_risk.delay("ATOMIC") → recalculates risk score
   └─ analyze_event_ai.delay(event_id, event_data) → NVIDIA API call

9. ws.py redis_reader receives from "rsentry:events":
   └─ broadcast({type: "new_event", event_type: "ENTROPY_SPIKE", severity: "MEDIUM", ...})

10. App.jsx handleWsMessage receives new_event:
    └─ setLiveEvent(msg)               → passed to Overview, TacticalResponseLog
    └─ severity=MEDIUM in trigger set  → aiPendingEvents["ev-id"] = {...}

11. TacticalResponseLog receives liveEvent:
    └─ synthEvent injected at top of list
    └─ "NEW" badge shown for 5 seconds
    └─ Flash animation on path segments for 3 seconds

12. ws.py receives from "rsentry:alerts":
    └─ broadcast({type: "new_alert", severity: "MEDIUM", ...})
    └─ AlertsPage: fetchAlerts() called immediately
    └─ MetricsStrip: fetchCounts() called immediately → MEDIUM count +1

13. Celery analyze_event_ai completes (2-5 seconds later):
    └─ ai_analyst.analyze_event(event_data) → NVIDIA API returns:
       {"threat_type": "Ransomware", "risk_level": "HIGH", "confidence": "MEDIUM", ...}
    └─ Redis publish to "rsentry:ai":
       {type: "ai_analysis", event_id: "...", threat_type: "Ransomware", ...}

14. ws.py broadcasts ai_analysis to all WebSocket clients

15. App.jsx handleWsMessage receives ai_analysis:
    └─ aiPendingEvents[event_id] deleted  → spinner card removed
    └─ aiAnalyses prepended with result   → analysis card appears
    └─ latestAiResult = result            → AlertsPage refreshes

16. AIAnalystPage receives updated analyses prop:
    └─ AnalysisCard renders with red border (HIGH risk)
    └─ "Ransomware" threat type, recommendation shown

17. risk_level="HIGH" (not LOW or Benign) → alert NOT auto-acked
    └─ Alert remains active in AlertsPage for analyst review
    └─ Analyst can click ACK or AI Analyze for on-demand re-analysis
```

---

## CONNECTION MAP — What Imports / Calls What

```
schemas.py ←── imported by ──→ events.py, alerts.py, hosts.py, tasks.py

main.py
  ├── imports: events.router, alerts.router, hosts.router, ws.router
  └── calls: analyze_health_ai.delay (via /api/ai/health endpoint)

events.py
  ├── imports: schemas.py (all models)
  ├── calls: push_event_ws.delay, push_alert_ws.delay
  ├── calls: update_host_risk.delay, analyze_event_ai.delay
  ├── calls: auto_ack_containment.delay, publish_markov_analysis.delay
  └── uses: database.py (get_db session)

alerts.py
  ├── calls: update_host_risk.delay (after ACK)
  └── calls: analyze_alert_ai.delay (on-demand analysis)

tasks.py
  ├── imports: ai_analyst.py (analyze_event, analyze_alert, analyze_system_health)
  ├── publishes to Redis: rsentry:alerts, rsentry:events, rsentry:ai
  └── reads: .env directly (no dotenv)

ai_analyst.py
  ├── uses: Redis (rate limit Lua script)
  └── calls: NVIDIA API (OpenAI-compatible endpoint)

ws.py
  └── subscribes: Redis rsentry:alerts, rsentry:events, rsentry:ai
      └── broadcasts to: all connected WebSocket clients

monitor.py  (inotify sensor)
  ├── imports: lineage.py (score_for_event)
  ├── imports: containment.py (contain, dry_run_contain)
  ├── imports: adaptive.py (MarkovRepositioner)
  ├── imports: exceptions.py (is_whitelisted)
  ├── imports: entropy.py (EntropyEngine)
  ├── imports: graph.py (FilesystemGraph)
  └── imports: client.py (AgentClient → HTTP POST to /api/events)

monitor_ebpf.py  (eBPF sensor — alternate backend)
  ├── attaches: TRACEPOINT_PROBE sys_enter_rename + renameat2
  ├── uses: BPF_PERF_OUTPUT (BCC 0.35)
  ├── detects: velocity burst, family profiling (LockBit5/Akira/ESXi), canary hits
  ├── suppresses: IGNORE_COMMS FP filter
  └── emits: same event interface as monitor.py → client.py → /api/events

App.jsx
  ├── uses: useWebSocket hook → connects to /ws/alerts
  ├── renders: TopBar, StatusBar, Overview, AlertsPage, HostsPage,
  │            FilesystemPage, AIAnalystPage, ReportsPage
  └── passes down: liveAlert, liveEvent, analyses, health, pendingEvents, latestAiResult

AlertsPage.jsx  (3-column SIEM layout)
  ├── renders: FacetRail, MetricsStrip, AlertsHistogram, AlertsTable, DetailFlyout
  ├── receives: newAlert, liveAiResult, liveEvent (from App.jsx)
  └── calls: /api/alerts, /api/alerts/{id}/acknowledge, /api/alerts/{id}/analyze

DetailFlyout.jsx / EventDetailModal.jsx
  └── renders: FileSystemGraph (D3 v7 force graph) for Filesystem tab

AIAnalystPage.jsx
  └── receives: analyses, health, newIds, timestamps, pendingEvents (from App.jsx)

HostsPage.jsx
  └── calls: /api/hosts, /api/hosts/{id}/risk, /api/hosts/{id}/contain
```
