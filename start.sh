#!/usr/bin/env bash
# start.sh — Start all Hybrid R-Sentry services in one command.
# Run from the repo root: bash start.sh
# Requires: Docker running, venv built, .env present, sudo password.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# ── Load env ─────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    echo "ERROR: .env not found. Copy .env.example and fill in your values."
    exit 1
fi
set -a && source .env && set +a
source venv/bin/activate

# ── Cleanup on Ctrl+C ────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "==> Stopping all services..."
    sudo kill "$AGENT_PID" 2>/dev/null || true
    kill "$CELERY_PID" "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
    docker compose stop
    echo "==> All services stopped."
}
trap cleanup SIGINT SIGTERM

# ── 1. Docker ─────────────────────────────────────────────────────────────────
echo "==> [1/5] Starting Docker (Postgres + Redis)..."
docker compose up -d
echo -n "    Waiting for containers to be healthy"
until docker compose ps | grep -E "(healthy|running)" | grep -qv "starting"; do
    echo -n "."
    sleep 2
done
echo " ready."

# ── 2. Backend ────────────────────────────────────────────────────────────────
echo "==> [2/5] Starting backend (uvicorn)..."
uvicorn backend.main:app --reload &> /tmp/rsentry-backend.log &
BACKEND_PID=$!
echo -n "    Waiting for backend"
until curl -s http://localhost:8000/health 2>/dev/null | grep -q "ok"; do
    echo -n "."
    sleep 2
done
echo " ready."

# ── 3. Celery ─────────────────────────────────────────────────────────────────
echo "==> [3/5] Starting Celery worker..."
PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info \
    &> /tmp/rsentry-celery.log &
CELERY_PID=$!
sleep 5
echo "    Celery started (pid $CELERY_PID)."

# ── 4. Agent ──────────────────────────────────────────────────────────────────
echo "==> [4/5] Starting agent (sudo required)..."
sudo -E "$REPO_DIR/venv/bin/python" -m agent.monitor &> /tmp/rsentry-agent.log &
AGENT_PID=$!
sleep 3
echo "    Agent started (pid $AGENT_PID)."

# ── 5. Frontend ───────────────────────────────────────────────────────────────
echo "==> [5/5] Starting frontend (npm start)..."
cd "$REPO_DIR/frontend"
BROWSER=none npm start &> /tmp/rsentry-frontend.log &
FRONTEND_PID=$!
echo -n "    Waiting for frontend"
until curl -s http://localhost:3000 2>/dev/null | grep -q "html"; do
    echo -n "."
    sleep 3
done
echo " ready."
cd "$REPO_DIR"

# ── All up ────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo " Hybrid R-Sentry is running!"
echo ""
echo "  Dashboard  : http://localhost:3000"
echo "  API docs   : http://localhost:8000/docs"
echo ""
echo "  Logs:"
echo "    Backend  : tail -f /tmp/rsentry-backend.log"
echo "    Celery   : tail -f /tmp/rsentry-celery.log"
echo "    Agent    : tail -f /tmp/rsentry-agent.log"
echo "    Frontend : tail -f /tmp/rsentry-frontend.log"
echo ""
echo "  Press Ctrl+C to stop all services."
echo "================================================================"

wait
