#!/usr/bin/env bash
# setup.sh — Bootstrap Hybrid R-Sentry on Kali Linux (PEP 668 safe)
# Run as a regular user; sudo is only invoked where needed.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/venv"
PYTHON="${PYTHON:-python3}"

echo "==> Hybrid R-Sentry setup starting..."
echo "    Repo : $REPO_DIR"
echo "    Python: $($PYTHON --version 2>&1)"

# ── 1. System packages ──────────────────────────────────────────────────────
echo ""
echo "==> [1/5] Installing system packages (requires sudo)..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    python3-venv python3-pip python3-dev \
    libpq-dev gcc gfortran \
    libopenblas-dev liblapack-dev \
    pkg-config meson ninja-build \
    iptables auditd \
    nodejs npm 2>/dev/null || true

# ── 2. Python virtual environment ───────────────────────────────────────────
echo ""
echo "==> [2/5] Creating Python virtual environment at $VENV_DIR ..."
if [ -d "$VENV_DIR" ]; then
    echo "    venv already exists — skipping creation."
else
    $PYTHON -m venv "$VENV_DIR"
    echo "    venv created."
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
echo "    Activated: $(which python)"

# ── 3. Python dependencies ───────────────────────────────────────────────────
echo ""
echo "==> [3/5] Installing Python dependencies..."
pip install --upgrade pip wheel setuptools --quiet
pip install scipy --only-binary :all: --quiet
pip install -r "$REPO_DIR/requirements.txt"
echo "    Python deps installed."

# ── 4. Frontend dependencies ─────────────────────────────────────────────────
echo ""
echo "==> [4/5] Installing Node/React dependencies..."
if [ -f "$REPO_DIR/frontend/package.json" ]; then
    cd "$REPO_DIR/frontend"
    npm install --silent
    cd "$REPO_DIR"
    echo "    Node deps installed."
else
    echo "    frontend/package.json not found — skipping."
fi

# ── 5. Env file ──────────────────────────────────────────────────────────────
echo ""
echo "==> [5/5] Environment file..."
if [ ! -f "$REPO_DIR/.env" ]; then
    cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
    echo "    .env created from .env.example — edit it before running."
else
    echo "    .env already exists — skipping."
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo " Setup complete!"
echo ""
echo " Activate the venv before each session:"
echo "   source venv/bin/activate"
echo ""
echo " Start infrastructure (Postgres + Redis):"
echo "   docker compose up -d postgres redis"
echo ""
echo " Run the backend:"
echo "   uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo " Run the agent (root needed for iptables):"
echo "   sudo venv/bin/python -m agent.monitor"
echo ""
echo " Run the frontend dev server:"
echo "   cd frontend && npm start"
echo "================================================================"
