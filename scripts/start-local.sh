#!/bin/bash
# ============================================================
# CyberSentinel X — Local development launcher
# Starts the backend (FastAPI on :8000) and frontend (Vite on :5173).
# Logs are written to logs/backend.log and logs/frontend.log.
# Stop with: scripts/stop-local.sh
# ============================================================
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/logs"

cd "$ROOT/backend"
if [ ! -d .venv ]; then
  echo "[start] creating backend venv..."
  python3.10 -m venv .venv || python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements-dev.txt
fi

echo "[start] running migrations..."
.venv/bin/alembic upgrade head
echo "[start] seeding (idempotent)..."
.venv/bin/python -c "from app.core.database import SessionLocal; from app.services.seed import run_seed; run_seed(SessionLocal())"

echo "[start] launching backend on http://localhost:8000"
nohup .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 > "$ROOT/logs/backend.log" 2>&1 &
echo $! > "$ROOT/logs/backend.pid"

cd "$ROOT/frontend"
if [ ! -d node_modules ]; then
  echo "[start] installing frontend deps..."
  npm install --no-audit --no-fund
fi

echo "[start] launching frontend on http://localhost:5173"
nohup npm run dev > "$ROOT/logs/frontend.log" 2>&1 &
echo $! > "$ROOT/logs/frontend.pid"

sleep 6
echo ""
echo "============================================================"
echo "  CyberSentinel X is running:"
echo "    Frontend  ->  http://localhost:5173"
echo "    Backend   ->  http://localhost:8000  (docs: /docs)"
echo "    Login     ->  admin@cybersentinel.io / Admin@2026"
echo "  Logs: logs/backend.log · logs/frontend.log"
echo "  Stop:  scripts/stop-local.sh"
echo "============================================================"
