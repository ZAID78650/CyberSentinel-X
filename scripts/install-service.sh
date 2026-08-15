#!/bin/bash
# ============================================================
# Install CyberSentinel X as persistent macOS services (launchd).
# The servers keep running even if the terminal closes or the
# chat client session ends. Stop with scripts/stop-service.sh.
# ============================================================
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LA="$HOME/Library/LaunchAgents"
mkdir -p "$LA"
mkdir -p "$HOME/Library/Logs/cybersentinel"

# Ensure the DB is migrated and seeded first (runs once, idempotent)
cd "$ROOT/backend"
.venv/bin/alembic upgrade head >/dev/null
.venv/bin/python -c "from app.core.database import SessionLocal; from app.services.seed import run_seed; run_seed(SessionLocal())"

# Install launch agents
cp "$ROOT/scripts/com.cybersentinel.backend.plist" "$LA/"
cp "$ROOT/scripts/com.cybersentinel.frontend.plist" "$LA/"

launchctl unload "$LA/com.cybersentinel.backend.plist" 2>/dev/null || true
launchctl unload "$LA/com.cybersentinel.frontend.plist" 2>/dev/null || true
launchctl load "$LA/com.cybersentinel.backend.plist"
launchctl load "$LA/com.cybersentinel.frontend.plist"

echo "============================================================"
echo "  Services installed. Waiting for them to boot..."
echo "============================================================"
sleep 8
if curl -s -m 3 http://localhost:8000/ready >/dev/null; then
  echo "  Backend  : http://localhost:8000  -> READY"
else
  echo "  Backend  : check ~/Library/Logs/cybersentinel/backend.err.log"
fi
if curl -s -m 3 -o /dev/null http://localhost:5173/; then
  echo "  Frontend : http://localhost:5173  -> READY"
else
  echo "  Frontend : check ~/Library/Logs/cybersentinel/frontend.err.log"
fi
echo "  Login    : admin@cybersentinel.io / Admin@2026"
echo "  Stop     : bash scripts/stop-service.sh"
