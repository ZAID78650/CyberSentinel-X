#!/bin/bash
# CyberSentinel X — Local development startup
# Starts backend (uvicorn) and frontend (vite dev) in background

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "🔒 CyberSentinel X — Starting local development servers"
echo ""

# Kill any existing processes on our ports
lsof -ti:8000 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti:5173 2>/dev/null | xargs kill -9 2>/dev/null || true

# --- Backend ---
echo "📦 Starting backend on http://localhost:8000 ..."
cd "$ROOT/backend"
DATABASE_URL="sqlite:///./cybersentinel.db" \
  .venv310/bin/uvicorn app.main:app \
  --host 0.0.0.0 --port 8000 --reload \
  --reload-exclude '.venv*' --reload-exclude 'data/*' \
  > /tmp/csx-backend.log 2>&1 &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"

# --- Frontend ---
echo "🌐 Starting frontend on http://localhost:5173 ..."
cd "$ROOT/frontend"
npm run dev -- --host --port 5173 > /tmp/csx-frontend.log 2>&1 &
FRONTEND_PID=$!
echo "   Frontend PID: $FRONTEND_PID"

# Wait for both to be ready
echo ""
echo "⏳ Waiting for services..."
for i in $(seq 1 30); do
  if curl -s -m 2 http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Backend ready at http://localhost:8000"
    break
  fi
  sleep 1
done

for i in $(seq 1 30); do
  if curl -s -m 2 http://localhost:5173/ > /dev/null 2>&1; then
    echo "✅ Frontend ready at http://localhost:5173"
    break
  fi
  sleep 1
done

echo ""
echo "🚀 CyberSentinel X is running!"
echo ""
echo "   Frontend:  http://localhost:5173"
echo "   Backend:   http://localhost:8000"
echo "   API Docs:  http://localhost:8000/docs"
echo ""
echo "   Login: admin@cybersentinel.io / Admin@2026"
echo ""
echo "   Logs: tail -f /tmp/csx-backend.log"
echo "         tail -f /tmp/csx-frontend.log"
echo ""
echo "   Press Ctrl+C to stop all services"

# Trap to clean up on exit
trap "echo ''; echo 'Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM

# Keep script alive
wait
