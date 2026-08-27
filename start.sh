#!/bin/bash
# CyberSentinel X — Start both services with logging
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_LOG="/tmp/csx-backend.log"
FRONTEND_LOG="/tmp/csx-frontend.log"

echo "=== Stopping existing services ==="
kill $(lsof -ti :8000) 2>/dev/null && echo "Killed backend on :8000" || true
kill $(lsof -ti :5174) 2>/dev/null && echo "Killed frontend on :5174" || true
sleep 1

echo ""
echo "=== Starting Backend ==="
cd "$BASEDIR/backend"
source .venv/bin/activate

# Start backend — ML engine will gracefully degrade if xgboost/lightgbm fail
nohup python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --log-level info 2>&1 | tee "$BACKEND_LOG" &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID (log: $BACKEND_LOG)"

# Wait for backend to be ready
echo -n "Waiting for backend"
for i in $(seq 1 30); do
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo " ✓ Ready!"
    break
  fi
  echo -n "."
  sleep 1
done

echo ""
echo "=== Starting Frontend ==="
cd "$BASEDIR/frontend"
nohup npx vite --host --port 5174 2>&1 | tee "$FRONTEND_LOG" &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID (log: $FRONTEND_LOG)"

sleep 2
echo ""
echo "=== Status ==="
echo "Backend:  http://localhost:8000  (PID $BACKEND_PID)"
echo "Frontend: http://localhost:5174  (PID $FRONTEND_PID)"
echo "API Docs: http://localhost:8000/docs"
