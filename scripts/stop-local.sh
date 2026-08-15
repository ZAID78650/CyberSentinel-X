#!/bin/bash
# Stop CyberSentinel X local dev servers started by start-local.sh
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for name in backend frontend; do
  PID_FILE="$ROOT/logs/$name.pid"
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      kill "$PID" && echo "[stop] $name (pid $PID) stopped"
    else
      echo "[stop] $name not running"
    fi
    rm -f "$PID_FILE"
  fi
done
echo "[stop] done"
