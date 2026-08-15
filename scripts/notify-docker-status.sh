#!/bin/bash
# ============================================================
# Docker status watchdog — emails the ops address when any
# CyberSentinel X container is unhealthy or down.
#
#   Usage (e.g. every 5 minutes via cron / launchd):
#     bash scripts/notify-docker-status.sh
#
#   Requires SMTP configured in backend/.env (SMTP_USER, SMTP_PASSWORD, OPS_EMAIL)
# ============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Load SMTP settings from backend/.env if present
if [ -f backend/.env ]; then
  set -a
  # shellcheck disable=SC1091
  source backend/.env
  set +a
fi

if [ -z "${OPS_EMAIL:-}" ]; then
  echo "[watchdog] OPS_EMAIL not set — nothing to do."
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[watchdog] docker not available."
  exit 1
fi

STATUS=$(docker compose ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null)
if [ $? -ne 0 ]; then
  echo "[watchdog] compose not running (no project up) — skipping."
  exit 0
fi

PROBLEMS=""
while IFS='|' read -r service state health; do
  [ -z "$service" ] && continue
  if [ "$state" != "running" ] || { [ -n "$health" ] && [ "$health" != "healthy" ]; }; then
    PROBLEMS="${PROBLEMS}${service}: ${state} (health: ${health:-n/a})
"
  fi
done <<< "$STATUS"

if [ -n "$PROBLEMS" ]; then
  SUBJECT="[CyberSentinel X] Container health alert"
  BODY="One or more containers are unhealthy or down:
${PROBLEMS}

Full status:
${STATUS}
"
  if [ -x backend/.venv/bin/python ]; then
    (cd backend && PYTHONPATH=. .venv/bin/python - "$SUBJECT" "$BODY" <<'PY'
import sys
from app.core.email import send_ops_alert
ok = send_ops_alert(sys.argv[1], sys.argv[2])
sys.exit(0 if ok else 1)
PY
    )
  else
    echo "[watchdog] email not sent — python venv missing. Problem containers:"
    echo "$PROBLEMS"
  fi
else
  echo "[watchdog] all containers healthy."
fi
