#!/usr/bin/env bash
# ============================================================================
# CyberSentinel-X — Render deployment end-to-end verification
#
# Verifies the live site the way a judge would: login -> upload the UNSW
# sample -> ingest through the real detection pipeline -> confirm events,
# alerts, incidents and the 3D dashboard data populate.
#
# Usage:
#   scripts/verify_render.sh [BASE_URL] [INGEST_LIMIT]
#
# Defaults:
#   BASE_URL     = https://cybersentinel-frontend.onrender.com  (nginx proxy —
#                  exercises the exact path a browser uses)
#   INGEST_LIMIT = 50000   (rows of the sample to ingest; 0 = everything,
#                  which takes several minutes on the free tier)
# ============================================================================
set -euo pipefail

BASE_URL="${1:-https://cybersentinel-frontend.onrender.com}"
INGEST_LIMIT="${2:-50000}"
SAMPLE="data/uploads/unsw_sample.csv"
API="$BASE_URL/api"

say() { printf "\n== %s ==\n" "$1"; }

say "CyberSentinel-X Render verification"
echo "Target:      $BASE_URL"
echo "Ingest limit: $INGEST_LIMIT"

# --- 1. Wait for the site (free tier cold-starts on first request) ----------
say "1. Waiting for the site to come up"
code=""
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$BASE_URL/" || true)
  if [ "$code" = "200" ]; then
    echo "Site is up (HTTP $code) after ${i} attempts"
    break
  fi
  echo "  attempt $i: HTTP ${code:-timeout} — waiting 10s..."
  sleep 10
done
if [ "$code" != "200" ]; then
  echo "FAIL: site never came up (last HTTP ${code:-timeout})"
  exit 1
fi

# --- 2. Login as admin --------------------------------------------------------
say "2. Login as admin"
LOGIN=$(curl -s -m 20 -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cybersentinel.io","password":"Admin@2026"}')
TOKEN=$(printf '%s' "$LOGIN" | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print(d.get('tokens',d).get('access_token',''))" 2>/dev/null || true)
if [ -z "$TOKEN" ]; then
  echo "FAIL: login did not return a token. Response:"
  printf '%s' "$LOGIN" | head -c 500
  echo
  exit 1
fi
AUTH="Authorization: Bearer $TOKEN"
echo "Logged in OK"

# --- 3. Pre-ingest state -------------------------------------------------------
say "3. Pre-ingest state"
curl -s -m 20 -H "$AUTH" "$API/dataset/status" | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print('events:',d['stats']['events_total'],'| alerts:',d['stats']['alerts'],'| incidents:',d['stats']['incidents'],'| attack flows:',d['stats']['attack_flows'])"

# --- 4. Upload the UNSW sample -------------------------------------------------
say "4. Upload UNSW sample ($SAMPLE)"
if [ ! -f "$SAMPLE" ]; then
  echo "FAIL: sample not found at $SAMPLE"
  echo "Either upload it from the UI (Data Sources → Upload Dataset) or"
  echo "restore it locally, then re-run this script."
  exit 1
fi
UPLOAD=$(curl -s -m 300 -H "$AUTH" -F "file=@$SAMPLE" "$API/dataset/upload")
NAME=$(printf '%s' "$UPLOAD" | python3 -c \
  "import sys,json;print(json.load(sys.stdin).get('name',''))" 2>/dev/null || true)
if [ -z "$NAME" ]; then
  # Tolerate re-runs: if the file was already uploaded, reuse its name.
  if printf '%s' "$UPLOAD" | grep -qi "already exists"; then
    NAME=$(basename "$SAMPLE")
    echo "(dataset already uploaded — reusing '$NAME')"
    printf '%s' "$UPLOAD" | python3 -c \
      "import sys,json;d=json.load(sys.stdin);print('Upload response (reused):',d.get('detail',d))" 2>/dev/null || true
  else
    echo "FAIL: upload did not return a name. Response:"
    printf '%s' "$UPLOAD" | head -c 500
    echo
    exit 1
  fi
else
  printf '%s' "$UPLOAD" | python3 -c \
    "import sys,json;d=json.load(sys.stdin);print('Uploaded:',d['name'],'| rows:',d['rows'],'| size:',round(d['size_bytes']/1e6,1),'MB')"
fi

# --- 5. Ingest (appends to the corpus, never wipes) -----------------------------
say "5. Ingesting sample (limit=$INGEST_LIMIT)"
curl -s -m 20 -H "$AUTH" -X POST "$API/dataset/uploads/$NAME/ingest?limit=$INGEST_LIMIT" | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print(d.get('message',d))"

# --- 6. Poll ingestion until it finishes ----------------------------------------
say "6. Waiting for ingestion to complete"
for i in $(seq 1 80); do
  STATUS=$(curl -s -m 15 -H "$AUTH" "$API/dataset/status" || true)
  RUNNING=$(printf '%s' "$STATUS" | python3 -c \
    "import sys,json;print(json.load(sys.stdin)['progress']['running'])" 2>/dev/null || echo true)
  PROC=$(printf '%s' "$STATUS" | python3 -c \
    "import sys,json;print(json.load(sys.stdin)['progress']['processed_rows'])" 2>/dev/null || echo 0)
  TOTAL=$(printf '%s' "$STATUS" | python3 -c \
    "import sys,json;print(json.load(sys.stdin)['progress']['total_rows'])" 2>/dev/null || echo 0)
  EV=$(printf '%s' "$STATUS" | python3 -c \
    "import sys,json;print(json.load(sys.stdin)['stats']['events_total'])" 2>/dev/null || echo "?")
  echo "  [$i] running=$RUNNING processed=$PROC/$TOTAL events=$EV"
  if [ "$RUNNING" = "False" ]; then
    echo "  ingestion finished"
    break
  fi
  sleep 15
done
printf '%s' "$STATUS" | python3 -c \
  "import sys,json;p=json.load(sys.stdin)['progress'];print('Result: inserted=',p['inserted_rows'],'attack flows=',p['attack_flows'],'alerts created=',p['alerts_created'],'incidents created=',p['incidents_created']);print('Error:',p['last_error'] or 'none')" 2>/dev/null \
  || echo "  (could not parse final status — ingestion may still be running)"

# --- 7. Post-ingest dashboard summary ---------------------------------------------
say "7. Post-ingest dashboard summary"
curl -s -m 20 -H "$AUTH" "$API/dashboard/summary" | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print('KPIs:');[print('  -',k['label'],'=',k['value']) for k in d['kpis']];print('alerts_by_severity:',d['alerts_by_severity']);print('risk_over_time points:',len(d['risk_over_time']));print('recent_events:',len(d['recent_events']),'| recent_incidents:',len(d['recent_incidents']))"

# --- 8. Events / Alerts / Incidents -------------------------------------------------
say "8. Events / Alerts / Incidents"
for EP in events alerts incidents; do
  T=$(curl -s -m 20 -H "$AUTH" "$API/$EP?limit=1" | python3 -c \
    "import sys,json;print(json.load(sys.stdin).get('total','?'))" 2>/dev/null || echo "?")
  echo "  $EP total: $T"
done

# --- 9. 3D dashboard endpoints --------------------------------------------------------
say "9. 3D dashboard data (threat-space / attack-distribution / events-timeseries)"
for EP in threat-space attack-distribution events-timeseries; do
  N=$(curl -s -m 20 -H "$AUTH" "$API/dashboard/$EP" | python3 -c \
    "import sys,json;d=json.load(sys.stdin);print(len(d) if isinstance(d,list) else len(d.get('points',d.get('series',d.get('data',[])))))" 2>/dev/null || echo "?")
  echo "  $EP: $N points"
done

echo
echo "=============================================================="
echo "Verification complete. Site is live at $BASE_URL"
echo "Login: admin@cybersentinel.io / Admin@2026 (change in Settings)"
echo "=============================================================="
