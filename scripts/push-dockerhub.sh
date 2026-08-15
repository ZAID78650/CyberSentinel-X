#!/bin/bash
# ============================================================
# Build + push CyberSentinel X images to Docker Hub.
#
#   Usage:
#     bash scripts/push-dockerhub.sh                 # uses DOCKER_REGISTRY from .env
#     DOCKER_REGISTRY=fs22ai006/cybersentinel-x bash scripts/push-dockerhub.sh
#
#   Prerequisites:
#     1. docker login (or this script will prompt)
#     2. DOCKER_REGISTRY set, e.g. fs22ai006/cybersentinel-x
# ============================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Resolve the registry (env var wins, then backend/.env, then default)
REGISTRY="${DOCKER_REGISTRY:-}"
if [ -z "$REGISTRY" ] && [ -f backend/.env ]; then
  REGISTRY=$(grep -E '^DOCKER_REGISTRY=' backend/.env | cut -d= -f2- | tr -d '"' || true)
fi
REGISTRY="${REGISTRY:-fs22ai006/cybersentinel-x}"
echo "[docker] registry: ${REGISTRY}"

# Build images
echo "[docker] building backend image..."
docker build -t "${REGISTRY}:backend" -t "${REGISTRY}:backend-latest" ./backend

echo "[docker] building frontend image..."
docker build -t "${REGISTRY}:frontend" -t "${REGISTRY}:frontend-latest" ./frontend

# Login + push
echo "[docker] checking docker login..."
if ! docker info >/dev/null 2>&1; then
  echo "[docker] ERROR: Docker daemon is not running. Start Docker Desktop and retry."
  exit 1
fi
if ! docker system info | grep -q "Username"; then
  echo "[docker] not logged in — run: docker login"
  echo "[docker] (use your Docker Hub username/email + an access token)"
  read -r -p "Continue login now? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    docker login
  else
    echo "[docker] login skipped — images are built locally but not pushed."
    exit 0
  fi
fi

echo "[docker] pushing backend..."
docker push "${REGISTRY}:backend"
docker push "${REGISTRY}:backend-latest"
echo "[docker] pushing frontend..."
docker push "${REGISTRY}:frontend"
docker push "${REGISTRY}:frontend-latest"

echo
echo "[docker] done. Images:"
echo "  ${REGISTRY}:backend"
echo "  ${REGISTRY}:frontend"
