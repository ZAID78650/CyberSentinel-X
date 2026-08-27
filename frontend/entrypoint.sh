#!/bin/sh
# CyberSentinel X — nginx entrypoint
# Substitutes $BACKEND_URL into the nginx config template,
# then starts nginx.

set -e

# Replace ${BACKEND_URL} with the actual value
envsubst '${BACKEND_URL}' < /etc/nginx/nginx.conf.template > /etc/nginx/conf.d/default.conf

echo "[entrypoint] nginx config ready — BACKEND_URL=${BACKEND_URL}"

# Start nginx in foreground
exec nginx -g "daemon off;"
