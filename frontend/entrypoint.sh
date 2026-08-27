#!/bin/sh
# CyberSentinel X — nginx entrypoint
# Substitutes $BACKEND_URL into the nginx config template using sed,
# then starts nginx. Preserves the original template across restarts.

set -e

# Read the template (never modified) and write the final config
# Use a fresh copy each time so BACKEND_URL changes take effect on restart
sed "s|\${BACKEND_URL}|${BACKEND_URL}|g" /etc/nginx/nginx.conf.template > /etc/nginx/conf.d/default.conf

echo "[entrypoint] nginx config ready — BACKEND_URL=${BACKEND_URL}"

# Start nginx in foreground
exec nginx -g "daemon off;"
