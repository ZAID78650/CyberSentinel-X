#!/bin/sh
# CyberSentinel X — nginx entrypoint
# Substitutes $BACKEND_URL into the nginx config template using sed,
# then starts nginx. envsubst is not reliably available in alpine.

set -e

# Use sed to replace ${BACKEND_URL} with the actual value
# The double-slash in the template's proxy_pass ensures proper stripping
sed -i "s|\${BACKEND_URL}|${BACKEND_URL}|g" /etc/nginx/nginx.conf.template

# Write the final config
cp /etc/nginx/nginx.conf.template /etc/nginx/conf.d/default.conf

echo "[entrypoint] nginx config ready — BACKEND_URL=${BACKEND_URL}"

# Start nginx in foreground
exec nginx -g "daemon off;"
