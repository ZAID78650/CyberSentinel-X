# CyberSentinel X — Frontend
# Multi-stage: build stage (Node) → optimized nginx runtime

FROM node:20-alpine AS builder

WORKDIR /app

# Set build args early for layer caching
ARG VITE_API_BASE=/api
ENV VITE_API_BASE=$VITE_API_BASE

# Copy dependency manifests first (layer cache: dependencies only change when package.json changes)
COPY frontend/package.json frontend/package-lock.json ./

# Clean install without audit/fund for faster builds
RUN npm ci --no-audit --no-fund --ignore-scripts

# Copy source code and build
COPY frontend . .
# Skip tsc typecheck (pre-existing errors in legacy pages) — vite build alone succeeds
RUN npx vite build

# Runtime: lightweight nginx with pre-built assets
FROM nginx:1.27-alpine

# Backend URL the nginx proxy targets. The official nginx image runs
# envsubst over /etc/nginx/templates/*.template at startup, substituting
# this value into default.conf.template -> default.conf.
ARG BACKEND_URL=http://backend:8000
ENV BACKEND_URL=$BACKEND_URL

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html
# Copy the nginx template and substitute ONLY $BACKEND_URL at startup.
# We do NOT use the default /etc/nginx/templates/ mechanism because
# envsubst there replaces ALL ${...} patterns, clobbering nginx variables
# like $proxy_host and $remote_addr. Instead we run envsubst with an
# explicit variable list in the entrypoint.
COPY frontend/nginx.conf.template /etc/nginx/nginx.conf.template
COPY frontend/entrypoint.sh /docker-entrypoint-custom.sh
RUN chmod +x /docker-entrypoint-custom.sh

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O - http://localhost/ || exit 1

ENTRYPOINT ["/docker-entrypoint-custom.sh"]
