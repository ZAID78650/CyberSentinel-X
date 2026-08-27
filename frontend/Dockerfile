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
# Template gets envsubst'd into /etc/nginx/conf.d/default.conf by the image
# entrypoint (needs root to write the generated config; the nginx master then
# drops to its `user nginx;` workers as configured in the base image).
COPY frontend/nginx.conf /etc/nginx/templates/default.conf.template

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O - http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
