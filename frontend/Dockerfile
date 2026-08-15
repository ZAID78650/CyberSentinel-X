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
RUN npm run build

# Runtime: lightweight nginx with pre-built assets
FROM nginx:1.27-alpine

# Create non-root user for nginx
RUN addgroup -g 101 -S nginx && \
    adduser -S -D -H -u 101 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx 2>/dev/null || true

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Set proper permissions
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chmod -R 755 /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O - http://localhost/ || exit 1

USER nginx

CMD ["nginx", "-g", "daemon off;"]
