# CyberSentinel X — Backend
# Multi-stage build for optimized image size and faster layer caching.

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /tmp

# Install build dependencies (only needed for wheel building)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements early for layer caching
COPY backend/requirements.txt .
RUN pip install --upgrade pip setuptools && \
    pip install --user --no-warn-script-location -r requirements.txt

# Production runtime stage
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only runtime dependencies (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/* && \
    addgroup --gid 1000 appuser && \
    adduser --uid 1000 --gid 1000 --disabled-password --gecos "" appuser

# Copy pre-built wheels from builder into the *system* site-packages so the
# non-root runtime user (appuser) can import them — /root/.local would be
# unreadable to appuser.
COPY --from=builder /root/.local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /root/.local/bin /usr/local/bin

# Copy application files
COPY backend/alembic.ini .
COPY backend/alembic ./alembic
COPY backend/app ./app
COPY backend/scripts ./scripts
COPY backend/docker-entrypoint.sh /docker-entrypoint.sh
# RAG knowledge base (resolved as /data/knowledge_base at runtime)
COPY data/knowledge_base /data/knowledge_base

# Data lives under /app/data (writable by appuser): uploads + RAG vector store.
# The uploads dir defaults to ../data/uploads relative to CWD — pin it here so
# the non-root runtime user can always write, on any host (compose or Render).
ENV DATASET_UPLOAD_DIR=/app/data/uploads

# Create data directories and set permissions
RUN mkdir -p /app/data/uploads && \
    chmod +x /docker-entrypoint.sh && \
    chmod +x /app/scripts/*.py 2>/dev/null || true && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]

# Shell form so WEB_CONCURRENCY is expandable at runtime — Render's free tier
# has 512 MB RAM, so default to 2 workers (4 can OOM at startup).
CMD gunicorn app.main:app --workers ${WEB_CONCURRENCY:-2} --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --access-logfile - --timeout 120 --max-requests 1000
