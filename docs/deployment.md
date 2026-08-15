# Deployment

## Docker Compose (local production-like stack)

```bash
cp .env.example .env
docker compose up --build -d
```

Services:

| Service | Image | Notes |
|---------|-------|-------|
| `postgres` | postgres:16-alpine | Persistent volume, healthcheck |
| `backend` | built from `backend/Dockerfile` | Waits for DB → migrates → seeds → gunicorn+uvicorn; healthcheck |
| `frontend` | built from `frontend/Dockerfile` | nginx serving the SPA and proxying `/api`, `/ws`, `/health`, `/ready` |

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health · Ready: http://localhost:8000/ready

## Production posture

- **Backend**: gunicorn with `uvicorn.workers.UvicornWorker` (2+ workers), `ENVIRONMENT=production`
- **Frontend**: nginx static server with gzip, SPA fallback, WebSocket upgrade headers
- **Database**: PostgreSQL with named volumes for persistence
- **Migrations**: run automatically by the entrypoint before the app starts
- **Seeding**: idempotent, runs at startup
- **Health checks**: container-level + `/health` / `/ready` endpoints
- **HTTPS**: terminate TLS at the platform load balancer / ingress (set `X-Forwarded-Proto`),
  or add a TLS-terminating reverse proxy in front of the frontend service

## Cloud deployment (Render / Railway / Fly / GCP / AWS)

The stack is provider-agnostic; no cloud provider is hard-coded. To deploy:

1. **Frontend** as a static site or container: build with `npm run build`, serve `dist/`.
   Set `VITE_API_BASE=/api` and point nginx/ingress at the backend.
2. **Backend** as a web service: `docker build -t csx-backend ./backend`, run with
   `DATABASE_URL` pointing at a managed PostgreSQL instance. Set JWT secrets via the platform's
   secret store. Command: `gunicorn app.main:app --workers 2 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000`.
3. **Database** as a managed PostgreSQL (e.g. RDS, Supabase, Neon).
4. **Persistent storage**: mount a volume for `data/reports` and `data/vector_store`
   (or use object storage for reports).

Required environment variables (set in the platform, never committed):

```
DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/cybersentinel
JWT_SECRET=<random>
JWT_REFRESH_SECRET=<random>
LLM_PROVIDER=local            # or openai/gemini with the matching API key
CORS_ORIGINS=https://your-frontend-domain
ENVIRONMENT=production
```

Generate secrets with: `python -c "import secrets; print(secrets.token_urlsafe(64))"`

## Docker Hub (publishing images)

```bash
# 1. Log in once (Docker Hub username/email + access token)
docker login

# 2. Build and push frontend + backend images
bash scripts/push-dockerhub.sh
# or: DOCKER_REGISTRY=fs22ai006/cybersentinel-x bash scripts/push-dockerhub.sh
```

Images are tagged `backend` / `frontend` (plus `-latest`).

## Email notifications (SMTP via Gmail)

Set these in `backend/.env` (or the platform's secret store):

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=fs22ai006@gmail.com
SMTP_PASSWORD=<gmail APP password — create at myaccount.google.com/apppasswords>
EMAIL_FROM=CyberSentinel X <fs22ai006@gmail.com>
OPS_EMAIL=fs22ai006@gmail.com
```

Enabled features once configured:

- **Password reset emails** — `/api/auth/forgot-password` sends a real reset link (30-min token)
- **Incident alerts** — HIGH/CRITICAL incidents email the ops address
- **SMTP test** — `POST /api/security/test-email` (ADMIN) verifies connectivity
- **Container watchdog** — `bash scripts/notify-docker-status.sh` emails when compose
  containers are unhealthy/down (run it on a 5-min cron/launchd timer)

If `SMTP_PASSWORD` is empty, email degrades gracefully (logged, never crashes).

## CI/CD (GitHub Actions)

`.github/workflows/ci.yml` runs on push/PR to `main`:

1. Backend: ruff lint + pytest (34 tests)
2. Frontend: `npm ci`, `npm run typecheck`, `npm run build`
3. Docker: build backend and frontend images, validate `docker compose config`

## Verification checklist

```bash
curl http://localhost:8000/health   # {"status":"ok"}
curl http://localhost:8000/ready    # {"status":"ready","database":"connected"}
```
Then run the end-to-end smoke test (see `backend/scripts/smoke_test.py`).
