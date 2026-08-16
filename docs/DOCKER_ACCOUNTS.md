# Local Docker stack — user sign-up & registration records

The whole platform runs locally in Docker (`docker-compose.yml`): Postgres 16 +
the FastAPI backend + the nginx-served frontend. **All account records — the
"Create Accounts" data — live in the Docker Postgres database**, persisted on
disk in the `pgdata` volume, so sign-ups survive container restarts.

## Run it

```bash
docker compose up --build -d
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000 (docs at /docs)
- Postgres: `localhost:5432` (user/pass/db all default to `cybersentinel`, override
  with `DB_USER` / `DB_PASSWORD` / `DB_NAME` or a `.env` file)

The backend container's entrypoint waits for Postgres, runs
`alembic upgrade head` (idempotent migrations), then seeds reference data —
exactly what production does on Render.

## Where sign-up / registration records are stored

| What | Where |
|---|---|
| Accounts created via **Register** (`POST /api/auth/register`) | `users` table (email, full_name, bcrypt password hash, roles, `created_at` join date, `is_verified`) |
| Accounts created via **Google / GitHub SSO** | `users` table with `oauth_provider` / `oauth_provider_id` + empty password hash (SSO-only) |
| Every sign-up/registration audit trail | `action_logs` table — `AUTH.REGISTER`, `AUTH.OAUTH_LOGIN`, `AUTH.PASSWORD_SET/CHANGED`, `AUTH.OAUTH_LINK/UNLINK` with actor, target, IP, timestamp |
| Persistence | Docker volume `pgdata` — survives `docker compose stop/up` and reboots |

## Verify it (account records land in Docker Postgres)

```bash
docker compose up -d postgres
cd backend
DATABASE_URL="postgresql+psycopg2://cybersentinel:cybersentinel@localhost:5432/cybersentinel" \
  .venv/bin/python - <<'PY'
from sqlalchemy import text
from app.core.database import SessionLocal
db = SessionLocal()
print(db.execute(text("SELECT email, created_at FROM users ORDER BY created_at DESC LIMIT 5")).mappings().all())
print(db.execute(text("SELECT action, actor, created_at FROM action_logs WHERE action LIKE 'AUTH.%' ORDER BY created_at DESC LIMIT 5")).mappings().all())
PY
```

1. Open http://localhost:3000 → **Create an account** and register.
2. Re-run the query above — the new `users` row and its `AUTH.REGISTER` audit
   record are in the Docker Postgres.
3. `docker compose stop` then `docker compose up -d postgres` — the records
   are still there (persisted in `pgdata`).

## Admin view of the records

Sign in as `admin@cybersentinel.io` / `Admin@2026` → **Administration → Users**
shows every account with its sign-in method (Password / Google / GitHub /
SSO-only), roles, join date and last login — the same data is served by
`GET /api/auth/users` (ADMIN only).

> Note: the compose DB (`pgdata` volume) is local-only. Production data lives
> in the managed Postgres on Render and is never touched by this stack.
