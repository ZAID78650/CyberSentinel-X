#!/bin/sh
# Wait for the database to become available, run migrations, then start the server.
set -e

echo "[entrypoint] waiting for database..."
python - <<'PY'
import os, time
import sqlalchemy as sa

url = os.environ.get("DATABASE_URL", "")
# Render emits postgres:// (SQLAlchemy treats it as an alias of postgresql://).
if url.startswith("postgres"):
    engine = sa.create_engine(url, connect_args={"connect_timeout": 3})
    for i in range(60):
        try:
            engine.connect().close()
            print("[entrypoint] database is ready")
            break
        except Exception as exc:
            print(f"[entrypoint] waiting for db ({i + 1}/60): {exc.__class__.__name__}")
            time.sleep(2)
    else:
        raise SystemExit("database did not become ready in time")
else:
    print("[entrypoint] non-postgres database — skipping readiness wait")
PY

echo "[entrypoint] running migrations..."
alembic upgrade head

echo "[entrypoint] seeding reference data (idempotent)..."
python - <<'PY'
from app.core.database import SessionLocal
from app.services.seed import run_seed
db = SessionLocal()
run_seed(db)
db.close()
print("[entrypoint] seed complete")
PY

echo "[entrypoint] starting application: $*"
exec "$@"
