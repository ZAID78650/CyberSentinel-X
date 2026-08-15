# Database

## Engine & migrations

- **SQLAlchemy 2.0** (sync) with `declarative_base`.
- **Alembic** migrations in `backend/alembic/`. `alembic upgrade head` creates the schema.
  Autogeneration is supported for both SQLite and PostgreSQL because all columns use portable
  generic types.
- The backend Docker entrypoint waits for PostgreSQL readiness, runs `alembic upgrade head`,
  then seeds reference data (idempotent).

## Schema (25 tables)

| Table | Purpose |
|-------|---------|
| `users` | Accounts with bcrypt password hashes |
| `roles`, `user_roles` | RBAC roles (ADMIN, SECURITY_ANALYST, VIEWER) and assignment |
| `devices` | Endpoint/device inventory with trust flags |
| `assets` | Asset inventory with criticality (0–10) |
| `security_events` | Normalized event stream (indexed on timestamp, source_ip, event_type) |
| `alerts` | Detection Agent output (severity, confidence, source events) |
| `incidents` | Correlated attack chains |
| `incident_events` | Incident ↔ event linkage |
| `investigations` | Agent investigation results (summary, verdict, confidence, timeline, evidence) |
| `investigation_evidence` | Individual evidence findings |
| `threat_indicators` | Indicator feed (IP/domain/hash/CVE/malware/technique) |
| `threat_intelligence_sources` | Intel source registry (local / stix / taxii / api) |
| `mitre_techniques` | Embedded ATT&CK knowledge base |
| `incident_mitre_mapping` | Incident → technique mappings with confidence/evidence |
| `attack_nodes`, `attack_edges` | Attack graph persistence |
| `risk_scores` | Explainable risk factor breakdowns |
| `response_recommendations` | Response actions with impact + status |
| `approval_requests` | Human-in-the-loop approval workflow |
| `action_logs` | Audit trail (actor, action, target, IP, request id) |
| `incident_reports` | Generated report metadata + content + PDF path |
| `ai_agent_runs` | Agent run observability (status, tools used, summary) |
| `knowledge_documents` | RAG source documents |
| `notifications` | User notifications |

## Conventions

- UUID primary keys, `created_at`/`updated_at` on all mutable tables
- Foreign keys with cascade rules (incident → events/mappings/graph/risk/approvals/reports)
- Indexes on hot query paths: event timestamp/source_ip/type, incident status, agent runs, audit log
- JSON columns for flexible payloads (event metadata, factor breakdowns, graph properties)
- **No plaintext passwords** — bcrypt with per-user salts (12 rounds)

## Seeding (`app/services/seed.py`)

Runs automatically at app startup (idempotent) and inside the Docker entrypoint:

- 3 demo users with RBAC roles
- 8 assets with criticality ratings
- 52 MITRE ATT&CK techniques
- 28 threat indicators (synthetic STIX-shaped feed)
- 9 RAG knowledge documents indexed into the vector store
- **1,024+ historical security events** including five full attack scenarios
  (account takeover, brute force, malware, data exfiltration, privilege escalation)

## Verification

```bash
cd backend
alembic upgrade head
python -c "from app.core.database import SessionLocal; from app.services.seed import run_seed; run_seed(SessionLocal())"
```
