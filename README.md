# 🛡️ CyberSentinel X

**Agentic AI-Powered Autonomous Cyber Threat Detection, Investigation & Response Platform**

CyberSentinel X is a professional Security Operations Center (SOC) platform prototype built for
**Smart India Hackathon 2026**. It delivers a genuine, end-to-end workflow — events are detected,
correlated, investigated by AI agents, mapped to MITRE ATT&CK, scored for risk, responded to with
human approval, and documented in automated reports.

> **Cybersecurity boundary:** every attack in this project is *synthetic and simulated*. The platform
> never attacks real systems, never executes destructive real-world response actions, and never
> allows AI agents unrestricted code/shell execution.

---

## ✨ Highlights

- **Hybrid detection** — deterministic rules + Isolation Forest anomaly detection + threat intelligence + AI reasoning (never LLM-only)
- **Agentic AI pipeline** — Detection → Investigation → Threat Intel → MITRE mapping → Attack Graph → Risk → Response → Human Approval → Simulated Response → Report
- **Controlled agents** — allowlisted tools only; no shell/code execution; concise evidence-based summaries (no hidden chain-of-thought)
- **Explainable risk engine** — 30% behavioral anomaly · 20% threat intelligence · 20% asset criticality · 15% attack progression · 15% historical evidence
- **RAG knowledge base** — vector retrieval over playbooks, policies, MITRE and CVE references, with graceful degradation
- **LLM abstraction** — `local` (deterministic, zero API keys) · `openai` · `gemini`
- **Real-time SOC** — WebSockets stream live events, agent status, alerts and incident updates
- **RBAC** — ADMIN · SECURITY_ANALYST · VIEWER with JWT access/refresh tokens
- **Full audit trail** — every action logged with actor, target, IP and timestamp
- **Synthetic attack simulator** — Account Takeover, Brute Force, Malware, Data Exfiltration, Privilege Escalation
- **Automated incident reports** — HTML + PDF export
- **Docker Compose, CI/CD, tests, migrations** — production-ready posture

---

## 🧱 Architecture

```
USER → React Frontend (Vite + TS + Tailwind)
         │ REST + WebSocket
         ▼
     FastAPI API
         │
   ┌──────┴──────┐
   │  Auth/RBAC  │  WebSocket events
   └──────┬──────┘
         ▼
     Service Layer
   (events · alerts · incidents)
         │
         ▼
   Agent Orchestrator (state machine)
   Detection → Investigation → Threat Intel → Risk
         │
         ▼
   Correlation → MITRE ATT&CK → Attack Graph
         │
         ▼
   Response Agent → Human Approval → Simulated Response → Incident Report
```

Supporting services: **PostgreSQL**, **vector store** (local numpy backend by default, Chroma optional),
**RAG knowledge base**, **local threat-intel feed** (STIX-shaped, swappable for live TAXII/APIs), **ML models**.

Full details: [docs/architecture.md](docs/architecture.md)

---

## 🗂️ Repository layout

```
cybersentinel-x/
├── backend/            FastAPI application
│   ├── app/
│   │   ├── api/        REST + WebSocket routes
│   │   ├── agents/     Detection, Investigation, Threat Intel, Response agents + orchestrator + LLM abstraction
│   │   ├── attack_graph/  Attack graph reconstruction
│   │   ├── core/       config, database, security, logging, rate limiting, websocket manager
│   │   ├── ml/         Isolation Forest anomaly detection
│   │   ├── models/     SQLAlchemy models (full schema)
│   │   ├── rag/        Vector store abstraction + retrieval pipeline
│   │   ├── reports/    HTML + PDF incident report generation
│   │   ├── response/   Response recommendations + human approval + simulated execution
│   │   ├── risk/       Explainable risk engine
│   │   ├── schemas/    Pydantic schemas
│   │   ├── services/   auth, events, detection, alert/incident, seed, simulator
│   │   └── threat_intel/  Local feed + STIX-shaped adapter + MITRE dataset
│   ├── alembic/        Database migrations
│   ├── scripts/        smoke_test.py (end-to-end API verification)
│   └── tests/          pytest suite (34 tests)
├── frontend/           React + Vite + TypeScript + Tailwind SOC console
├── data/
│   ├── knowledge_base/  RAG documents (playbooks, policies, CVE, MITRE)
│   └── vector_store/    Persisted embeddings (generated)
├── docs/               Architecture, database, agents, API, security, deployment, demo
├── scripts/
├── docker-compose.yml
├── .env.example
└── .github/workflows/ci.yml
```

---

## 🚀 Quick start (Docker — recommended)

```bash
cp .env.example .env          # optionally set JWT secrets
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health · Readiness: http://localhost:8000/ready

## 🖥️ Local development

**Backend** (Python 3.10+; Docker image uses 3.12):

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env          # defaults to SQLite — zero external deps
alembic upgrade head          # create schema
python -c "from app.services.seed import run_seed; from app.core.database import SessionLocal; run_seed(SessionLocal())"
uvicorn app.main:app --reload --port 8000
```

**Frontend**:

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173 (proxies /api and /ws to :8000)
```

### Demo accounts (seeded)

| Role | Email | Password |
|------|-------|----------|
| ADMIN | `admin@cybersentinel.io` | `Admin@2026` |
| SECURITY_ANALYST | `analyst@cybersentinel.io` | `Analyst@2026` |
| VIEWER | `viewer@cybersentinel.io` | `Viewer@2026` |

---

## 🎬 2–5 minute demo

1. **Log in** with `admin@cybersentinel.io`
2. Open the **Dashboard** — live KPIs, agent status, risk charts
3. Click **Simulate Account Takeover** (or Brute Force / Malware / Data Exfiltration / Privilege Escalation)
4. Watch **live events** stream in and the **Detection Agent** raise a CRITICAL alert
5. Open the incident → **AI Investigation** completes with evidence, verdict and confidence
6. Review **Threat Intelligence**, **MITRE ATT&CK** mapping and the **Attack Graph**
7. See the **Risk Score** with its explainable factor breakdown
8. Open **Response Center** → **Approve** a recommended action → watch the simulated response execute
9. **Generate the Incident Report** and export the **PDF**

Full walkthrough: [docs/demo.md](docs/demo.md)

---

## 🧪 Testing

```bash
# Backend unit + integration tests (34 tests: auth, RBAC, detection, ML, RAG,
# threat intel, MITRE, attack graph, risk, approvals, reports, full pipelines)
cd backend && pytest tests -q

# End-to-end API smoke test (requires running backend)
cd backend && uvicorn app.main:app --port 8000 &
python scripts/smoke_test.py
```

Frontend: `npm run typecheck` and `npm run build` (strict TypeScript, ESLint configured).

---

## 🔐 Security posture

- bcrypt password hashing · JWT access + refresh tokens · RBAC on every route
- Input validation (Pydantic) · parameterized queries (SQLAlchemy) · XSS/CSP/clickjacking headers · CORS allowlist
- Rate limiting on authentication endpoints · full audit logging (never logs secrets)
- **Agent hardening:** allowlisted tools only, no shell/code execution, human approval for high-impact actions, simulated response execution
- Secrets only via environment variables — never committed, never in frontend code

More: [docs/security.md](docs/security.md)

---

## 📚 Documentation

| Doc | Contents |
|-----|----------|
| [docs/architecture.md](docs/architecture.md) | System architecture & data flow |
| [docs/database.md](docs/database.md) | Schema, migrations, seeding |
| [docs/agents.md](docs/agents.md) | Agent orchestration, tools, LLM abstraction |
| [docs/api.md](docs/api.md) | REST + WebSocket API reference |
| [docs/security.md](docs/security.md) | Security architecture & hardening |
| [docs/deployment.md](docs/deployment.md) | Docker, CI/CD, cloud deployment |
| [docs/demo.md](docs/demo.md) | SIH demo walkthrough |

## 🗺️ Roadmap

- Live STIX/TAXII and vendor threat-intel adapters
- pgvector / FAISS vector backends
- Multi-tenant organizations and SSO
- XGBoost classifier for attack-type prediction
- Real EDR/SIEM ingestion connectors (syslog, CEF)
- SOAR-style playbook automation with external integrations

## ⚠️ Known limitations

- Threat intel is a synthetic local feed (no live external APIs by default)
- Response actions are simulated by design — no real EDR/network enforcement
- Vector store defaults to a lightweight numpy backend; Chroma is optional
- Without an LLM API key, AI summaries are deterministic, evidence-grounded templates

## 📄 License

MIT — see [LICENSE](LICENSE).
