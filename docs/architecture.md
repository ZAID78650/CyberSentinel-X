# Architecture

## System overview

CyberSentinel X is a full-stack SOC platform with a React SPA frontend and a FastAPI backend,
PostgreSQL for persistence, a vector store for RAG, and a controlled agent orchestration layer.

```
                        USER
                         │
                         ▼
                  React Frontend (Vite + TS + Tailwind + React Flow + Recharts)
                         │ REST (+ WebSocket for real-time)
                         ▼
                    FastAPI API
                         │
             +-----------+-----------+
             │                       │
             ▼                       ▼
      Authentication            WebSocket
        / RBAC                   Events
             │                       │
             ▼                       ▼
       Service Layer ─────────────►  broadcast
             │
     +-------+-------+        +--------+
     │       │       │        │        │
     ▼       ▼       ▼        ▼        ▼
   Events  Alerts  Incidents  RAG    Intel
     │       │       │
     +-------+-------+───────────────► Agent Orchestrator
                                         │
                    Detection → Investigation → Threat Intel → Risk
                                         │
                    Correlation → MITRE ATT&CK → Attack Graph
                                         │
                    Response Agent → Human Approval → Simulated Response → Report
```

## Key design decisions

1. **Sync SQLAlchemy 2.0** — FastAPI runs sync handlers in a threadpool; this keeps the agent
   pipeline straightforward while remaining fully async at the HTTP/WebSocket boundary.
2. **SQLite for local dev, PostgreSQL in Docker** — the same Alembic migrations use portable
   generic column types (`sa.Uuid`, `sa.JSON`), so one schema works in both environments.
3. **LLM provider abstraction** — `LocalModelProvider` (deterministic, evidence-grounded) is the
   default and requires no API key; `OpenAIProvider`/`GeminiProvider` activate via env vars.
   The platform is fully functional without any LLM.
4. **Vector store abstraction** — `LocalVectorStore` (numpy + hashing embeddings) is the default;
   `ChromaVectorStore` can be selected via `VECTOR_DB_BACKEND=chroma`. If unavailable, RAG
   degrades gracefully.
5. **Agent orchestration is a controlled state machine** — each stage runs in an isolated DB
   session, broadcasts status over WebSocket, and a failure in one stage never crashes the
   pipeline (stages are marked FAILED and the flow continues where safe).
6. **All response actions are simulated** — the platform is a defensive prototype; high-impact
   actions require human approval before the (simulated) execution step.

## Frontend structure

```
src/
├── components/       UI primitives, Logo, incident detail view
├── pages/            Login, Register, Dashboard, Alerts, Incidents, LiveEvents, RiskOverview,
│                     Investigation, ThreatIntelligence, AttackGraph, ResponseCenter,
│                     HumanApprovals, ActionsLog, IncidentReports, Analytics, Settings
├── layouts/          AppLayout (sidebar + top bar)
├── contexts/         AuthContext, WebSocketContext
├── hooks/            useWebSocket (re-export)
├── services/         axios client with token refresh, auth helpers
├── types/            API types
└── config.ts         runtime config (API base, WS URL)
```

## Backend structure

```
app/
├── api/              routes + auth dependencies
├── agents/           base agent, detection/investigation/threat-intel/response agents,
│                     orchestrator, LLM providers, allowlisted tools
├── attack_graph/     node/edge reconstruction with layered layout
├── core/             settings, engine, security, logging, rate limiter, WS manager
├── ml/               Isolation Forest anomaly detector
├── models/           SQLAlchemy models (25 tables)
├── rag/              vector store + indexing + retrieval
├── reports/          HTML/PDF report generation (reportlab)
├── response/         recommendations, approvals, simulated execution
├── risk/             explainable scoring engine
├── schemas/          Pydantic schemas
├── services/         auth, events, detection rules, alert/incident correlation, seed, simulator
└── threat_intel/     local STIX-shaped feed + adapter + MITRE dataset
```

## Data flow for a simulated attack

1. `POST /api/simulations/{scenario}` generates a correlated event stream.
2. Events pass through the detection pipeline: rules → intel check → ML anomaly score.
3. The Detection Agent groups anomalous events, creates an alert, and opens an incident.
4. The Orchestrator runs the async pipeline: investigation (tools: event search, entity history,
   IP reputation, intel, RAG, MITRE, attack graph, risk) → threat intel enrichment → risk →
   response recommendations (with approval requests) → automated report.
5. WebSocket broadcasts keep the frontend live at every stage.
6. Analysts approve high-impact actions; the simulated response executes and the incident is
   marked CONTAINED/RESOLVED.
