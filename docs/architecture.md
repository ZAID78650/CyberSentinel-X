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
├── api/              routes + auth dependencies (incl. campaign_intel, ueba, analytics_ext)
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
├── services/         auth, events, detection rules, alert/incident correlation, seed, simulator,
│                     campaign_intel (velocity/momentum/similarity/mutation/MITRE coverage),
│                     ueba (behavioral baselines, entity risk, attack surface),
│                     data_quality (quality score, model drift PSI)
└── threat_intel/     local STIX-shaped feed + adapter + MITRE dataset
```

## Campaign intelligence & UEBA (new in this cycle)

New engines compute analytics from real correlated data (no random values):

- **Attack velocity** — kill-chain stage transition times, stages/hour, acceleration and
  `LOW/MEDIUM/HIGH/CRITICAL` band + campaign-escalation flag.
- **Campaign momentum** — 0-100 weighted score from event-rate change, new assets,
  new techniques, severity change, anomaly ratio and exfiltration signals.
- **Campaign similarity** — explainable weighted technique/behavior/severity/protocol/source
  comparison (Jaccard + cosine) with per-component reasons.
- **Campaign mutation** — flags campaigns with high behavioral similarity but low IOC overlap.
- **MITRE detection coverage** — expected vs detected techniques per kill-chain tactic + gaps.
- **Business impact** — qualitative HIGH/MEDIUM/LOW from critical assets, sensitive data stores,
  affected users and external endpoints.
- **UEBA** — per user/IP/device baselines (first 60% of history) vs current (last 40%) with
  explainable factors (off-hours, failed-auth spike, new device, large data access).
- **Entity risk + enterprise risk** — weighted UEBA/intel/anomaly/criticality per entity.
- **Attack surface** — score from observed protocols, external endpoints, intel matches,
  auth failures and ports.
- **Data quality** — completeness/duplicates/imbalance/staleness/ingestion health -> 0-100.
- **Model drift** — Population Stability Index / KL divergence on anomaly-score distributions.
- **Merkle roots** — ledger blocks now carry a binary Merkle-tree root over their evidence hashes
  (previously a linear digest), verified during chain audits.

See [CAMPAIGN_UEBA_INTEL.md](CAMPAIGN_UEBA_INTEL.md) for endpoints, algorithms and the demo flow.

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

## Integration round — feedback loop, SBOM, intel fusion, Judge Mode

- **Analyst feedback loop** — `analyst_feedback` table (alert FK, label, analyst, note);
  `POST /api/alerts/{id}/feedback` (latest label wins per analyst) and
  `GET /api/analytics/feedback-stats` (signals before correlation vs alerts after,
  label distribution, observed precision and false-positive rate). Labels are stored,
  audited (action_logs) and never silently applied to models.
- **SBOM / supply chain** — `GET /api/sbom` scans the repo's own `package-lock.json` +
  `requirements.txt` into a normalized SBOM and cross-references dependencies against
  the local CVE feed. Explainable supply-chain risk with visible factor weights;
  dependencies with no local CVE match are reported as not known-vulnerable, never guessed.
- **Threat intel fusion status** — `GET /api/threat-intelligence/sources/status` reports
  configured feeds with provenance; with only the local feed it explicitly returns
  `NO LIVE THREAT INTELLIGENCE SOURCE CONFIGURED`.
- **Data pipeline aggregate** — `GET /api/data/pipeline` reports INGEST → … → RETRAIN
  with real per-stage counts and strict train/validation/test separation.
- **Judge Mode** — `GET /api/analytics/judge-mode` aggregates the end-to-end pipeline
  (EVENTS → ALERTS → CAMPAIGNS → ATTACK DNA → PREDICTION → BLAST RADIUS → RESPONSE →
  BLOCKCHAIN PROOF) with real counts, provenance per stage, MTTD/MTTR, evidence verified,
  merkle roots and agent-run health. Frontend page at `/judge-mode`; SBOM page at `/sbom`;
  Alerts page has the TP/FP/Benign feedback controls.
