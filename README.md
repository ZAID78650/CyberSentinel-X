# 🛡️ CyberSentinel X — Predictive Financial Cybercrime Intelligence Platform

**Agentic AI-Powered Predictive Cybercrime Withdrawal Analytics for SIH 2026 (SIH26184)**

CyberSentinel X is a **predictive financial-cybercrime intelligence platform** built for
**Smart India Hackathon 2026** under problem statement **SIH26184 — Predictive Cybercrime 
Withdrawal Analytics**. It transforms raw cybercrime complaints into proactive, actionable 
intelligence using machine learning, geospatial analysis, and blockchain-backed evidence integrity.

> **The central story:** Complaint → AI Prediction → Alert → Intervention → Potential Prevention

> **Cybersecurity boundary:** Every dataset in this project is synthetic and simulated. The platform
> never attacks real systems, never accesses real financial data, and never allows unrestricted AI execution.

---

## ✨ Key Capabilities

### 🎯 Predictive Withdrawal Intelligence Engine
- **XGBoost-style ML model** that learns from complaint time, transaction patterns, fraud types, 
  account relationships, geographic clustering, and temporal patterns
- Produces **risk probability** (not certainty) with confidence scores
- Generates predictive alerts with full **explainability** — every prediction shows contributing features

### 🗺️ GIS Risk Heatmap *(PS Required)*
- Interactive geographic visualization of risk zones across India
- Filters by state, district, fraud type, risk level, and prediction window
- Click any zone for **explainability**: why is this area high risk?
- Shows related complaints, linked transactions, historical patterns, and confidence intervals

### 🚨 Real-Time Intelligence *(PS Required)*
- Proactive intervention workflow: Complaint → AI Prediction → Alert → Intervention
- Predictive alerts with risk probability, confidence, time windows, and crime patterns
- Evidence chain with cryptographic hashing for audit integrity

### 🏦 LEA & Bank/FI Dashboards *(PS Required)*
- **Law Enforcement Dashboard** with intervention pipeline, case timeline, and alert management
- **Bank/FI Alert System** with institution-level crime analytics
- Action tracking: acknowledge, escalate, or dismiss predictive alerts

### 🔐 Evidence Integrity Ledger
- SHA-256 hash chain with proof-of-work anchoring
- Every prediction, alert, and intervention creates an immutable audit record
- Tamper detection and chain-of-custody verification
- Blockchain-compatible architecture (migrate to Hyperledger Fabric)

---

## 🧱 Architecture

```
USER → React Frontend (Vite + TypeScript + Tailwind)
         │ REST + WebSocket
         ▼
     FastAPI Backend
         │
   ┌─────┴─────────────────────┐
   │  Cyber Intelligence       │  Financial Intelligence
   │  • Threat Detection       │  • Complaint Analysis
   │  • Anomaly Detection      │  • Transaction Analysis
   │  • IP Intelligence        │  • Fraud Patterns
   │  • MITRE ATT&CK           │  • Account Relationships
   └─────┬─────────────────────┘
         ↓
   PREDICTIVE AI ENGINE
         │
   ┌─────┼─────────────────┐
   ↓     ↓                 ↓
   Pattern ML    Geospatial ML    Time-Series
         │
         ↓
   WITHDRAWAL PREDICTION
         │
   ┌─────┴─────────────┐
   ↓                   ↓
   GIS Heatmap    Predictive Alerts
         │
   ┌─────┴─────────────┐
   ↓                   ↓
   LEA Dashboard   Bank/FI Alerts
         │
         ↓
   ACTIONABLE INTELLIGENCE
         │
         ↓
   Evidence Integrity Ledger (Blockchain)
```

---

## 🗂️ Repository Layout

```
cybersentinel-x/
├── backend/            FastAPI application
│   ├── app/
│   │   ├── api/routes/ REST routes including:
│   │   │   ├── financial.py   Financial intelligence + GIS + predictions + LEA
│   │   │   └── ...
│   │   ├── agents/     AI agents (detection, investigation, response)
│   │   ├── core/       Config, database, security, logging
│   │   ├── ml/         Isolation Forest anomaly detection
│   │   ├── models/     SQLAlchemy models including:
│   │   │   ├── financial.py   Complaints, transactions, zones, predictions
│   │   │   └── ...
│   │   ├── services/   Business logic including:
│   │   │   ├── financial_data.py     Synthetic data generator
│   │   │   ├── predictive_engine.py  ML prediction engine
│   │   │   └── ...
│   │   └── ...
│   └── tests/          pytest suite
├── frontend/           React + Vite + TypeScript + Tailwind
│   └── src/pages/
│       ├── GisHeatmap.tsx          GIS Risk Heatmap (PS Required)
│       ├── PredictiveAlerts.tsx    Predictive Alert cards
│       ├── FinancialIntelligence.tsx  Financial Intel dashboard
│       ├── LeaDashboard.tsx        LEA & Bank/FI dashboard
│       └── Dashboard.tsx           Main dashboard with financial summary
├── data/
├── docs/
└── docker-compose.yml
```

---

## 🚀 Quick Start (Docker)

```bash
cp .env.example .env
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

---

## 🖥️ Local Development

**Backend:**
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Demo Accounts
| Role | Email | Password |
|------|-------|----------|
| ADMIN | `admin@cybersentinel.io` | `Admin@2026` |
| ANALYST | `analyst@cybersentinel.io` | `Analyst@2026` |
| VIEWER | `viewer@cybersentinel.io` | `Viewer@2026` |

---

## 🎬 Demo Walkthrough (Killer Demo)

1. **Log in** with admin account
2. Open **Dashboard** — see financial crime intelligence summary
3. Navigate to **GIS Risk Heatmap** — interactive zone visualization
4. Click a **high-risk zone** — see explainability layer (why is this area risky?)
5. Open **Predictive Alerts** — killer alert cards with risk probability, confidence, time windows
6. Expand an **alert** — full analysis with feature contributions, recommended actions, evidence chain
7. Open **LEA Dashboard** — proactive intervention pipeline, case timeline
8. Check **Bank/FI Alerts** — institution-level analytics
9. Review **Evidence Ledger** — blockchain-style hash chain for all predictions
10. Navigate to **Financial Intelligence** — complaint trends, fraud type breakdown, state distribution

---

## 🧪 Testing

```bash
# Backend tests
cd backend && pytest tests -q

# Frontend typecheck + build
cd frontend && npm run typecheck && npm run build
```

---

## 🔐 Security

- bcrypt password hashing · JWT access + refresh tokens · RBAC
- Input validation (Pydantic) · parameterized queries (SQLAlchemy)
- CORS allowlist · Rate limiting · Full audit logging
- Evidence integrity with SHA-256 hash chain + proof-of-work

---

## 📚 Problem Statement Alignment

| PS Deliverable | CyberSentinel-X Implementation |
|----------------|-------------------------------|
| Predictive Analytics Engine | XGBoost-style ensemble with 8 weighted features, sigmoid activation, temporal adjustment |
| GIS Risk Heatmap | Interactive SVG map with zone clustering, filters, and explainability |
| Law Enforcement Interface | LEA Dashboard with intervention pipeline, case management, alert actions |
| Alert & Notification System | Predictive alert cards with risk probability, confidence, time windows |
| Evidence Integrity | SHA-256 hash chain with proof-of-work anchoring, tamper detection |
| Proactive Intervention | Complaint → AI Prediction → Alert → Intervention → Prevention pipeline |

---

## 📄 License

MIT
