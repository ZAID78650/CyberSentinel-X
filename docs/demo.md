# SIH Demo Walkthrough (2–5 minutes)

This script shows the complete platform in a judge-friendly flow. All data is synthetic;
nothing external is touched.

## Setup

```bash
docker compose up --build -d        # or run local dev (see README)
```

Open http://localhost:3000.

## Script

**1. Login (30s)**
- Sign in with `admin@cybersentinel.io` / `Admin@2026`
- Note the dark SOC theme, shield logo, sidebar groups, real-time indicator in the top bar

**2. Dashboard (45s)**
- Point out the six KPI cards (alerts, criticals, active incidents, high risk, anomalies, approvals)
- AI Agent Status panel (Detection / Investigation / Threat Intel / Risk / Response)
- Risk-over-time and alerts-by-severity charts, top threat sources, recent incidents

**3. Simulate Account Takeover (30s)**
- Click **Simulate Account Takeover** on the dashboard
- Watch live events stream in, the Detection Agent fire, and a CRITICAL alert appear
- A toast confirms the pipeline started; you're taken to the new incident

**4. Investigation (45s)**
- The AI Investigation tab shows the agent correlating events
- When complete: verdict ("HIGH-CONFIDENCE MALICIOUS ACTIVITY"), confidence %, evidence list,
  MITRE ATT&CK mappings (T1110, T1078, T1548…), and an event timeline

**5. Intelligence & graph (30s)**
- Threat Intelligence tab: search `45.155.205.233` → local feed matches with severity/confidence
- Attack Graph tab: node/edge list, then open the full interactive React Flow graph

**6. Risk (30s)**
- Risk tab: gauge + five explainable factors with evidence strings and the weighted breakdown

**7. Response & human approval (45s)**
- Response tab: recommended actions (revoke sessions, force MFA, isolate endpoint, block IP…)
- Approve one — watch the simulated execution summary appear and the incident move to CONTAINED/RESOLVED
- Show the same flow from **Human Approvals** (queue + approve/reject)

**8. Report (30s)**
- Open **Incident Reports**, generate the report, view it, and download the **PDF**

**9. Extras (time permitting)**
- Live Events page streaming, Actions Log audit trail, Analytics charts, RBAC (log in as `viewer@…`
  and show simulations are blocked with 403)

## What judges should notice

- Genuine end-to-end flow — nothing hard-coded, all data from the API
- Real-time updates via WebSocket (no page reloads)
- Explainability everywhere: detection reasons, evidence, risk factors, tool usage
- Security discipline: allowlisted agents, human approval, simulated responses, audit log
