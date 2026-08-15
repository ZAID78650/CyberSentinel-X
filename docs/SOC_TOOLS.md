# CyberSentinel-X — SOC Analyst Tools

Analyst-facing capabilities built on **real system data** (UNSW-NB15 corpus +
the agent pipeline). Nothing here is randomly generated.

All endpoints are under `/api/soc` (auth required). Backend:
`backend/app/services/soc_analytics.py` + `backend/app/api/routes/soc_tools.py`.

---

## 1. Threat Hunting Console

**API:** `POST /api/soc/threat-hunting` · `POST /api/soc/threat-hunting/save`
**UI:** sidebar → **Security → Threat Hunting**

Natural-language queries are translated into a **whitelisted, validated filter
object** — never arbitrary user SQL. The generated filters are shown to the
analyst with a confidence score.

Examples that work:

| Query | Generated filters |
|---|---|
| "Find all critical incidents in the last 6 hours" | `severity IN (CRITICAL)`, `timestamp >= now() - interval '6 hours'` |
| "repeated authentication failures from 45.155.205.233" | `event_type IN (LOGIN_FAILURE)`, `source_ip IN (45.155.205.233)` |
| "show endpoints with abnormal outbound traffic" | `event_type IN (SUSPICIOUS_NETWORK_CONNECTION)` |
| "find assets associated with privilege escalation" | `event_type IN (PRIVILEGE_ESCALATION)`, `category IN (PRIVILEGE_ESCALATION)` |

Scope: `events | alerts | incidents | all`. Results are paginated lists of real
records. Saving a hunt writes an audit record (`THREAT_HUNT.SAVED`) so history
is immutable and attributable.

**Safety:** only IPs (validated octets), a fixed event-type/severity vocabulary,
and bounded time windows are recognized. Anything else falls back to a broad
recent-events scan. No SQL fragments are ever built from user text.

---

## 2. Incident War Room

**UI:** `/incidents/:id/war-room` (linked from the Incidents table and the
incident detail tabs)

Aggregates one incident into a single analyst view:

- **Header** — ID, severity, status, provenance (DATASET vs SIMULATED), risk, confidence
- **Attack DNA** — fingerprint, family, confidence, behaviors, historical similarity
- **Predicted Next Stage** — current → predicted, probability, confidence, recommended control (PREDICTION badge)
- **Blast Radius** — assets/users/databases reachable from the attack graph (ESTIMATE label)
- **AI Investigation** — verdict, confidence, summary
- **Attack Timeline** — correlated event sequence
- **MITRE ATT&CK** — mapped techniques (links to attack.mitre.org)
- **Recommended Response** — recommendations + approval status
- **Explainable Risk** — weighted factors
- **Evidence Ledger** — chain-of-custody records for this incident

---

## 3. Blast Radius

**API:** `GET /api/soc/blast-radius/{incident_id}`

Runs the attack-graph builder, then walks graph reachability from every
compromised/attacker node and counts distinct **assets, users, databases and
critical services** in the exposure cone. Output is explicitly labeled
`estimate: true` — observed correlation, not confirmed spread.

---

## 4. Campaigns (alert-fatigue dedup)

**API:** `GET /api/soc/campaigns`
**UI:** sidebar → **Security → Campaigns**

Groups incidents by (source IP, attack category) into campaigns and reports the
dedup funnel:

```text
257,795 events → 20 alerts → 20 incidents → 15 campaigns  (dedup ratio ~12,889:1)
```

Each campaign shows incident count, correlated event count, MITRE techniques,
severity, duration window and risk — the direct answer to analyst alert fatigue.

---

## 5. Asset Risk Intelligence

**API:** `GET /api/soc/asset-risk`
**UI:** sidebar → **Infrastructure → Asset Risk Intelligence**

Per-asset digital-twin risk: `criticality (25%) + incident exposure (40%) +
anomalous events (15%) + active alerts (20%)`, capped at 100. Configurable
weights; the formula is returned with the response so the score is explainable.

---

## 6. Global Search 2.0

**API:** `GET /api/soc/search?q=...`
**UI:** top-bar search + sidebar → **Investigation → Global Search**

One box across **incidents, alerts, events, Attack DNA fingerprints, MITRE
techniques and evidence records** — matching by ID, title, category, IP, user,
hash, technique, tactic. Results link back to the relevant page.

---

## Verification

```bash
# threat hunt (NL → filters)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  http://localhost:8000/api/soc/threat-hunting \
  -d '{"query":"find login failures from 45.155.205.233 in the last 24 hours"}'

# blast radius
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/soc/blast-radius/INCIDENT_UUID

# campaigns + funnel
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/soc/campaigns

# asset risk
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/soc/asset-risk

# global search
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/api/soc/search?q=T1078"
```

Backend tests: `pytest tests/test_soc_tools.py` (5 tests, part of the 57-test suite).
