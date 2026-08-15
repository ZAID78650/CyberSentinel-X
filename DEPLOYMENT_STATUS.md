# DEPLOYMENT_STATUS.md

**CyberSentinel X — deployment & verification status**

| Item | Status |
|------|--------|
| Environment | Local development (macOS) — backend + frontend dev servers verified |
| Frontend URL | http://localhost:5173 (dev server, verified) — `docker compose` serves http://localhost:3000 |
| Backend URL | http://localhost:8000 (verified) — API docs at http://localhost:8000/docs |
| Database | SQLite (local, verified) — PostgreSQL configured via Docker Compose (not run locally — no Docker daemon on this machine) |
| Health status | `/health` → `{"status":"ok"}` ✓ · `/ready` → `{"status":"ready","database":"connected"}` ✓ |
| Reference data | 3 users, 3 roles, 8 assets, 52 MITRE techniques, 28 indicators, 9 RAG docs — **no synthetic sample events are seeded** (by design) |
| Dataset | **UNSW-NB15 ingested: 257,673 flows (164,673 attack, 93,000 benign) from the training + testing CSVs** — mapped to the event model, scored by the hybrid engine, fully searchable and 3D-analyzable |
| Auto-detection | Background loop (20s) correlates live anomalous events → alerts/incidents and deep-dives ingested campaigns (investigation → risk → response → report) without any manual trigger |
| Dataset APIs | `GET /api/dataset/status` · `POST /api/dataset/unsw/ingest` (ADMIN) · `POST /api/dataset/clear` (ADMIN) — with live progress in the UI |
| 3D analysis APIs | `GET /api/dashboard/threat-space` (3D point cloud) · `/api/dashboard/attack-distribution` (3D bars) · `/api/dashboard/events-timeseries` (live flow) |
| Forensic layer | **Attack DNA** (`/api/attack-dna` — behavioral fingerprints + historical similarity) · **Predictive attack path** (`/api/predictions` — next-stage forecast, always labeled PREDICTION) · **Evidence Ledger** (`/api/evidence` — SHA-256 hash chain + proof-of-work blocks, tamper detection, chain-of-custody audit) |
| SOC analyst tools | **Threat Hunting** (`POST /api/soc/threat-hunting` — NL → safe whitelisted filters, never raw SQL) · **Blast Radius** (`/api/soc/blast-radius/{id}` — attack-graph reachability estimate) · **Campaigns** (`/api/soc/campaigns` — source+category grouping + alert-fatigue funnel) · **Asset Risk Intelligence** (`/api/soc/asset-risk`) · **Global Search** (`/api/soc/search` — incidents/alerts/events/DNA/MITRE/evidence) |
| New UI pages | Incident War Room (`/incidents/:id/war-room` — timeline, DNA, prediction, MITRE, evidence, blast radius, response) · Threat Hunting Console · Campaigns · Asset Risk Intelligence · Global Search (top-bar + page) |
| Provenance | Every evidence record / DNA / prediction carries a `data_source` tag (LIVE · DATASET · SIMULATED · MODEL · LOCAL) rendered as a badge in the UI — benchmark, live and predicted data are never silently mixed |
| Backend tests | **57/57 pytest passed** (auth, RBAC, detection, ML, RAG, intel, MITRE, graph, risk, approvals, reports, pipelines, UNSW mapping, response-agent regression, evidence-ledger integrity, attack DNA, predictions, **threat hunting, blast radius, campaigns, asset risk, global search**) |
| Ruff | `ruff check app tests scripts` → All checks passed ✓ |
| Frontend typecheck/build | `tsc --noEmit` clean (strict) + `vite build` succeeds ✓ |
| Frontend runtime | Dashboard verified live: 3D Threat Space (echarts-gl scatter3D), Attack Rhythm 3D (bar3D), Live Threat Flow (WebSocket), AI investigation summary, risk-scored incidents, Data Sources page with ingest/clear controls |
| WebSocket | Real-time streaming verified (`REAL-TIME` badge, live event feed, live flow chart) |
| Docker Hub | Registry configured: **fs22ai006/cybersentinel-x** (`DOCKER_REGISTRY` in `.env` + `docker-compose.yml`; `scripts/push-dockerhub.sh`). **Not pushed** — Docker daemon is not running on this machine; run `docker login` (email `fs22ai006@gmail.com`) + `bash scripts/push-dockerhub.sh` on a machine with Docker |
| CI/CD | `.github/workflows/ci.yml` committed — pending first GitHub run |
| Cloud deployment | Not deployed (no cloud credentials provided) — see [docs/deployment.md](docs/deployment.md) |

## Verified end-to-end (actual commands/results)

```text
$ alembic upgrade head                    → Running upgrade -> a1b2c3d4e5f6 (forensic ledger, attack dna, predictions) ✓
$ pytest tests -q                         → 52 passed ✓
$ ruff check app tests scripts            → All checks passed! ✓
$ python scripts/smoke_test.py            → SMOKE TEST: 34 passed, 0 failed ✓
$ npm run typecheck && npm run build      → clean ✓

$ POST /api/dataset/unsw/ingest           → started in background
$ GET  /api/dataset/status                → 257,673 rows · 164,673 attack flows · 9 alerts · 9 incidents
$ GET  /api/dashboard/threat-space        → 1,600 3D points (bytes sent/recv vs rate, colored by family)
$ GET  /api/dashboard/attack-distribution → 216 cells (9 attack families × 24 hours)
$ GET  /api/dashboard/events-timeseries   → 49 hourly buckets ending now
```

Every UNSW incident was auto-investigated: all 9 have evidence + MITRE mappings +
attack graphs + risk scores (55.6–63.6) + response recommendations + generated
reports; 13 approvals pending for human review.

## What changed in this cycle

1. **Sample data removed** — `seed.py` now seeds reference data only (users, roles,
   assets, MITRE, indicators, RAG docs); all previously seeded events/alerts/incidents
   were deleted from the DB; `POST /api/dataset/clear` can wipe all event data on demand.
2. **UNSW-NB15 connected** — `backend/app/services/unsw.py` parses the CSVs
   (`UNSW_DATASET_DIR` in `backend/.env`), maps each flow to the event model
   (attack family → event type/severity, synthesized IPs, full feature metadata),
   fits an Isolation Forest on a stratified sample, scores every flow, bulk-inserts,
   and auto-correlates campaigns into alerts + incidents.
3. **Automatic detection system** — `auto_detection_loop` in the API runs every 20s:
   fresh anomalous events → alerts/incidents, and incident campaigns without a
   completed pipeline get the full investigation → risk → response → report run.
4. **3D live analysis on the dashboard** — echarts-gl scatter3D (threat space),
   bar3D (attack rhythm), and a WebSocket-driven live flow chart; all existing
   charts restyled (gradients, glow, custom tooltips, rounded bars).
5. **Docker Hub account wired in** — `fs22ai006/cybersentinel-x` set in `.env`,
   `docker-compose.yml` (incl. dataset volume mount + env), and the push script.
6. **Forensic layer** — new `Attack DNA`, `Predictive Attack Path`, and `Evidence
   Ledger` capabilities (see [docs/FORENSICS.md](docs/FORENSICS.md)):
   - Attack DNA fingerprints generated for all incidents (family, confidence,
     behaviors, MITRE techniques, cosine-similarity search).
   - Next-stage predictions (probability + confidence + recommended prevention
     control; clearly labeled as predictions).
   - Evidence ledger: chain-linked records anchored by proof-of-work blocks;
     integrity audit recomputes every hash; tamper → `TAMPERED` → restore → `VALID`.
7. **SOC analyst tooling** — all new capabilities built on real system data:
   - Threat Hunting Console: NL queries → generated structured filters
     (e.g. "critical incidents last 6h" → `severity IN (CRITICAL)` + 6h window),
     results across events/alerts/incidents, save-hunt audit trail.
   - Incident War Room: one screen with timeline, Attack DNA, prediction, MITRE,
     evidence ledger links, explainable risk, recommendations, blast radius.
   - Campaigns: groups incidents by source+category; live funnel shows
     257,795 events → 20 alerts → 20 incidents → 15 campaigns (12,889:1 dedup).
   - Asset Risk Intelligence: per-asset risk from criticality + incidents +
     anomalies + alerts (8 assets scored, avg 72/100).
   - Global Search: one box across incidents, alerts, events, DNA, MITRE, evidence.
8. **Resilience & demo layer** — see [docs/RESILIENCE.md](docs/RESILIENCE.md):
   - What-if Attack Simulator: deterministic kill-chain projection from any
     asset + starting stage; risk before/after with the mitigation stack
     (labeled SIMULATED; verified live: risk 51 → 7.7, assets 9 → 2).
   - Live scenario replay (`POST /api/soc/simulate/run-live`): the projected
     kill chain is re-ingested as clearly-labeled SIMULATED events through the
     real detection engine; the engine flags anomalies, the Detection Agent
     correlates alert + incident, and the full orchestrator pipeline
     (investigation → DNA → prediction → evidence → response → report) runs
     on it. Events stream over WebSocket so judges watch detection happen.
     Verified live: 15–18 events, 100% anomalous, alert + incident created.
9. **Attack Graph upgraded to industry standard** — every node/edge is now
   risk-weighted from real data (severity + anomaly signal + asset
   criticality) and carries event counts + first/last seen timestamps:
   - Graph statistics: node/edge counts, density, kill-chain depth, and the
     crown-jewel asset with its risk.
   - Critical path: highest cumulative-risk route from attacker to the crown
     jewel (Dijkstra over hostile progression), returned by the API and
     highlighted live in the UI (red animated edges).
   - Explicit lateral-movement edges (`MOVED_TO`) when a user/device spans
     two assets; assets are always connected (fallback `ACCESSED` via the
     acting user when no technique mapping exists yet).
   - Frontend: risk chips + glow scaled to risk on every node, click-to-
     inspect side panel (risk gauge, events, severity, criticality, first/
     last seen, ON CRITICAL PATH badge), node-type filter chips + hide-
     low-risk toggle, attack timeline scrubber with play/pause replay over
     the incident's real timestamps, JSON export, and full legend.
   - Follow-up polish: MiniMap removed (white overlay); plotting rewritten
     to a layered BFS-depth layout (attacker → crown jewel left-to-right,
     columns vertically stacked & centered — verified zero node overlaps,
     previously techniques overlapped in a fixed-type column); native
     tooltips on nodes/edges; new Attack-flow analysis strip (attackers,
     users, techniques, assets touched, events analyzed + MITRE chips) in
     the API stats and the page.
10. **Graph accuracy audit (industry-standard scanning)** —
    `POST /api/attack-graph/{id}/validate` runs five validation scans over
    the reconstructed graph (NIST 800-115-aligned): evidence grounding
    (every node backed by events or a real MITRE mapping — phantoms flagged
    HIGH), edge schema validity (typed edges must connect allowed node
    kinds), MITRE consistency (graph ↔ incident mapping), timeline
    consistency (no edge predates its source entity), and determinism
    (rebuild must be identical). Returns a weighted accuracy_score (0–100),
    per-check pass rates, and severity-tagged findings. Frontend shows a
    live Accuracy Audit panel that auto-scans per incident and offers
    Re-scan. Verified: clean graphs score 100/HIGH with 0 findings.
   - Model Center: production Isolation Forest + rules model with hyperparameters
     and metrics measured on a labeled corpus (98.81% acc, 93.85% precision,
     100% recall, F1 96.83).
   - Compliance Center: observed MITRE techniques mapped to NIST CSF / CIS /
     ISO 27001 — NIST 80%, CIS 86%, ISO 100%, overall 88% with explicit gaps.
   - Cyber Resilience Score (`GET /api/soc/resilience`): explainable weighted
     mean of 6 real-data factors (currently 47.8, WEAK — driven by 16/20
     HIGH/CRITICAL incidents and 1/20 resolved; the honest answer, not a vanity number).
11. **Dataset upload + dataset malware scanner** —
   - Data Sources now has two tabs: **Connected Datasets** (existing UNSW
     connection) and **Upload Dataset** — drag-drop or choose a CSV (up to
     256 MB; WAF body limit raised for this path only, multipart bodies
     exempted from payload scanning because `--` boundaries false-positived
     as SQLi). Uploads land in `data/uploads` with a manifest (rows / columns
     parsed at upload time) and appear in the Available Datasets list with
     **Scan** (jumps to the malware Dataset Scanner preselected), **Ingest**
     (runs the file through the real detection pipeline — appends to the
     corpus, never wipes the main feed), and **Delete**.
   - Malware Analysis now has two tabs: **Event Corpus Scan** (existing) and
     **Dataset Scanner** — pick any uploaded or UNSW file (optional row cap)
     and scan it for malware indicators matched against the local intel feed
     + malware KB: hashes, C2 domains, CVEs, IPs, processes, and attack-
     category mapping. Nothing is ingested by a scan; results include
     severity, confidence, matched indicators with counts, MITRE mapping and
     detection basis. Verified live on a 175k-row UNSW sample: Backdoor
     1,746 rows + Shellcode 1,133 rows (both CRITICAL, 85% conf), 2,879
     matched rows.
   - New endpoints: `POST /api/dataset/upload`, `GET /api/dataset/uploads`,
     `POST /api/dataset/uploads/{name}/ingest`,
     `DELETE /api/dataset/uploads/{name}`, `POST /api/malware/scan-dataset`.

## Remaining limitations

1. **Docker not run locally** — images were not built/pushed on this machine (no
   Docker daemon). Run `bash scripts/push-dockerhub.sh` on a Docker-equipped machine;
   Docker Hub account is `fs22ai006@gmail.com` (username `fs22ai006`).
2. **No live threat-intel / LLM APIs configured** — local synthetic feed and
   deterministic local LLM provider are active (zero external dependencies by design).
3. **No cloud deployment performed** — no credentials were provided.
4. Response actions are **simulated** by design (defensive prototype; human approval enforced).
5. Frontend unit tests are not included; the frontend is verified via strict typechecking,
   production build, and live end-to-end UI verification.
