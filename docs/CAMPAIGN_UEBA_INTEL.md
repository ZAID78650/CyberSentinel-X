# Campaign Intelligence, UEBA & Ledger Merkle Roots

This cycle extends CyberSentinel-X with real analytics engines computed from the
stored event corpus. Every value is explainable and derived from actual data —
no random or hardcoded numbers. Where data is insufficient the API says so
(`INSUFFICIENT_DATA` / `EMPTY`) instead of inventing results.

## Endpoints (all authenticated)

### Campaign intelligence — `/api/campaigns/{campaign_id}/...`
`campaign_id` accepts either the computed campaign id (`CGN-####`) or an
incident id (`INC-...`).

| Endpoint | Output | Algorithm |
|---|---|---|
| `/velocity` | stage sequence, transition times, stages/hour, acceleration, band, escalation flag | kill-chain stage mapping + temporal rate/acceleration |
| `/momentum` | 0-100 score, status (ESCALATING/STABLE/CONTAINED), per-signal breakdown | weighted event-rate, new assets, new techniques, severity, anomaly, exfiltration signals |
| `/similar?limit=` | ranked list with per-component scores + top reasons | Jaccard (techniques, sources) + cosine (event types, severities, protocols) |
| `/mitre-coverage` | overall + per-tactic coverage, detection gaps | observed vs expected techniques per stage tactic |
| `/mutation` | campaigns with behavioral ≥ 65% but IOC overlap < 40% | behavioral fingerprint vs IOC fingerprint |
| `/business-impact` | critical assets, sensitive data stores, users, impact | qualitative aggregation of event/asset data |
| `/intel` | combined velocity + momentum + coverage payload | — |

### UEBA — `/api/ueba`
| Endpoint | Output |
|---|---|
| `/profiles?entity_type=user\|ip\|device` | per-entity baselines vs current behavior with explainable risk factors |
| `/entity-risk?entity_type=` | per-entity risk + enterprise aggregate (weighted UEBA/intel/anomaly/criticality) |
| `/attack-surface` | 0-100 score + band + highest-risk asset |

### Analytics — `/api/analytics`
| Endpoint | Output |
|---|---|
| `/data-quality` | 0-100 quality + pipeline health (missing rates, duplicates, imbalance, staleness, ingestion health) |
| `/model-drift` | PSI + KL divergence between reference and recent anomaly-score windows, drift level + recommendation |

### Evidence ledger (Merkle upgrade)
- `POST /api/evidence/ledger/mine` now returns `merkle_root`; block payloads in
  `GET /api/evidence/ledger` include it.
- `POST /api/evidence/ledger/verify` recomputes each block's Merkle root from
  its records and reports `merkle_roots_valid` alongside the chain audit.

## Algorithms

- **Velocity** — events are mapped to kill-chain stages (shared
  `STAGE_EVENT_MAP`), first appearance per stage is recorded, and
  stages/hour = transitions ÷ duration. Acceleration compares stage counts
  before/after the campaign midpoint; a late-stage burst on a fast campaign
  sets `campaign_escalation_detected`.
- **Momentum** — the first/second half of the campaign are compared on five
  weighted signals (0.35 rate change, 0.20 new assets, 0.20 anomaly ratio,
  0.15 severity change, 0.10 exfiltration). Rate change is squashed with a
  sigmoid so extreme spikes don't saturate the score.
- **Similarity** — fixed feature vector per campaign (technique set, event-type
  distribution, severity distribution, protocol mix, source-IP set); Jaccard
  for sets, cosine for distributions, weighted 0.30/0.25/0.15/0.15/0.15.
- **UEBA** — an entity's history is split 60/40 into baseline vs current.
  Factors trigger on deviation: off-hours ratio, failed-login ratio, unseen
  devices, >3× data volume, anomaly ratio > 0.5. Risk sums factor points (max
  100); scores under 4 events report `INSUFFICIENT_DATA`.
- **Merkle roots** — binary tree over record hashes (odd layers duplicate the
  last leaf), paired with the existing SHA-256 record/block chain. Verification
  recomputes each block's root from its records in chain order.

## SIH demo flow

1. Run `POST /api/simulations/brute-force` (or the SIH demo scenario).
2. `GET /api/soc/campaigns` — campaigns appear once incidents share a source + category.
3. `GET /api/campaigns/CGN-0001/velocity` — stages, transition minutes, band.
4. `GET /api/campaigns/CGN-0001/momentum` — momentum + ESCALATING/STABLE.
5. `GET /api/campaigns/CGN-0001/mitre-coverage` — per-tactic coverage + gaps.
6. `GET /api/campaigns/CGN-0001/similar` — ranked similar campaigns with reasons.
7. `GET /api/campaigns/CGN-0001/mutation` — possible mutations.
8. `GET /api/campaigns/CGN-0001/business-impact` — qualitative impact.
9. `GET /api/ueba/profiles?entity_type=user` — behavioral deviations.
10. `GET /api/ueba/entity-risk` — entity + enterprise risk.
11. `GET /api/ueba/attack-surface` — exposure score.
12. `GET /api/analytics/data-quality` and `/api/analytics/model-drift`.
13. `POST /api/evidence/ledger/mine` → `merkle_root`; `POST /api/evidence/ledger/verify`
    → `merkle_roots_valid`.

## Integration round: feedback, SBOM, intel fusion, Judge Mode

### Analyst feedback loop (Feature 16)
- `POST /api/alerts/{alert_id}/feedback` — body `{"label": "TRUE_POSITIVE|FALSE_POSITIVE|BENIGN|UNKNOWN", "note": "..."}`.
  Latest label wins per (alert, analyst); every label writes an `action_logs` audit row.
- `GET /api/analytics/feedback-stats` — signals before correlation, alerts after
  correlation, label distribution, observed precision and false-positive rate.
  Labels tune nothing silently — they only inform the analyst and stats.

### SBOM / supply chain (Feature 31)
- `GET /api/sbom` — normalized SBOM from `frontend/package-lock.json` +
  `backend/requirements.txt`; CVE cross-reference against the **local** feed only.
  Supply-chain risk is explainable (factor weights listed per finding).

### Threat intel fusion (Feature 20)
- `GET /api/threat-intelligence/sources/status` — configured feeds + provenance.
  With only the local feed: `live_feed_configured=false` and message
  `NO LIVE THREAT INTELLIGENCE SOURCE CONFIGURED`.

### Data pipeline & Judge Mode (Features 34/36)
- `GET /api/data/pipeline` — INGEST→VALIDATE→NORMALIZE→FEATURE ENGINEERING→TRAIN→…→RETRAIN
  with real per-stage counts and strict split separation.
- `GET /api/analytics/judge-mode` — EVENTS→ALERTS→CAMPAIGNS→ATTACK DNA→PREDICTION→
  BLAST RADIUS→RESPONSE→BLOCKCHAIN PROOF with real counts + provenance (canonical
  vocabulary: LIVE/DATASET/SIMULATED/MODEL/LOCAL), MTTD/MTTR, evidence verified,
  merkle roots, agent health. No fabricated accuracy.

### Performance + ledger round
- **TTL caching** — `app/services/cache.py`; `/api/soc/campaigns` and
  `/api/analytics/judge-mode` are cached (20s/30s) so heavy N+1 reads stay fast
  at 175k+ events. Cache is bypassed in tests.
- **Merkle backfill** — `POST /api/evidence/ledger/backfill-merkle` (admin)
  recomputes missing Merkle roots for blocks mined before the tree existed.
- **Feedback categories** — `GET /api/analytics/feedback-stats` now returns
  per-category precision/FPR with plain-language suggestions (e.g. raise a
  noisy category's threshold). Suggestions are advisory — never applied silently.
- **SBOM curated CVE reference** — version-aware advisory dataset for the
  platform's own stack (vite, axios, python-multipart, pydantic, starlette,
  log4j) with `affected|patched|check` status computed from pinned versions.
  Real finding on the shipped lockfile: vite 5.x → CVE-2025-30208.
- **Campaign command center** — `/campaigns/:id` page: Overview (DNA, business
  impact, momentum signals, timeline, mutation watch), Similarity, Prediction,
  Blast Radius, Response, Evidence & Blockchain.

### Round 2 — command center, per-campaign evidence, retrain-with-consent
- `GET /api/campaigns/command-center` — summary cards (active/critical/escalating/
  predicted/contained) + full table rows with momentum/velocity/status/confidence/
  assets/prediction in one TTL-cached call. `/api/campaigns/{id}/intel` now also
  returns `status`, `confidence`, `asset_count` and `prediction` extras.
- `POST /api/evidence/campaign/{campaign_id}/commit` — anchors a campaign's
  evidence into its own Merkle-rooted block (`campaign_id` + `campaign_commit` in
  block meta). The command center's Evidence tab shows the per-campaign root.
- `POST /api/analytics/feedback/retrain` (admin) — retrain correlation **with
  consent**: FP-heavy categories (FPR > 0.5, ≥2 labels) get `+0.15` on the
  Detection Agent's anomaly floor; clean categories (precision ≥ 0.8) get `-0.05`.
  Every change is audited (`CORRELATION.RETRAINED`), surfaced in
  `feedback-stats.applied_settings`, and reversible. Nothing is applied silently.
- **WebSocket**: `analyst_feedback` events broadcast on label submission; the
  Alerts page refreshes stats live and the Campaigns command center refreshes on
  `new_alert` / `new_incident` / `incident_updated` — no polling.

A timed 5-minute judge script is in [SIH_DEMO.md](SIH_DEMO.md).

## Testing

`backend/tests/test_campaign_intel.py`, `test_ueba.py`, `test_data_quality.py`,
`test_evidence_merkle.py` cover every engine, including empty/insufficient-data
paths and Merkle cases (empty, single, even, odd). The integration round adds
`test_feedback.py`, `test_sbom.py` and `test_judge.py` (feedback API + stats,
real-manifest SBOM scan, judge-mode / pipeline aggregates, intel source status).
