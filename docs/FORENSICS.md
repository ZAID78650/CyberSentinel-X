# CyberSentinel-X — Forensic Layer

The forensic layer turns every significant incident into an explainable,
evidence-backed, tamper-evident artifact:

```
INCIDENT
   │
   ├─ Attack DNA        behavioral fingerprint + historical similarity search
   ├─ Attack Prediction next-stage forecast (always labeled as a prediction)
   └─ Evidence Ledger   SHA-256 hash chain + proof-of-work blocks (chain of custody)
```

Everything is generated automatically by the orchestrator pipeline
(`backend/app/agents/orchestrator.py` → `_stage_forensics`) the moment an
incident is created, and can also be computed on demand per incident.

---

## 1. Attack DNA

**Service:** `backend/app/services/attack_dna.py`
**Model:** `AttackDna` (`backend/app/models/forensics.py`)
**API:** `/api/attack-dna`

For each incident a fixed-length behavioral feature vector is derived from its
correlated events:

- event-type distribution (14 canonical types)
- severity mix
- source/destination/asset/protocol cardinality (log-scaled)
- flow statistics (bytes, packets, rate)
- mean ML anomaly score
- risk score, MITRE technique count

The vector is normalized and:

1. **Fingerprinted** — `SHA-256(features + behaviors + techniques)` → stable 64-hex identity.
2. **Compared** — cosine similarity against every historical fingerprint
   (`historical_similarity`, `similar_to`).
3. **Labelled** — attack family (from incident category + observed behaviors)
   and confidence (blends anomaly signal, risk, and volume).

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/attack-dna` | List fingerprints (limit, default 100) |
| GET | `/api/attack-dna/{incident_id}` | Get or generate the DNA for an incident + top-5 similar attacks |
| GET | `/api/attack-dna/similar?incident_id=…&top_k=…` | Similarity search across all fingerprints |

---

## 2. Predictive Attack Path

**Service:** `backend/app/services/prediction.py`
**Model:** `AttackPrediction`
**API:** `/api/predictions`

A transparent, domain-prior transition model over the MITRE-aligned kill chain
(`STAGE_ORDER`): observed event types place the incident at the furthest stage
reached; a fixed transition table yields the most likely next stage, its
probability, a recommended prevention control, and a human-readable rationale.

**Predictions are always flagged** (`is_prediction=True`, "PREDICTION" badge in
the UI, rationale text stating *"This is a prediction, not a confirmed event"*).

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/predictions` | List predictions (limit) |
| GET | `/api/predictions/{incident_id}` | Get (or generate) the prediction for an incident |
| GET | `/api/predictions/{incident_id}?full=true` | Full predicted kill-chain path |

---

## 3. Evidence Ledger (chain of custody)

**Service:** `backend/app/services/evidence.py`
**Models:** `EvidenceRecord`, `LedgerBlock`
**API:** `/api/evidence`

Privacy-aware, permissioned-ledger abstraction. **Raw logs are never stored on
any chain** — only hashes, IDs and provenance metadata. The design mirrors a
permissioned ledger so it can migrate to Hyperledger Fabric later without
changing call sites.

### Integrity model

```
content_hash  = SHA-256( canonical(title, description, meta) )
record_hash   = SHA-256( chain_index | prev_hash | content_hash | canonical_dt(created_at) )
block_hash    = SHA-256( block_index | prev_block_hash | records_digest | nonce )
                with proof-of-work: leading POW_DIFFICULTY (4) zero hex chars
```

- `prev_hash` links each record to the previous one — the chain of custody.
- `prev_block_hash` links blocks; block 0 anchors to the 64-char genesis hash.
- Verification recomputes **every** hash from stored fields. Any modification
  after hashing (content or chain link) flips the record to `TAMPERED` and the
  full-chain audit reports `integrity: TAMPERED`.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/evidence` | List evidence records (filter by incident_id, status) |
| POST | `/api/evidence` | Create an evidence record (ADMIN / SECURITY_ANALYST) |
| GET | `/api/evidence/ledger` | List mined blocks |
| POST | `/api/evidence/ledger/mine` | Mine a block anchoring all uncommitted records |
| POST | `/api/evidence/ledger/verify` | Full-chain integrity audit |
| POST | `/api/evidence/{evidence_id}/verify` | Recompute hashes for one record |
| POST | `/api/evidence/{evidence_id}/tamper-test` | **SIMULATION** — mutate payload without updating hashes to demonstrate detection |
| POST | `/api/evidence/{evidence_id}/restore` | Restore the original payload after a tamper test |

### Verification procedure (manual)

```bash
# 1. Full-chain audit
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/evidence/ledger/verify

# 2. Integrity demo: tamper → detect → restore
EVID=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/evidence \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['items'][0]['evidence_id'])")
curl -X POST -H "Authorization: Bearer $TOKEN" "http://localhost:8000/api/evidence/$EVID/tamper-test"
# → tamper_detected: true, status: TAMPERED, content_hash_ok: false
curl -X POST -H "Authorization: Bearer $TOKEN" "http://localhost:8000/api/evidence/$EVID/restore"
# → valid: true, status: VALID
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/evidence/ledger/verify
# → integrity: VALID
```

### Key design decisions

- **Canonical timestamp** (`_canonical_dt`): SQLite stores datetimes without
  tzinfo; hashing a timezone-aware creation timestamp vs. the naive read-back
  would break verification. All record hashes use a normalized UTC-naive
  microseconds ISO string.
- **Chain-index anchoring for mining**: "uncommitted" records are found by the
  max chain index committed by the previous block — never by wall-clock time,
  which can re-commit records from the same second.
- **Hash input consistency**: the content hash covers exactly what verification
  recomputes (title + description + stored meta). The caller's `payload` is
  merged into `meta` so the API round-trips deterministically.

---

## 4. Data provenance

Every evidence record and every DNA/prediction artifact carries a
`data_source` tag rendered as a provenance badge in the UI:

| Tag | Meaning |
|---|---|
| `LIVE` | real-time telemetry |
| `DATASET` | UNSW-NB15 benchmark corpus |
| `SIMULATED` | synthetic demo scenario |
| `MODEL` | AI/ML prediction (never presented as a confirmed event) |
| `LOCAL` | local reference data / analyst-created |
| `UNKNOWN` | unclassified |

Benchmark data, live telemetry and model predictions are never silently mixed
in the UI — the badge is always visible next to the value.
