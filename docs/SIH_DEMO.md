# SIH Judge Demonstration — 5-Minute Script

> CyberSentinel-X is an AI-powered predictive cyber defense platform that
> converts security telemetry into attack campaigns, generates behavioral
> Attack DNA, reconstructs attack paths, predicts attack progression,
> calculates blast radius, optimizes response decisions, and preserves
> tamper-evident forensic evidence through cryptographic and blockchain-based
> verification.

Every number shown below is real — computed from the platform's stores.
Nothing in this script is fabricated; where data is simulated it is labeled
`SIMULATION`, dataset-derived data is labeled `DATASET`, and model outputs are
labeled `MODEL PREDICTION`.

**Deployment:** https://cybersentinel-frontend.onrender.com
**Logins:** admin@cybersentinel.io / Admin@2026 (analyst@cybersentinel.io / Analyst@2026)

> ⚠ Before the demo: open the site ~2 minutes early to let the free-tier
> services cold-start (the app auto-retries, but a warm start is smoother).

---

## 0:00–0:30 · Login & Judge Mode

1. Log in as admin.
2. Open **Judge Mode** (sidebar → Overview → Judge Mode).
3. Point at the pipeline: **EVENTS → ALERTS → CAMPAIGNS → ATTACK DNA →
   PREDICTION → BLAST RADIUS → RESPONSE → BLOCKCHAIN PROOF**, each with a real
   count and a provenance badge.
4. Read the metrics row aloud — events processed, campaigns detected,
   MTTD/MTTR, evidence verified, Merkle roots.

> Talk track: *"This is the whole pipeline, live. Every stage is computed
> from the actual event store — nothing is random."*

## 0:30–1:15 · Real-time evidence (WebSocket)

5. Open **Live Events** in a second tab. The socket badge must read
   **CONNECTED** (green).
6. Back in the first tab run the brute-force scenario
   (`curl -X POST https://cybersentinel-frontend.onrender.com/api/simulations/brute-force` —
   or the SIH demo button in **Attack Simulator**).
7. Watch events stream into Live Events in real time.

> Talk track: *"One socket, full-duplex — telemetry lands in the browser the
> same second the Detection Agent scores it."*

## 1:15–2:30 · Campaign command center

8. Open **Campaigns**. The alert-fatigue funnel shows the correlation
   collapse (events → alerts → incidents → campaigns).
9. Click the campaign the scenario produced → **command center**:
   - **Overview**: Attack DNA fingerprint + family + confidence; business
     impact; momentum signals; attack timeline (stage transition minutes).
   - **Similarity**: ranked look-alike campaigns with reasons.
   - **Prediction**: Markov next-stage prediction — read the `MODEL
     PREDICTION` badge and the probability/confidence (never claimed as
     verified accuracy).

> Talk track: *"Same behavior, different campaign — the mutation watch flags
> look-alikes whose IOCs diverge, so we catch re-tooled versions of the same
> actor."*

## 2:30–3:30 · Blast radius & response (human-in-the-loop)

10. Open the **Blast Radius** tab — affected assets/users and the attack
    path, computed by graph reachability.
11. Open the **Response** tab — recommendations with impact ratings; none
    execute without approval (see **Human Approvals**).

> Talk track: *"The platform recommends; a human decides. Every action is
> audited in the Actions Log."*

## 3:30–4:15 · Blockchain evidence — the showstopper

12. Open **Evidence Ledger**.
13. Click **Verify chain** → INTEGRITY: VALID, Merkle roots valid.
14. Click **Tamper test** on one evidence record → it flips to **TAMPERED**
    with recomputed-vs-stored hash mismatch. Click **Restore** → VALID again.

> Talk track: *"Only hashes and provenance go on the ledger — never raw
> logs. SHA-256 → Merkle root → proof-of-work block. Tamper with one byte
> and the chain audit catches it."*

## 4:15–4:45 · Threat intel & feedback

15. **Threat Intelligence** → the feed-status card honestly states
    **NO LIVE THREAT INTELLIGENCE SOURCE CONFIGURED** (local feed only).
16. **Alerts** → mark an alert **FP** or **TP**; the feedback cards update
    precision / false-positive rate.

## 4:45–5:00 · Close

17. Answer questions with **Global Search** (find any IP, hash, campaign,
    evidence) and **SBOM & Supply Chain** (real finding: vite 5.x →
    CVE-2025-30208 from the curated reference, clearly labeled advisory).

---

## If asked "is any of this fake?"

- Everything derives from the UNSW-NB15 **DATASET** corpus (50k+ events) or
  the **SIMULATION** engine; both are labeled with provenance badges.
- **MODEL PREDICTION** badges mark ML outputs; the platform does not claim
  accuracy it has not measured (see Model Center for real evaluation metrics).
- The ledger is a **permissioned local ledger** abstraction — swappable for
  Hyperledger Fabric without changing call sites.
- Verification: `bash scripts/verify_render.sh` checks login, upload/ingest,
  WebSocket handshake (HTTP 101) and live event streaming against the
  deployment.
