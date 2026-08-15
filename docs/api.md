# API Reference

Base URL: `http://localhost:8000` (dev) · interactive docs at `/docs` (Swagger UI).

All routes except `/health`, `/ready` and `/api/auth/*` require `Authorization: Bearer <access_token>`.

## Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Create account (full_name, email, organization, password, confirm_password, accept_terms) |
| POST | `/api/auth/login` | Login (email, password, remember_me) → access + refresh tokens |
| POST | `/api/auth/refresh` | Exchange refresh token for a new access token |
| POST | `/api/auth/logout` | Audit logout (client discards tokens) |
| GET | `/api/auth/me` | Current user profile + roles |
| POST | `/api/auth/forgot-password` | Generic reset-request response (never discloses account existence) |
| GET | `/api/auth/oauth/providers` | SSO provider status (google/github, configured or not) |
| GET | `/api/auth/oauth/{provider}/authorize` | OAuth authorize URL (graceful 200 when unconfigured) |
| GET | `/api/auth/oauth/{provider}/callback` | OAuth code exchange → JWT + redirect to SPA |

## Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness probe |
| GET | `/ready` | Readiness probe (checks DB connectivity) |

## Events

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/events` | Paginated event list (filters: event_type, severity, source_ip, user_id, anomalous_only, sort) |
| POST | `/api/events` | Ingest one normalized event |
| POST | `/api/events/batch` | Ingest a batch |
| GET | `/api/events/live` | Most recent events for the live feed |

## Alerts & Incidents

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/alerts` · `/api/alerts/{id}` | Alert list (severity/status/category filters) + detail |
| GET | `/api/incidents` · `/api/incidents/{id}` | Incident list + detail |
| POST | `/api/incidents` | Manually create an incident |
| POST | `/api/incidents/{id}/investigate` | Launch the AI investigation pipeline (async) |
| PATCH | `/api/incidents/{id}/status` | Update incident status (ADMIN/ANALYST) |

## Investigation & Analysis

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/investigations/{incident_id}` | Investigation detail: summary, verdict, confidence, evidence, MITRE mappings |
| GET | `/api/attack-graph/{incident_id}` | Reconstructed attack graph (nodes + edges) |
| GET | `/api/risk/{incident_id}` | Explainable risk score with factor breakdown |
| GET | `/api/threat-intelligence` | Indicator feed (paginated, filterable) |
| POST | `/api/threat-intelligence/search` | Free-text intel search |
| GET | `/api/threat-intelligence/mitre` | MITRE ATT&CK technique reference |

## Response & Approvals

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/response-recommendations/{incident_id}` | Recommended actions for an incident |
| GET | `/api/approvals` | Approval requests (filter by status) |
| POST | `/api/approvals/{id}/approve` | Approve → simulated execution (ADMIN/ANALYST) |
| POST | `/api/approvals/{id}/reject` | Reject |
| POST | `/api/response-recommendations/{id}/execute` | Execute an approved action (simulated) |
| GET | `/api/actions-log` | Audit trail (paginated, filterable) |

## Reports & Analytics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/reports` | Report list |
| POST | `/api/reports/{incident_id}/generate` | Generate HTML + PDF report |
| GET | `/api/reports/{id}` | Report detail + content |
| GET | `/api/reports/{id}/pdf` | Download PDF |
| GET | `/api/reports/{id}/html` | View HTML report |
| GET | `/api/analytics` | Aggregated analytics (includes detection accuracy metrics) |
| GET | `/api/security/firewall` | Defense-in-depth firewall layers + block counters |
| GET | `/api/security/firewall/layers` | Firewall layer details |
| GET | `/api/security/detection-accuracy` | Live-measured detection accuracy (precision/recall/F1, confusion matrix) |
| GET | `/api/security/assets` | Monitored asset inventory (paginated, type filter) |
| GET | `/api/security/playbooks` | Knowledge-base playbooks, policies, CVEs (paginated) |

## Simulations

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/simulations/account-takeover` | Synthetic account takeover attack |
| POST | `/api/simulations/brute-force` | Synthetic brute force |
| POST | `/api/simulations/malware` | Synthetic malware infection |
| POST | `/api/simulations/data-exfiltration` | Synthetic data exfiltration |
| POST | `/api/simulations/privilege-escalation` | Synthetic privilege escalation |
| GET | `/api/simulations` | List available scenarios |

Simulation endpoints require ADMIN or SECURITY_ANALYST. All simulated activity is synthetic.

## WebSocket

- Endpoint: `/ws?token=<access_token>` (or first message `{"type":"auth","token":"…"}`)
- Events broadcast to clients: `new_event`, `new_alert`, `new_incident`, `agent_status`,
  `incident_updated`, `pipeline_stage_failed`
- Clients may send `{"type":"ping"}` → server replies `{"event":"pong"}`

## Pagination & errors

List endpoints accept `page`, `page_size` (max 200) and return
`{items, total, page, page_size, pages}`. Errors use RFC-style
`{"detail": "…"}` with appropriate status codes; validation errors list field-level messages.
