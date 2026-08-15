# Security Architecture

## Authentication

- **Passwords**: bcrypt with per-user salts (12 rounds). Never stored in plaintext; never logged.
- **JWT**: short-lived access tokens (30 min) + long-lived refresh tokens (7 days, with `jti`).
  Separate secrets for access and refresh (`JWT_SECRET`, `JWT_REFRESH_SECRET`).
- **Refresh strategy**: access tokens are refreshed transparently by the frontend axios
  interceptor; on refresh failure the client logs out.
- **Storage**: tokens live in `localStorage` on the client; the frontend never embeds secrets.

## Authorization (RBAC)

| Role | Capabilities |
|------|--------------|
| ADMIN | Everything, including approvals and settings |
| SECURITY_ANALYST | Investigate incidents, run simulations, approve/reject response actions |
| VIEWER | Read-only access to dashboards, reports and analytics |

Enforced via `require_roles()` dependency on sensitive routes (simulations, approvals,
incident status changes).

## Request hardening

- **Input validation**: Pydantic schemas validate every body, query and path parameter
- **SQL injection**: SQLAlchemy parameterized queries throughout
- **XSS**: React escapes output; `Content-Security-Policy` header set
- **Clickjacking**: `X-Frame-Options: DENY`
- **MIME sniffing**: `X-Content-Type-Options: nosniff`
- **Referrer policy**: `strict-origin-when-cross-origin`
- **CORS**: explicit origin allowlist from `CORS_ORIGINS`
- **Rate limiting**: in-memory sliding window on authentication endpoints (per client IP)

## Audit logging

Every meaningful action is recorded to `action_logs`: actor, action, target type/id, detail,
client IP and request id. Authentication events (success/failure), alert/incident creation,
simulations, approvals and report generation are all audited. **Secrets are never written to
logs** — only action identifiers and safe metadata.

## Agent security (critical)

- Agents may only call **allowlisted tools** (`agents/tools.py`) — plain database queries.
- **No tool** executes shell commands, runs arbitrary Python, accesses arbitrary files,
  reaches external systems, or exfiltrates data.
- High-impact response actions (session revocation, endpoint isolation, IP blocking, credential
  resets) **require human approval** before the (simulated) execution step.
- Hidden chain-of-thought is never stored or exposed; only concise evidence-based summaries.

## Secrets management

- All secrets are environment variables (`.env`, never committed; see `.env.example`)
- The frontend build contains no secrets; the API base is a runtime config
- `.gitignore` excludes `.env*` files, DBs, generated data and build artifacts
- CI runs a secret-exposure scan as part of the quality gate (grep for keys/tokens patterns)

## Boundaries

This is a **defensive prototype**: all attacks are synthetic; all response actions are
simulated; the platform cannot attack real systems or perform destructive actions.
