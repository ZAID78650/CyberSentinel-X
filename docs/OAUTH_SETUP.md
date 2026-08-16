# Enabling Google & GitHub SSO (OAuth 2.0)

CyberSentinel X supports "Sign in with Google" and "Sign in with GitHub". The
flow is fully implemented (backend routes + frontend buttons); it shows
**"SSO not configured"** until you create OAuth apps with the two providers and
set four environment variables.

> You need a Google/GitHub account to create the apps. No code changes are
> required — this is a configuration-only step.

## Redirect URIs (register these with the providers)

> ⚠️ The callback must be on the **frontend origin**, not the backend's. The
> browser reaches `/api` through the frontend's nginx (or Vite dev) proxy, so
> the CSRF state cookie is stored on the **frontend host**. The provider must
> redirect the browser back to that same host, or the cookie is never sent and
> every login fails with *"OAuth state mismatch"*. The backend computes the
> redirect URI from `FRONTEND_URL` automatically.

| Provider | Redirect URI |
|---|---|
| Google | `https://cybersentinel-frontend.onrender.com/api/auth/oauth/google/callback` |
| GitHub | `https://cybersentinel-frontend.onrender.com/api/auth/oauth/github/callback` |

For **local development**, additionally register (Vite proxies `/api` from
5173 → 8000):

- `http://localhost:5173/api/auth/oauth/google/callback`
- `http://localhost:5173/api/auth/oauth/github/callback`

---

## 1. Google Cloud

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) →
   create/select a project.
2. **APIs & Services → OAuth consent screen** → choose *External* → fill in the
   app name (e.g. "CyberSentinel X"), your email → save. Add your email as a
   **test user** while the app is in *Testing* mode.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID** →
   *Web application*.
4. Authorized redirect URIs → add the Google row from the table above (and the
   localhost one if you develop locally). Create.
5. Copy the **Client ID** and **Client secret** from the dialog.

## 2. GitHub

1. GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Application name: "CyberSentinel X". Homepage URL:
   `https://cybersentinel-frontend.onrender.com`.
3. **Authorization callback URL** → the GitHub row from the table above (and
   the localhost one if you develop locally). Register application.
4. Copy the **Client ID** and generate the **Client secret**.

## 3. Set the environment variables

| Variable | From |
|---|---|
| `GOOGLE_CLIENT_ID` | Google step 5 |
| `GOOGLE_CLIENT_SECRET` | Google step 5 |
| `GITHUB_CLIENT_ID` | GitHub step 4 |
| `GITHUB_CLIENT_SECRET` | GitHub step 4 |

**Production (Render):** open the backend service →
**Environment** → add the four variables (Render keeps the secret values once
set; the blueprint's `sync: false` entries never overwrite them). The deploy
restarts automatically and the login page buttons flip to enabled.

**Local:** add the same four keys to `backend/.env` (see
`backend/.env.example`), with `FRONTEND_URL=http://localhost:5173` for local
testing (the redirect URI is built from `FRONTEND_URL`, not `BACKEND_URL`).

## 4. Verify

1. Open the login page — the Google/GitHub buttons should be enabled (the
   providers endpoint reports `configured: true`).
2. Click one — you're redirected to the provider, then back to
   `https://cybersentinel-frontend.onrender.com/oauth/callback#access=…&refresh=…`
   and logged in.
3. First-time SSO users are auto-provisioned as `SECURITY_ANALYST` with a
   verified account (no password needed).

## Account linking

- **New provider account** → provisioned automatically (`SECURITY_ANALYST`,
  verified, no password).
- **Existing account, same email** → the provider identity is **linked** to it
  (no duplicate is created) and the user's password login keeps working.
- **Identity takes precedence** — once linked, repeat SSO logins match by
  `provider + provider_id`, so a renamed provider email still lands on the
  same account.
- The account menu shows `via Google` / `via GitHub` on linked accounts.

A seeded SSO-only demo user `sso.demo@cybersentinel.io` (verified, no
password) exists in fresh databases — it can only sign in through a provider
that returns that email, demonstrating the linking path. Password login is
rejected for it by design.

## Notes

- If the app returns "OAuth state mismatch", just click the button again — the
  state cookie is valid for 10 minutes and is single-use per flow.
- GitHub users with private emails are supported (the backend fetches
  `/user/emails` and uses the primary verified address).
- Google accounts with unverified emails are rejected.
- Tokens are delivered in the URL **fragment**, never the query string, so they
  don't appear in server or referrer logs.
