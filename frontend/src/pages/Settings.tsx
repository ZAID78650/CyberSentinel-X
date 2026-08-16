import { useEffect, useState } from "react";
import { Github, KeyRound, Loader2, ShieldCheck, Unlink, User } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import { Card, StatusBadge } from "../components/ui";
import { getErrorMessage, oauthLink, oauthProviders, oauthUnlink } from "../services/api";
import type { OAuthProviderStatus } from "../types";

export default function Settings() {
  const { user, refreshUser } = useAuth();
  const { success, error, info } = useToast();
  const [providers, setProviders] = useState<OAuthProviderStatus[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    oauthProviders().then(setProviders).catch(() => undefined);
  }, []);

  const handleLink = async (provider: string) => {
    setBusy(provider);
    try {
      const res = await oauthLink(provider);
      if (!res.configured) {
        info("SSO not configured", res.message ?? `${provider} is not set up on the server.`);
      } else if (res.authorize_url) {
        window.location.href = res.authorize_url;
      }
    } catch (err) {
      error("Link failed", getErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const handleUnlink = async (provider: string) => {
    setBusy(provider);
    try {
      const updated = await oauthUnlink(provider);
      await refreshUser();
      success("Unlinked", `${provider} is no longer connected to your account.`);
      void updated;
    } catch (err) {
      error("Unlink failed", getErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <Card title="Profile" subtitle="Your analyst account">
        <div className="flex items-center gap-4">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-electric-500 to-cyber-purple text-2xl font-bold text-white">
            {(user?.full_name ?? "A").slice(0, 1).toUpperCase()}
          </div>
          <div>
            <p className="text-lg font-bold text-slate-100">{user?.full_name}</p>
            <p className="text-sm text-slate-500">{user?.email}</p>
            <div className="mt-1 flex gap-2">
              {user?.roles.map((r) => <StatusBadge key={r} status={r} />)}
            </div>
          </div>
        </div>
        <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
          <div className="rounded-lg bg-night-850/60 px-4 py-3">
            <dt className="text-xs uppercase tracking-wider text-slate-600">Organization</dt>
            <dd className="mt-0.5 font-medium text-slate-200">{user?.organization ?? "—"}</dd>
          </div>
          <div className="rounded-lg bg-night-850/60 px-4 py-3">
            <dt className="text-xs uppercase tracking-wider text-slate-600">Last login</dt>
            <dd className="mt-0.5 font-medium text-slate-200">
              {user?.last_login_at ? new Date(user.last_login_at).toLocaleString() : "—"}
            </dd>
          </div>
        </dl>
      </Card>

      <Card title="Sign-in methods" subtitle="Password + social login (SSO)">
        <div className="space-y-2.5">
          <div className="flex items-center gap-3 rounded-lg bg-night-850/60 px-4 py-2.5">
            <span className="text-electric-400"><KeyRound className="h-4 w-4" /></span>
            <span className="flex-1 text-sm text-slate-300">Password</span>
            <span className="text-xs font-medium text-emerald-400">Active</span>
          </div>
          {providers.map((p) => {
            const linked = user?.oauth_provider === p.provider;
            return (
              <div key={p.provider} className="flex items-center gap-3 rounded-lg bg-night-850/60 px-4 py-2.5">
                <span className="text-electric-400"><Github className="h-4 w-4" /></span>
                <span className="flex-1 text-sm text-slate-300">Continue with {p.name}</span>
                {!p.configured ? (
                  <span className="text-xs font-medium text-slate-600">Not configured</span>
                ) : linked ? (
                  <button
                    onClick={() => handleUnlink(p.provider)}
                    disabled={busy === p.provider}
                    className="flex items-center gap-1.5 rounded-md border border-cyber-red/40 px-2.5 py-1 text-xs font-medium text-cyber-red transition hover:bg-cyber-red/10"
                  >
                    {busy === p.provider ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unlink className="h-3.5 w-3.5" />}
                    Unlink
                  </button>
                ) : (
                  <button
                    onClick={() => handleLink(p.provider)}
                    disabled={busy === p.provider}
                    className="flex items-center gap-1.5 rounded-md border border-electric-500/40 px-2.5 py-1 text-xs font-medium text-electric-400 transition hover:bg-electric-500/10"
                  >
                    {busy === p.provider ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                    Link
                  </button>
                )}
              </div>
            );
          })}
        </div>
        <p className="mt-3 text-xs text-slate-600">
          Linking lets you sign in with Google or GitHub while keeping your password login.
          An SSO-only account (no password) cannot unlink its last provider.
        </p>
      </Card>

      <Card title="Security" subtitle="Platform hardening status">
        <div className="space-y-2.5">
          {[
            { label: "Password hashing", value: "bcrypt (12 rounds)", icon: <KeyRound className="h-4 w-4" /> },
            { label: "Authentication", value: "JWT access + refresh tokens", icon: <ShieldCheck className="h-4 w-4" /> },
            { label: "Authorization", value: "RBAC (ADMIN / SECURITY_ANALYST / VIEWER)", icon: <User className="h-4 w-4" /> },
            { label: "Agent tooling", value: "Allowlisted tools only — no shell/code execution", icon: <ShieldCheck className="h-4 w-4" /> },
            { label: "Response actions", value: "Simulated only; high-impact requires human approval", icon: <ShieldCheck className="h-4 w-4" /> },
            { label: "Audit trail", value: "Full action log with actor, target, IP, timestamp", icon: <ShieldCheck className="h-4 w-4" /> },
          ].map((row) => (
            <div key={row.label} className="flex items-center gap-3 rounded-lg bg-night-850/60 px-4 py-2.5">
              <span className="text-electric-400">{row.icon}</span>
              <span className="flex-1 text-sm text-slate-300">{row.label}</span>
              <span className="text-xs font-medium text-slate-500">{row.value}</span>
            </div>
          ))}
        </div>
      </Card>

      <p className="text-center text-xs text-slate-600">
        CyberSentinel X v1.0.0 · Smart India Hackathon 2026 · All attack demonstrations use synthetic data.
      </p>
    </div>
  );
}
