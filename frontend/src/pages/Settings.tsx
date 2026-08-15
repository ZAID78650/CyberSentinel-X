import { KeyRound, ShieldCheck, User } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { Card, StatusBadge } from "../components/ui";

export default function Settings() {
  const { user } = useAuth();

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
