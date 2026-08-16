import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Chrome, Github, KeyRound, Lock, Loader2, ShieldAlert, UserCheck, Users } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { Card, StatusBadge } from "../components/ui";
import { getErrorMessage, listUsers } from "../services/api";
import type { User } from "../types";

type SignInKind = "password" | "google" | "github" | "sso-only";

function signInMethod(u: User): { label: string; kind: SignInKind } {
  if (u.oauth_provider === "google") return { label: "Google SSO", kind: "google" };
  if (u.oauth_provider === "github") return { label: "GitHub SSO", kind: "github" };
  if (u.has_password) return { label: "Password", kind: "password" };
  return { label: "SSO-only · no password", kind: "sso-only" };
}

function MethodBadge({ u }: { u: User }) {
  const m = signInMethod(u);
  const styles: Record<SignInKind, string> = {
    password: "border-emerald-500/40 text-emerald-400",
    google: "border-sky-500/40 text-sky-400",
    github: "border-slate-400/40 text-slate-300",
    "sso-only": "border-cyber-yellow/40 text-cyber-yellow",
  };
  const Icon = m.kind === "google" ? Chrome : m.kind === "github" ? Github : m.kind === "password" ? KeyRound : Lock;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${styles[m.kind]}`}>
      <Icon className="h-3 w-3" />
      {m.label}
    </span>
  );
}

export default function AdminUsers() {
  const { user } = useAuth();
  const [users, setUsers] = useState<User[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const isAdmin = user?.roles.includes("ADMIN") ?? false;

  const load = useCallback(() => {
    setLoadErr(null);
    listUsers().then(setUsers).catch((err) => setLoadErr(getErrorMessage(err)));
  }, []);

  useEffect(() => {
    if (isAdmin) load();
  }, [isAdmin, load]);

  if (!isAdmin) {
    return (
      <div className="mx-auto max-w-xl pt-10">
        <Card title="Admin access required" subtitle="Account management is restricted to administrators">
          <div className="flex items-center gap-3 rounded-lg bg-cyber-red/10 px-4 py-3 text-sm text-cyber-red">
            <ShieldAlert className="h-5 w-5" />
            Your role ({user?.roles.join(", ") ?? "none"}) does not permit viewing the user directory.
          </div>
          <Link to="/dashboard" className="mt-4 inline-block text-sm font-semibold text-electric-400 hover:underline">
            ← Back to dashboard
          </Link>
        </Card>
      </div>
    );
  }

  const ssoLinked = users?.filter((u) => u.oauth_provider).length ?? 0;
  const ssoOnly = users?.filter((u) => !u.oauth_provider && !u.has_password).length ?? 0;
  const active = users?.filter((u) => u.is_active).length ?? 0;

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <Card
        title="User directory"
        subtitle="Accounts, roles and sign-in methods across the platform"
      >
        <div className="mb-4 grid gap-3 sm:grid-cols-4">
          {[
            { label: "Total accounts", value: users?.length ?? "…", icon: <Users className="h-4 w-4" /> },
            { label: "Active", value: users ? `${active}` : "…", icon: <UserCheck className="h-4 w-4" /> },
            { label: "SSO linked", value: users ? `${ssoLinked}` : "…", icon: <Chrome className="h-4 w-4" /> },
            { label: "SSO-only (no password)", value: users ? `${ssoOnly}` : "…", icon: <Lock className="h-4 w-4" /> },
          ].map((s) => (
            <div key={s.label} className="rounded-lg bg-night-850/60 px-4 py-3">
              <p className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-600">
                <span className="text-electric-400">{s.icon}</span>
                {s.label}
              </p>
              <p className="mt-1 text-xl font-bold text-slate-100">{s.value}</p>
            </div>
          ))}
        </div>

        {loadErr && (
          <div className="mb-4 rounded-lg bg-cyber-red/10 px-4 py-3 text-sm text-cyber-red">
            Failed to load users: {loadErr}
            <button onClick={load} className="ml-3 font-semibold underline">Retry</button>
          </div>
        )}

        {!users && !loadErr && (
          <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading users…
          </div>
        )}

        {users && users.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-night-700 text-[10px] uppercase tracking-wider text-slate-600">
                  <th className="py-2.5 pr-4 font-semibold">User</th>
                  <th className="py-2.5 pr-4 font-semibold">Roles</th>
                  <th className="py-2.5 pr-4 font-semibold">Sign-in method</th>
                  <th className="py-2.5 pr-4 font-semibold">Status</th>
                  <th className="py-2.5 pr-4 font-semibold">Joined</th>
                  <th className="py-2.5 font-semibold">Last login</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-night-800/60 hover:bg-night-800/40">
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-3">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-electric-500 to-cyber-purple text-xs font-bold text-white">
                          {u.full_name.slice(0, 1).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <p className="truncate font-semibold text-slate-200">{u.full_name}</p>
                          <p className="truncate text-xs text-slate-500">{u.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex flex-wrap gap-1">
                        {u.roles.map((r) => <StatusBadge key={r} status={r} />)}
                      </div>
                    </td>
                    <td className="py-3 pr-4"><MethodBadge u={u} /></td>
                    <td className="py-3 pr-4">
                      <span className={`text-xs font-medium ${u.is_active ? "text-emerald-400" : "text-cyber-red"}`}>
                        {u.is_active ? "Active" : "Disabled"}
                        {u.is_verified ? "" : " · Unverified"}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-xs text-slate-500">
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : "—"}
                    </td>
                    <td className="py-3 text-xs text-slate-500">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
