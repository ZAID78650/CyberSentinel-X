import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Archive, Check, Chrome, Github, KeyRound, Loader2, Lock, Pencil, Power,
  RotateCcw, ShieldAlert, ShieldCheck, ShieldOff, UserCheck, Users, X,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import { Card, StatusBadge } from "../components/ui";
import {
  adminResetPassword, deprovisionUser, getErrorMessage, listUsers, restoreUser,
  setUserSsoBlock, setUserStatus, updateUserRoles,
} from "../services/api";
import type { User } from "../types";

type SignInKind = "password" | "google" | "github" | "sso-only";

const ROLE_OPTIONS = ["ADMIN", "SECURITY_ANALYST", "VIEWER"];

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
  const { user, refreshUser } = useAuth();
  const { success, error } = useToast();
  const [users, setUsers] = useState<User[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editRoles, setEditRoles] = useState<string[]>([]);
  const [editPwd, setEditPwd] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [savingRoles, setSavingRoles] = useState(false);

  const isAdmin = user?.roles.includes("ADMIN") ?? false;
  const meId = user?.id;

  const load = useCallback(() => {
    setLoadErr(null);
    listUsers().then(setUsers).catch((err) => setLoadErr(getErrorMessage(err)));
  }, []);

  useEffect(() => {
    if (isAdmin) load();
  }, [isAdmin, load]);

  const apply = useCallback(async (p: Promise<User>, okMsg: string) => {
    try {
      const updated = await p;
      await load();
      if (updated.id === meId) await refreshUser();
      success("Updated", okMsg);
    } catch (err) {
      error("Action failed", getErrorMessage(err));
    }
  }, [load, refreshUser, meId, success, error]);

  const handleToggleActive = async (u: User) => {
    const target = u.is_active ? "Disable" : "Enable";
    if (!window.confirm(`${target} ${u.email}? ${u.is_active ? "They will no longer be able to sign in." : "They will regain access immediately."}`)) return;
    setBusyId(u.id);
    await apply(setUserStatus(u.id, !u.is_active), `${u.email} ${u.is_active ? "disabled" : "enabled"}.`);
    setBusyId(null);
  };

  const handleResetPassword = async (u: User) => {
    if (editPwd.length < 8) {
      error("Weak password", "Use at least 8 characters with letters and numbers.");
      return;
    }
    setBusyId(u.id);
    await apply(adminResetPassword(u.id, editPwd), `Password reset for ${u.email}.`);
    setBusyId(null);
    setEditPwd("");
    setEditingId(null);
  };

  const handleSaveRoles = async (u: User) => {
    if (editRoles.length === 0) {
      error("No roles", "Pick at least one role.");
      return;
    }
    setSavingRoles(true);
    await apply(updateUserRoles(u.id, editRoles), `Roles updated for ${u.email}.`);
    setSavingRoles(false);
    setEditingId(null);
  };

  const handleDeprovision = async (u: User) => {
    if (!window.confirm(
      `Deprovision ${u.email}? This archives the account, blocks SSO and revokes ALL of their sessions.`)) return;
    setBusyId(u.id);
    await apply(deprovisionUser(u.id), `${u.email} deprovisioned — all sessions revoked.`);
    setBusyId(null);
    setEditingId(null);
  };

  const handleRestore = async (u: User) => {
    setBusyId(u.id);
    await apply(restoreUser(u.id), `${u.email} restored.`);
    setBusyId(null);
    setEditingId(null);
  };

  const handleBlockSso = async (u: User, blocked: boolean) => {
    setBusyId(u.id);
    await apply(setUserSsoBlock(u.id, blocked), `${u.email} SSO ${blocked ? "blocked" : "enabled"}.`);
    setBusyId(null);
  };

  const toggleRole = (role: string) =>
    setEditRoles((rs) => (rs.includes(role) ? rs.filter((r) => r !== role) : [...rs, role]));

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
        subtitle="Accounts, roles, sign-in methods and account management"
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
                  <th className="py-2.5 pr-4 font-semibold">Last login</th>
                  <th className="py-2.5 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <Row
                    key={u.id}
                    u={u}
                    meId={meId}
                    editing={editingId === u.id}
                    editRoles={editRoles}
                    editPwd={editPwd}
                    busyId={busyId}
                    savingRoles={savingRoles}
                    onToggleActive={() => handleToggleActive(u)}
                    onStartEdit={() => { setEditingId(u.id); setEditRoles(u.roles); setEditPwd(""); }}
                    onCancelEdit={() => setEditingId(null)}
                    onToggleRole={toggleRole}
                    onPwdChange={setEditPwd}
                    onResetPassword={() => handleResetPassword(u)}
                    onSaveRoles={() => handleSaveRoles(u)}
                    onDeprovision={() => handleDeprovision(u)}
                    onRestore={() => handleRestore(u)}
                    onBlockSso={(blocked: boolean) => handleBlockSso(u, blocked)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

interface RowProps {
  u: User;
  meId?: string;
  editing: boolean;
  editRoles: string[];
  editPwd: string;
  busyId: string | null;
  savingRoles: boolean;
  onToggleActive: () => void;
  onStartEdit: () => void;
  onCancelEdit: () => void;
  onToggleRole: (role: string) => void;
  onPwdChange: (v: string) => void;
  onResetPassword: () => void;
  onSaveRoles: () => void;
  onDeprovision: () => void;
  onRestore: () => void;
  onBlockSso: (blocked: boolean) => void;
}

function Row(props: RowProps) {
  const { u, meId, editing, editRoles, editPwd, busyId, savingRoles } = props;
  const busy = busyId === u.id;
  const isSelf = u.id === meId;

  return (
    <>
      <tr className="border-b border-night-800/60 hover:bg-night-800/40">
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
            {u.is_active ? "Active" : "Deprovisioned"}
            {u.is_verified ? "" : " · Unverified"}
            {u.sso_blocked ? " · SSO blocked" : ""}
          </span>
        </td>
        <td className="py-3 pr-4 text-xs text-slate-500">
          {u.created_at ? new Date(u.created_at).toLocaleDateString() : "—"}
        </td>
        <td className="py-3 pr-4 text-xs text-slate-500">
          {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}
        </td>
        <td className="py-3">
          <div className="flex items-center gap-1.5">
            <button
              onClick={props.onToggleActive}
              disabled={busy || isSelf}
              title={isSelf ? "You cannot disable your own account" : u.is_active ? "Disable account" : "Enable account"}
              className={`flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition ${
                u.is_active
                  ? "border-cyber-red/40 text-cyber-red hover:bg-cyber-red/10"
                  : "border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10"
              } disabled:cursor-not-allowed disabled:opacity-40`}
            >
              {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Power className="h-3 w-3" />}
              {u.is_active ? "Disable" : "Enable"}
            </button>
            <button
              onClick={props.onStartEdit}
              disabled={editing}
              className="flex items-center gap-1 rounded-md border border-night-600 px-2 py-1 text-[11px] font-medium text-slate-300 transition hover:bg-night-700/60"
            >
              <Pencil className="h-3 w-3" />
              Manage
            </button>
          </div>
        </td>
      </tr>

      {editing && (
        <tr className="border-b border-night-800/60 bg-night-850/40">
          <td colSpan={7} className="px-4 py-3">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
              <div>
                <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">Roles</p>
                <div className="flex flex-wrap gap-2">
                  {ROLE_OPTIONS.map((role) => (
                    <label key={role} className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        checked={editRoles.includes(role)}
                        onChange={() => props.onToggleRole(role)}
                        className="h-3.5 w-3.5 accent-electric-500"
                      />
                      {role}
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">Reset password</p>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={editPwd}
                    onChange={(e) => props.onPwdChange(e.target.value)}
                    placeholder="New password (8+ chars, letters + numbers)"
                    className="w-64 rounded-md border border-night-700 bg-night-900 px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-electric-500/60 focus:outline-none"
                  />
                  <button
                    onClick={props.onResetPassword}
                    disabled={busy}
                    className="flex items-center gap-1 rounded-md border border-electric-500/40 px-2.5 py-1.5 text-[11px] font-medium text-electric-400 transition hover:bg-electric-500/10 disabled:opacity-50"
                  >
                    {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <KeyRound className="h-3 w-3" />}
                    Reset
                  </button>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={props.onSaveRoles}
                  disabled={savingRoles}
                  className="flex items-center gap-1 rounded-md bg-electric-500 px-3 py-1.5 text-[11px] font-semibold text-night-950 transition hover:bg-electric-400 disabled:opacity-50"
                >
                  {savingRoles ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
                  Save roles
                </button>
                <button
                  onClick={props.onCancelEdit}
                  className="flex items-center gap-1 rounded-md border border-night-600 px-3 py-1.5 text-[11px] font-medium text-slate-400 transition hover:bg-night-700/60"
                >
                  <X className="h-3 w-3" />
                  Cancel
                </button>
              </div>
              <div className="min-w-[220px]">
                <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">Account lifecycle</p>
                <div className="flex flex-wrap items-center gap-3">
                  <label className={`flex cursor-pointer items-center gap-1.5 text-xs ${isSelf ? "text-slate-600" : "text-slate-300"}`}>
                    <input
                      type="checkbox"
                      checked={u.sso_blocked ?? false}
                      onChange={() => props.onBlockSso(!u.sso_blocked)}
                      disabled={busy || isSelf}
                      className="h-3.5 w-3.5 accent-cyber-yellow"
                    />
                    <ShieldOff className="h-3 w-3" />
                    Block SSO sign-in
                  </label>
                  {u.is_active ? (
                    <button
                      onClick={props.onDeprovision}
                      disabled={busy || isSelf}
                      className="flex items-center gap-1 rounded-md border border-cyber-red/50 px-2.5 py-1.5 text-[11px] font-semibold text-cyber-red transition hover:bg-cyber-red/10 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Archive className="h-3 w-3" />}
                      Deprovision · revoke sessions
                    </button>
                  ) : (
                    <button
                      onClick={props.onRestore}
                      disabled={busy}
                      className="flex items-center gap-1 rounded-md border border-emerald-500/40 px-2.5 py-1.5 text-[11px] font-semibold text-emerald-400 transition hover:bg-emerald-500/10 disabled:opacity-50"
                    >
                      {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCcw className="h-3 w-3" />}
                      Restore account
                    </button>
                  )}
                </div>
              </div>
            </div>
            <p className="mt-2 text-[11px] text-slate-600">
              <ShieldCheck className="mr-1 inline h-3 w-3" />
              You cannot disable, demote or deprovision your own account; removing the last ADMIN is blocked
              server-side. Every lifecycle action is written to the signed audit trail.
            </p>
          </td>
        </tr>
      )}
    </>
  );
}
