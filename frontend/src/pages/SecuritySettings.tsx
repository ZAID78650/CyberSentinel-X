import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Check, CheckCircle2, Copy, Key, RefreshCw,
  Shield, ShieldCheck, ShieldOff,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, Skeleton } from "../components/ui";

// ── Types ──────────────────────────────────────────────────────────────

interface TFAStatus {
  enabled: boolean;
  verified: boolean;
  has_secret: boolean;
}


interface TFAResult {
  valid: boolean;
  message: string;
  backup_codes?: string[];
  warning?: string;
}

interface TFASetupData {
  secret: string;
  uri: string;
  qr_data_uri: string;
  enabled: boolean;
  issuer: string;
  account: string;
}

/** Wait for the Render backend to wake up by polling /health. */
async function waitForBackend(maxAttempts = 3, delayMs = 3000): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 8000);
      const res = await fetch("/health", { signal: controller.signal });
      clearTimeout(t);
      if (res.ok) return;
    } catch { /* backend still waking */ }
    if (i < maxAttempts - 1) await new Promise(r => setTimeout(r, delayMs));
  }
}

/** POST with retry for 502/503 (Render cold-start). */
async function postWithRetry<T>(url: string, body: unknown, retries = 2): Promise<{ data: T }> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await api.post<T>(url, body);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { status?: number } };
      const status = axiosErr.response?.status;
      const isLast = attempt === retries;
      // Retry on 502 / 503 / network (Render cold-start)
      if (!isLast && (!status || status === 502 || status === 503)) {
        await waitForBackend(1, 2000);
        continue;
      }
      throw err;
    }
  }
  throw new Error("Unreachable");
}

// ── 2FA Setup Panel ────────────────────────────────────────────────────

function TFASetupPanel() {
  const [secret, setSecret] = useState("");
  const [qrUri, setQrUri] = useState("");
  const [verifyCode, setVerifyCode] = useState("");
  const [copied, setCopied] = useState(false);
  const [result, setResult] = useState<TFAResult | null>(null);
  const [error, setError] = useState("");

  const queryClient = useQueryClient();

  const setupMutation = useMutation({
    mutationFn: async () => {
      await waitForBackend();
      const res = await api.get<TFASetupData>("/auth/2fa/setup");
      return res.data;
    },
    onSuccess: (data) => {
      setSecret(data.secret);
      setQrUri(data.qr_data_uri || data.uri);
      setResult(null);
      setCopied(false);
      setError("");
    },
    onError: (err: unknown) => {
      setError(getErrorMessage(err));
    },
  });

  const verifyMutation = useMutation({
    mutationFn: async (code: string) => {
      await waitForBackend();
      const res = await postWithRetry<TFAResult>("/auth/2fa/verify", { code, action: "enable" }, 2);
      return res.data;
    },
    onSuccess: (data) => {
      setResult(data);
      setError("");
      setVerifyCode("");
      queryClient.invalidateQueries({ queryKey: ["auth-me"] });
      queryClient.invalidateQueries({ queryKey: ["tfa-status"] });
    },
    onError: (err: unknown) => {
      setError(getErrorMessage(err));
    },
  });

  const handleCopySecret = () => {
    // Copy without spaces for Google Authenticator compatibility
    navigator.clipboard.writeText(secret.replace(/\s/g, ""));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-electric-500/10 border border-electric-500/30">
          <ShieldCheck className="h-5 w-5 text-electric-400" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-slate-200">Enable Two-Factor Authentication</h3>
          <p className="text-xs text-slate-500">Add an extra layer of security to your account</p>
        </div>
      </div>

      {/* Error banner — always visible when set */}
      {(error || setupMutation.isError || verifyMutation.isError) && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-red-400" />
          <div>
            <p className="font-semibold">Verification Failed</p>
            <p className="text-xs text-red-400 mt-1">
              {error || getErrorMessage(setupMutation.error || verifyMutation.error)}
            </p>
            <p className="text-[11px] text-red-500 mt-1">
              Make sure you entered the correct 6-digit code from your authenticator app. The code changes every 30 seconds.
            </p>
          </div>
        </div>
      )}

      {/* Setup button — shown when no secret yet and no result */}
      {!secret && !result && (
        <button
          onClick={() => { setError(""); setupMutation.mutate(); }}
          disabled={setupMutation.isPending}
          className="btn-primary"
        >
          {setupMutation.isPending ? (
            <><RefreshCw className="h-4 w-4 animate-spin" /> Generating...</>
          ) : (
            <><Shield className="h-4 w-4" /> Set Up 2FA</>
          )}
        </button>
      )}

      {/* Loading spinner during verification */}
      {verifyMutation.isPending && (
        <div className="rounded-lg border border-electric-500/30 bg-electric-500/5 p-4 flex items-center gap-3">
          <RefreshCw className="h-5 w-5 text-electric-400 animate-spin" />
          <div>
            <p className="text-sm font-semibold text-electric-300">Verifying your code...</p>
            <p className="text-xs text-slate-500">Waking up backend, this may take a moment.</p>
          </div>
        </div>
      )}

      {/* QR code + verification input */}
      {secret && !result && !verifyMutation.isPending && (
        <div className="space-y-4">
          <div className="rounded-lg border border-cyber-yellow/30 bg-cyber-yellow/5 p-4">
            <p className="text-xs font-bold text-cyber-yellow mb-2">Step 1: Add to your authenticator app</p>
            <p className="text-xs text-slate-400 mb-3">
              Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.):
            </p>
            <div className="flex justify-center mb-4">
              <img
                src={qrUri.startsWith("data:") ? qrUri : `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrUri)}`}
                alt="2FA QR Code"
                className="rounded-lg bg-white p-2"
                width={200}
                height={200}
              />
            </div>
            <div className="text-center">
              <p className="text-[10px] text-slate-500 mb-1">Or enter this code manually:</p>
              <button
                onClick={handleCopySecret}
                className="inline-flex items-center gap-2 rounded-lg border border-electric-500/30 bg-electric-500/10 px-4 py-2 font-mono text-sm text-electric-400 hover:bg-electric-500/20 transition-colors"
              >
                <span className="tracking-[0.15em]">{secret.match(/.{1,4}/g)?.join(' ') || secret}</span>
                {copied ? <Check className="h-4 w-4 text-green-400" /> : <Copy className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-night-700/70 p-4">
            <p className="text-xs font-bold text-slate-300 mb-2">Step 2: Enter the 6-digit verification code</p>
            <p className="text-xs text-slate-500 mb-3">
              Enter the 6-digit code from your authenticator app to complete setup.
            </p>
            <div className="flex gap-3">
              <input
                type="text"
                className="input flex-1 text-center text-lg tracking-[0.3em] font-mono"
                placeholder="000000"
                maxLength={6}
                pattern="[0-9]{6}"
                value={verifyCode}
                onChange={(e) => {
                  const val = e.target.value.replace(/[^0-9]/g, "").slice(0, 6);
                  setVerifyCode(val);
                  setError(""); // clear error on new input
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && verifyCode.length === 6) {
                    setError("");
                    verifyMutation.mutate(verifyCode);
                  }
                }}
              />
              <button
                className="btn-primary"
                disabled={verifyCode.length !== 6 || verifyMutation.isPending}
                onClick={() => { setError(""); verifyMutation.mutate(verifyCode); }}
              >
                {verifyMutation.isPending ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <><Check className="h-4 w-4" /> Verify</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ✅ SUCCESS — with backup codes */}
      {result && result.backup_codes && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/5 p-5 space-y-4">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-400" />
            <p className="text-sm font-bold text-green-400">{result.message || "2FA has been enabled successfully!"}</p>
          </div>
          <p className="text-xs text-green-300/80">
            Your account is now protected with two-factor authentication. You will need to enter a code from your authenticator app each time you log in.
          </p>

          <div className="rounded-lg bg-night-800 p-4">
            <p className="text-xs font-bold text-slate-300 mb-3">🔑 Your Backup Codes — Save These Now!</p>
            <p className="text-[11px] text-amber-400 mb-3 flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5" />
              {result.warning || "These codes will not be shown again. Store them securely."}
            </p>
            <div className="grid grid-cols-2 gap-2 font-mono text-sm">
              {result.backup_codes.map((code, i) => (
                <div key={i} className="flex items-center gap-2 bg-night-700/50 rounded px-3 py-1.5">
                  <span className="text-[10px] text-slate-500">{i + 1}.</span>
                  <span className="text-electric-300">{code}</span>
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={() => {
              navigator.clipboard.writeText(result.backup_codes!.join("\n"));
            }}
            className="text-xs text-electric-400 hover:text-electric-300 flex items-center gap-1"
          >
            <Copy className="h-3 w-3" /> Copy All Backup Codes
          </button>
        </div>
      )}

      {/* ✅ SUCCESS — without backup codes (edge case) */}
      {result && !result.backup_codes && (
        <div className="flex items-center gap-2 rounded-lg border border-green-500/30 bg-green-500/5 p-4">
          <CheckCircle2 className="h-5 w-5 text-green-400" />
          <span className="text-sm text-green-300">{result.message}</span>
        </div>
      )}
    </div>
  );
}

// ── 2FA Status Card ─────────────────────────────────────────────────────

function TFAStatusCard() {
  const { data: status, isLoading, refetch } = useQuery({
    queryKey: ["tfa-status"],
    queryFn: async () => (await api.get("/auth/2fa/status")).data as TFAStatus,
  });

  const [disableCode, setDisableCode] = useState("");
  const [disableError, setDisableError] = useState("");
  const [disableResult, setDisableResult] = useState<string | null>(null);

  const queryClient = useQueryClient();

  const disableMutation = useMutation({
    mutationFn: async (code: string) => {
      await waitForBackend();
      const res = await postWithRetry<TFAResult>("/auth/2fa/verify", { code, action: "disable" }, 2);
      return res.data;
    },
    onSuccess: (data) => {
      setDisableResult(data.message);
      setDisableError("");
      queryClient.invalidateQueries({ queryKey: ["auth-me"] });
      queryClient.invalidateQueries({ queryKey: ["tfa-status"] });
    },
    onError: (err: unknown) => {
      setDisableError(getErrorMessage(err));
    },
  });

  if (isLoading) return <Skeleton className="h-32" />;
  if (!status) return null;

  const StatusIcon = status.enabled ? ShieldCheck : ShieldOff;
  const statusColor = status.enabled ? "text-green-400" : "text-slate-400";
  const statusBg = status.enabled ? "bg-green-500/10 border-green-500/30" : "bg-slate-500/10 border-slate-500/30";
  const statusText = status.enabled ? "2FA is Active" : "2FA is Disabled";
  const statusDesc = status.enabled
    ? "Your account is secured with two-factor authentication. You will be asked for a verification code at each login."
    : "Your account is not protected by two-factor authentication. We strongly recommend enabling it.";

  return (
    <div className="space-y-4">
      {/* Status Banner */}
      <div className={`rounded-lg border p-4 ${statusBg}`}>
        <div className="flex items-center gap-3">
          <StatusIcon className={`h-8 w-8 ${statusColor}`} />
          <div>
            <p className={`text-lg font-bold ${statusColor}`}>{statusText}</p>
            <p className="text-xs text-slate-400 mt-0.5">{statusDesc}</p>
          </div>
          <button onClick={() => refetch()} className="ml-auto text-slate-500 hover:text-slate-300" title="Refresh">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Disable section (only if enabled) */}
      {status.enabled && !disableResult && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4">
          <div className="flex items-center gap-2 mb-3">
            <ShieldOff className="h-4 w-4 text-red-400" />
            <p className="text-sm font-semibold text-red-300">Disable 2FA</p>
          </div>
          <p className="text-xs text-slate-400 mb-3">
            To disable two-factor authentication, enter your current 6-digit verification code.
          </p>
          <div className="flex gap-3">
            <input
              type="text"
              className="input flex-1 text-center text-lg tracking-[0.3em]"
              placeholder="000000"
              maxLength={6}
              value={disableCode}
              onChange={(e) => setDisableCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
            />
            <button
              className="btn-ghost text-red-400 border-red-500/30 hover:bg-red-500/10"
              disabled={disableCode.length !== 6 || disableMutation.isPending}
              onClick={() => disableMutation.mutate(disableCode)}
            >
              {disableMutation.isPending ? <RefreshCw className="h-4 w-4 animate-spin" /> : "Disable"}
            </button>
          </div>
          {disableError && <p className="mt-2 text-xs text-red-400">{disableError}</p>}
        </div>
      )}

      {disableResult && (
        <div className="flex items-center gap-2 rounded-lg border border-green-500/30 bg-green-500/5 p-4">
          <CheckCircle2 className="h-5 w-5 text-green-400" />
          <span className="text-sm text-green-300">{disableResult}</span>
        </div>
      )}

      {/* Backup codes */}
      {status.enabled && !disableResult && (
        <BackupCodesPanel />
      )}
    </div>
  );
}

// ── Backup Codes Panel ─────────────────────────────────────────────────

function BackupCodesPanel() {
  const [codes, setCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [warning, setWarning] = useState("");

  const generateMutation = useMutation({
    mutationFn: async () => {
      await waitForBackend();
      const res = await api.get("/auth/2fa/backup-codes");
      return res.data as { codes: string[]; warning: string };
    },
    onSuccess: (data) => {
      setCodes(data.codes);
      setWarning(data.warning);
      setCopied(false);
    },
  });

  const handleCopyAll = () => {
    navigator.clipboard.writeText(codes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-electric-500/20 p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Key className="h-4 w-4 text-electric-400" />
          <span className="text-sm font-bold text-slate-200">Backup Codes</span>
        </div>
        <button
          className="btn-ghost text-xs"
          onClick={() => generateMutation.mutate()}
          disabled={generateMutation.isPending}
        >
          {generateMutation.isPending ? (
            <><RefreshCw className="h-3 w-3 animate-spin" /> Generating...</>
          ) : (
            <><Key className="h-3 w-3" /> Generate New Codes</>
          )}
        </button>
      </div>

      {codes.length > 0 && (
        <div>
          {warning && <p className="text-[11px] text-amber-400 mb-2">⚠️ {warning}</p>}
          <div className="grid grid-cols-2 gap-2 font-mono text-sm">
            {codes.map((code, i) => (
              <div key={i} className="flex items-center gap-2 bg-night-700/50 rounded px-3 py-1.5">
                <span className="text-[10px] text-slate-500">{i + 1}.</span>
                <span className="text-electric-300">{code}</span>
              </div>
            ))}
          </div>
          <button
            onClick={handleCopyAll}
            className="mt-3 text-xs text-electric-400 hover:text-electric-300 flex items-center gap-1"
          >
            {copied ? <><Check className="h-3 w-3" /> Copied!</> : <><Copy className="h-3 w-3" /> Copy All</>}
          </button>
        </div>
      )}

      {codes.length === 0 && (
        <p className="text-xs text-slate-500">
          Click "Generate New Codes" to get one-time recovery codes. Each code can only be used once.
        </p>
      )}
    </div>
  );
}

// ── Security Recommendations ────────────────────────────────────────────

function SecurityRecommendations() {
  const { data: user } = useQuery({
    queryKey: ["auth-me"],
    queryFn: async () => {
      const res = await api.get("/auth/me");
      return res.data;
    },
  });

  if (!user) return null;

  const checks = [
    { label: "Email verified", value: user.is_verified, icon: <ShieldCheck className="h-4 w-4" /> },
    { label: "Password set", value: user.has_password, icon: <Key className="h-4 w-4" /> },
    { label: "Two-factor enabled", value: user.two_factor_enabled, icon: <Shield className="h-4 w-4" /> },
  ];

  const passed = checks.filter(c => c.value).length;
  const total = checks.length;
  const score = Math.round((passed / total) * 100);
  const scoreColor = score >= 80 ? '#4ade80' : score >= 50 ? '#facc15' : '#f87171';

  return (
    <Card title="🔒 Security Score" subtitle="Account security assessment">
      <div className="flex items-center gap-6">
        <div className="relative h-20 w-20 shrink-0">
          <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
            <circle cx="50" cy="50" r="42" fill="none" stroke="#1a2540" strokeWidth="8" />
            <circle
              cx="50" cy="50" r="42" fill="none"
              stroke={scoreColor}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${(score / 100) * 264} 264`}
              style={{ filter: `drop-shadow(0 0 6px ${scoreColor})` }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-xl font-bold font-mono" style={{ color: scoreColor }}>{score}%</span>
          </div>
        </div>

        <div className="flex-1 space-y-2">
          {checks.map(c => (
            <div key={c.label} className="flex items-center gap-2">
              <span className={c.value ? "text-green-400" : "text-slate-600"}>{c.icon}</span>
              <span className={`text-sm ${c.value ? "text-green-400" : "text-slate-500"}`}>{c.label}</span>
              {c.value ? (
                <Check className="ml-auto h-3.5 w-3.5 text-green-400" />
              ) : (
                <span className="ml-auto text-xs text-red-400">Required</span>
              )}
            </div>
          ))}
        </div>
      </div>
      {score < 100 && (
        <div className="mt-4 rounded-lg bg-amber-500/10 border border-amber-500/20 p-3 text-xs text-amber-200">
          <strong>Recommendation:</strong> Enable two-factor authentication to improve your account security.
          It protects your account even if your password is compromised.
        </div>
      )}
    </Card>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────

export default function SecuritySettings() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="h-6 w-6 text-electric-400" />
        <div>
          <h1 className="text-xl font-bold text-white">Security Settings</h1>
          <p className="text-sm text-slate-400">Manage your account security and authentication settings</p>
        </div>
      </div>

      <SecurityRecommendations />

      <div className="grid gap-6 lg:grid-cols-2">
        {/* 2FA Status */}
        <Card title="🔐 Authentication Status">
          <TFAStatusCard />
        </Card>

        {/* Setup 2FA */}
        <Card title="🛡️ Set Up Two-Factor Authentication">
          <TFASetupPanel />
        </Card>
      </div>

      {/* Security Best Practices */}
      <Card title="🛡️ Security Best Practices" subtitle="Protect your CyberSentinel account">
        <div className="grid gap-3 md:grid-cols-2">
          {[
            {
              icon: <ShieldCheck className="h-5 w-5 text-green-400" />,
              title: "Enable 2FA",
              desc: "Add an extra layer of security with two-factor authentication using an authenticator app."
            },
            {
              icon: <Key className="h-5 w-5 text-blue-400" />,
              title: "Strong Password",
              desc: "Use a unique, complex password with at least 12 characters, including numbers and symbols."
            },
            {
              icon: <ShieldOff className="h-5 w-5 text-yellow-400" />,
              title: "Backup Codes",
              desc: "Generate and securely store backup codes in case you lose access to your authenticator."
            },
            {
              icon: <AlertTriangle className="h-5 w-5 text-red-400" />,
              title: "Monitor Access",
              desc: "Review your account's login history regularly for any unauthorized access attempts."
            },
          ].map(item => (
            <div key={item.title} className="flex gap-3 rounded-lg border border-night-700 bg-night-850/50 p-4">
              <div className="mt-0.5 shrink-0">{item.icon}</div>
              <div>
                <p className="text-sm font-semibold text-slate-200">{item.title}</p>
                <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
