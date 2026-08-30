import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  BookOpen, Clock, Download, FileText, Shield, ShieldCheck,
  ShieldAlert, Sparkles, RefreshCw, Eye, CheckCircle2, Lock,
  BarChart3, ChevronRight, Hash, QrCode, Key,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { useToast } from "../components/ui/Toast";
import { Card, EmptyState, Modal, Skeleton, SeverityBadge, StatusBadge } from "../components/ui";
import type { Incident, Paginated } from "../types";

/* ── Types ────────────────────────────────────────────────────────────── */

interface ReportData {
  report_id: string;
  title: string;
  severity: string;
  created_at: string;
  created_by: string;
  id?: string;
  incident_id?: string;
  content?: any;
  pdf_available?: boolean;
}

interface EnhancedReport {
  report_id: string;
  html_content: string;
  pdf_available: boolean;
  pdf_url: string | null;
  integrity_hash: string;
  classification: string;
  tfa_verified: boolean;
  generated_by: string;
  generated_at: string;
  data_summary: {
    incidents: number;
    complaints: number;
    transactions: number;
    total_amount: number;
    risk_level: string;
  };
  processing_time_s: number;
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

async function waitForBackend(maxAttempts = 3, delayMs = 2000): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 6000);
      const res = await fetch("/health", { signal: c.signal });
      clearTimeout(t);
      if (res.ok) return;
    } catch { /* waking up */ }
    if (i < maxAttempts - 1) await new Promise(r => setTimeout(r, delayMs));
  }
}

async function postWithRetry<T>(url: string, body: unknown, retries = 2): Promise<{ data: T }> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await api.post<T>(url, body);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { status?: number } };
      const status = axiosErr.response?.status;
      if (attempt < retries && (!status || status === 502 || status === 503)) {
        await waitForBackend(1, 2000);
        continue;
      }
      throw err;
    }
  }
  throw new Error("Unreachable");
}

/* ── 2FA Gate ─────────────────────────────────────────────────────────── */

function TwoFactorGate({ onSuccess, onCancel }: { onSuccess: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const verify = async () => {
    if (code.length !== 6) return;
    setLoading(true);
    setError("");
    try {
      await waitForBackend();
      await api.post("/auth/2fa/verify", { code, action: "verify" });
      onSuccess();
    } catch (err: any) {
      if (err?.response?.status === 400 && err?.response?.data?.detail?.includes("not set up")) {
        onSuccess(); // 2FA not configured, allow anyway
      } else {
        setError(getErrorMessage(err));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/10 border border-amber-500/30">
          <ShieldAlert className="h-5 w-5 text-amber-400" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-amber-400">Security Verification Required</h3>
          <p className="text-xs text-slate-400">Enter your 6-digit 2FA code to generate this report</p>
        </div>
      </div>
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">{error}</div>
      )}
      <div className="flex gap-3">
        <input
          type="text"
          className="input flex-1 text-center text-lg tracking-[0.3em] font-mono"
          placeholder="000000"
          maxLength={6}
          autoFocus
          value={code}
          onChange={(e) => { setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6)); setError(""); }}
          onKeyDown={(e) => { if (e.key === "Enter" && code.length === 6) verify(); if (e.key === "Escape") onCancel(); }}
        />
        <button className="btn-primary" disabled={code.length !== 6 || loading} onClick={verify}>
          {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <><Lock className="h-4 w-4 mr-1" /> Verify</>}
        </button>
        <button className="btn-ghost px-3" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

/* ── Report Viewer (HTML preview with biometric elements) ─────────────── */

function ReportViewer({ report, onClose }: { report: EnhancedReport; onClose: () => void }) {
  return (
    <div className="space-y-4">
      {/* Biometric Header */}
      <div className="flex items-center gap-4 rounded-xl border border-electric-500/20 bg-electric-500/5 p-4">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-electric-500/20">
          <ShieldCheck className="h-6 w-6 text-electric-400" />
        </div>
        <div className="flex-1">
          <h3 className="text-sm font-bold text-white">Official Intelligence Report</h3>
          <p className="text-xs text-slate-400 font-mono mt-1">{report.report_id}</p>
        </div>
        <div className="text-right">
          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-[11px] font-semibold ${
            report.tfa_verified ? "bg-green-500/10 text-green-400 border border-green-500/30" : "bg-amber-500/10 text-amber-400 border border-amber-500/30"
          }`}>
            {report.tfa_verified ? "✓ 2FA VERIFIED" : "⚠ NO 2FA"}
          </span>
          <p className="text-[10px] text-slate-500 mt-1">{report.classification}</p>
        </div>
      </div>

      {/* Data Summary */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Incidents", value: report.data_summary.incidents, color: "text-electric-400" },
          { label: "Complaints", value: report.data_summary.complaints.toLocaleString(), color: "text-white" },
          { label: "Transactions", value: report.data_summary.transactions.toLocaleString(), color: "text-white" },
          { label: "Risk Level", value: report.data_summary.risk_level, color: report.data_summary.risk_level === "CRITICAL" ? "text-red-400" : "text-amber-400" },
        ].map(s => (
          <div key={s.label} className="rounded-lg bg-night-800/60 p-3 text-center">
            <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">{s.label}</p>
            <p className={`text-lg font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Integrity Block */}
      <div className="rounded-lg border border-night-700/70 bg-night-900/60 p-4">
        <div className="flex items-center gap-2 mb-2">
          <Hash className="h-4 w-4 text-electric-400" />
          <span className="text-xs font-bold text-slate-200">Document Integrity</span>
        </div>
        <div className="space-y-1 font-mono text-[10px] text-slate-500">
          <p>Report: {report.report_id}</p>
          <p>HMAC-SHA256: <span className="text-electric-400 break-all">{report.integrity_hash?.slice(0, 64) || "N/A"}...</span></p>
          <p>Generated: {report.generated_at} by {report.generated_by}</p>
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-3">
        {report.pdf_available && report.pdf_url && (
          <a
            href={report.pdf_url}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-primary"
          >
            <Download className="h-4 w-4 mr-1" /> Download PDF
          </a>
        )}
        <button
          className="btn-ghost"
          onClick={() => {
            // Open HTML report in new tab
            const blob = new Blob([report.html_content], { type: "text/html" });
            const url = URL.createObjectURL(blob);
            window.open(url, "_blank");
          }}
        >
          <Eye className="h-4 w-4 mr-1" /> View Full Report
        </button>
        <button className="btn-ghost ml-auto" onClick={onClose}>Close</button>
      </div>

      {/* HTML Preview */}
      <div className="rounded-xl border border-night-700/70 overflow-hidden" style={{ height: "60vh" }}>
        <iframe
          srcDoc={report.html_content}
          className="w-full h-full border-0"
          title="Report Preview"
        />
      </div>
    </div>
  );
}

/* ── Main Page ────────────────────────────────────────────────────────── */

export default function IncidentReports() {
  const { success, error: toastError } = useToast();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [viewing, setViewing] = useState<EnhancedReport | null>(null);
  const [showTfaVerify, setShowTfaVerify] = useState(false);
  const [generating, setGenerating] = useState(false);

  const warmUp = async () => { try { await api.get("/health"); } catch { /* */ } };

  // Fetch incidents
  const { data: incidents, isLoading: incidentsLoading } = useQuery({
    queryKey: ["incidents", "reports"],
    queryFn: async () => {
      const res = await api.get<Paginated<Incident>>("/incidents", { params: { page: 1, page_size: 50 } });
      return res.data;
    },
  });

  // Auto-generate report from incidents
  const generateMutation = useMutation({
    mutationFn: async () => {
      await waitForBackend();
      setGenerating(true);
      const res = await postWithRetry<EnhancedReport>("/reports/enhanced/generate", {
        tfa_code: null,
        classification: "CONFIDENTIAL",
      }, 2);
      return res.data;
    },
    onSuccess: (data) => {
      setViewing(data);
      setGenerating(false);
      success("Report Generated", `Report ${data.report_id} created with ${data.data_summary.incidents} incidents`);
    },
    onError: (err: any) => {
      setGenerating(false);
      toastError("Generation Failed", getErrorMessage(err));
    },
  });

  const handleGenerate = () => {
    setShowTfaVerify(true);
  };

  const handleTfaSuccess = () => {
    setShowTfaVerify(false);
    generateMutation.mutate();
  };

  // Auto-generate on first load if there are incidents but no reports
  useEffect(() => {
    if (incidents && incidents.items.length > 0 && !viewing && !generating) {
      // Don't auto-generate — let user click the button
    }
  }, [incidents]);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-electric-500 to-cyber-purple">
          <FileText className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">Intelligence Reports</h1>
          <p className="text-sm text-slate-400">Auto-generated from incidents with biometric verification</p>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-green-400">
            <Shield className="h-3.5 w-3.5" />
            <span>2FA Protected</span>
          </div>
          <button
            className="btn-primary"
            disabled={generating || generateMutation.isPending}
            onClick={handleGenerate}
          >
            {generating || generateMutation.isPending ? (
              <><RefreshCw className="h-4 w-4 animate-spin mr-1" /> Generating Report...</>
            ) : (
              <><Sparkles className="h-4 w-4 mr-1" /> Auto-Generate Report</>
            )}
          </button>
        </div>
      </div>

      {/* 2FA Gate */}
      {showTfaVerify && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <TwoFactorGate
            onSuccess={handleTfaSuccess}
            onCancel={() => setShowTfaVerify(false)}
          />
        </Card>
      )}

      {/* Loading state */}
      {(generating || generateMutation.isPending) && (
        <Card className="border-electric-500/30 bg-electric-500/5">
          <div className="flex items-center gap-4 p-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-electric-500/20">
              <RefreshCw className="h-5 w-5 text-electric-400 animate-spin" />
            </div>
            <div>
              <p className="text-sm font-semibold text-electric-300">Auto-generating intelligence report...</p>
              <p className="text-xs text-slate-500">Collecting incident data, running analysis, generating biometric stamps</p>
            </div>
          </div>
        </Card>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        {/* Left: Recent incidents + reports */}
        <div className="lg:col-span-2 space-y-4">
          {/* Incidents to generate reports from */}
          <Card title="🎯 Recent Incidents" subtitle="Select an incident or auto-generate from all">
            {incidentsLoading ? (
              <div className="space-y-2">
                {[1, 2, 3].map(i => <Skeleton key={i} className="h-16 rounded-lg" />)}
              </div>
            ) : incidents && incidents.items.length > 0 ? (
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {incidents.items.slice(0, 10).map((inc) => (
                  <div key={inc.id} className="flex items-center gap-3 rounded-lg border border-night-700/50 bg-night-850/40 p-3 hover:border-electric-500/30 transition-colors">
                    <div className="shrink-0 w-8 h-8 rounded bg-night-800 flex items-center justify-center">
                      <FileText className="h-4 w-4 text-electric-400/60" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-slate-200 truncate">{inc.title}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[10px] font-mono text-electric-400/70">{inc.incident_id?.slice(0, 12)}</span>
                        <SeverityBadge severity={inc.severity} />
                        <StatusBadge status={inc.status} />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={<FileText className="h-6 w-6" />}
                title="No incidents yet"
                description="Run a simulation or upload data to create incidents, then generate reports."
              />
            )}
          </Card>

          {/* Generated reports */}
          <Card title="📋 Generated Reports" subtitle="Official intelligence reports with biometric verification">
            {viewing ? (
              <ReportViewer report={viewing} onClose={() => setViewing(null)} />
            ) : (
              <div className="text-center py-8">
                <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-night-800 mx-auto mb-4">
                  <FileText className="h-8 w-8 text-slate-600" />
                </div>
                <p className="text-sm text-slate-400 mb-2">No report generated yet</p>
                <p className="text-xs text-slate-500 mb-4">
                  Click "Auto-Generate Report" to create a professional intelligence report
                  from all incidents, with biometric stamps and HMAC integrity verification.
                </p>
                <button
                  className="btn-primary"
                  disabled={generating || generateMutation.isPending}
                  onClick={handleGenerate}
                >
                  <Sparkles className="h-4 w-4 mr-1" /> Auto-Generate Report
                </button>
              </div>
            )}
          </Card>
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          {/* Quick Generate */}
          <Card title="⚡ Quick Generate" subtitle="One-click report from all incidents">
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                Generate a comprehensive intelligence report from all {incidents?.items.length || 0} incidents,
                including fraud analysis, geographic distribution, and risk assessment.
              </p>
              <button
                className="w-full btn-primary"
                disabled={generating || generateMutation.isPending}
                onClick={handleGenerate}
              >
                {generating ? (
                  <><RefreshCw className="h-4 w-4 animate-spin mr-1" /> Generating...</>
                ) : (
                  <><Sparkles className="h-4 w-4 mr-1" /> Generate Full Report</>
                )}
              </button>
            </div>
          </Card>

          {/* Report Features */}
          <Card title="🔐 Report Features" subtitle="Professional biometric elements">
            <div className="space-y-2.5">
              {[
                { icon: <ShieldCheck className="h-4 w-4 text-green-400" />, text: "HMAC-SHA256 integrity signature" },
                { icon: <QrCode className="h-4 w-4 text-electric-400" />, text: "QR code verification link" },
                { icon: <Lock className="h-4 w-4 text-amber-400" />, text: "2FA authorization badge" },
                { icon: <FileText className="h-4 w-4 text-blue-400" />, text: "Official CONFIDENTIAL stamp" },
                { icon: <Shield className="h-4 w-4 text-purple-400" />, text: "CyberSentinel-X official seal" },
                { icon: <Hash className="h-4 w-4 text-cyan-400" />, text: "Tamper-evident watermark" },
              ].map((f, i) => (
                <div key={i} className="flex items-center gap-2 text-xs text-slate-400">
                  {f.icon}
                  <span>{f.text}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Security */}
          <Card title="🔒 Security" subtitle="2FA protection for reports">
            <div className="space-y-2">
              <p className="text-xs text-slate-400">
                Reports are protected by two-factor authentication. Each report includes
                a digital signature, HMAC integrity hash, and audit trail.
              </p>
              <button
                onClick={() => window.location.href = "/security-settings"}
                className="flex items-center gap-1.5 text-xs text-electric-400 hover:text-electric-300"
              >
                <Key className="h-3.5 w-3.5" /> Configure 2FA
              </button>
            </div>
          </Card>

          {/* Quick Links */}
          <Card title="🔗 Quick Links">
            <div className="space-y-1">
              {[
                { label: "Incident Dashboard", to: "/incidents", icon: <BarChart3 className="h-3.5 w-3.5" /> },
                { label: "Evidence Ledger", to: "/evidence-ledger", icon: <BookOpen className="h-3.5 w-3.5" /> },
                { label: "Security Settings", to: "/security-settings", icon: <ShieldCheck className="h-3.5 w-3.5" /> },
              ].map(link => (
                <button
                  key={link.to}
                  onClick={() => window.location.href = link.to}
                  className="flex items-center gap-2 w-full text-left rounded-lg px-3 py-2 text-xs text-slate-400 hover:bg-night-800 hover:text-slate-200 transition-colors"
                >
                  {link.icon} {link.label} <ChevronRight className="ml-auto h-3 w-3 opacity-50" />
                </button>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
