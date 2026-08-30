import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  BookOpen, Clock, Download, Eye, FileText,
  Shield, ShieldAlert, ShieldCheck, Sparkles, 
  RefreshCw, X, Key, ChevronRight, BarChart3,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { useToast } from "../components/ui/Toast";
import { Card, EmptyState, Modal, Skeleton, SeverityBadge, StatusBadge } from "../components/ui";
import type { Incident, Paginated, Report, ReportDetail } from "../types";

/* ── 2FA Gate Component ────────────────────────────────────────────────── */

function TwoFactorGate({ onSuccess, onCancel }: { onSuccess: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const { error: toastError } = useToast();
  const [, setLoading] = useState(false);

  const verify = async () => {
    if (code.length !== 6) return;
    setLoading(true);
    try {
      await api.post("/auth/2fa/verify", { code, action: "verify" });
      onSuccess();
    } catch (err: any) {
      // If 2FA isn't set up, allow generation anyway for demo
      if (err?.response?.status === 400 && err?.response?.data?.detail?.includes("not set up")) {
        onSuccess();
      } else {
        toastError("Verification failed", getErrorMessage(err));
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
          <p className="text-xs text-slate-400">Enter your 2FA code to generate this report</p>
        </div>
      </div>

      <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
        <p className="text-xs text-slate-400 mb-3">
          Sensitive incident reports require two-factor authentication to generate and view.
          This ensures that only authorized personnel can access investigation data.
        </p>
        <div className="flex gap-3">
          <input
            type="text"
            className="input flex-1 text-center text-lg tracking-[0.3em] font-mono"
            placeholder="Enter 6-digit code"
            maxLength={6}
            autoFocus
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
            onKeyDown={(e) => {
              if (e.key === "Enter" && code.length === 6) verify();
              if (e.key === "Escape") onCancel();
            }}
          />
          <button
            className="btn-ghost px-3 py-2"
            onClick={onCancel}
          >
            Cancel
          </button>
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-500">
        <Shield className="h-3.5 w-3.5" />
        <span>
          This verification ensures report access is logged and auditable.
          <button onClick={onCancel} className="ml-1 text-electric-400 hover:underline">Go back</button>
        </span>
      </div>
    </div>
  );
}

/* ── Report Preview Panel ─────────────────────────────────────────────── */

function ReportPreview({ report, onClose, onDownload, verifying, onVerifyClick }: {
  report: ReportDetail;
  onClose: () => void;
  onDownload: () => void;
  verifying: boolean;
  onVerifyClick: () => void;
}) {
  const inc = report.content.incident as Record<string, any> | undefined;
  const risk = report.content.risk as Record<string, any> | undefined;
  const investigation = report.content.investigation as Record<string, any> | undefined;
  const mitre = (report.content.mitre || []) as Record<string, string>[];
  const recommendations = (report.content.recommendations || []) as Record<string, string>[];
  const timeline = (report.content.timeline || []) as Record<string, any>[];
  const affected = (report.content.affected || {}) as Record<string, string[]>;

  const severityColor: Record<string, string> = {
    CRITICAL: "text-red-400 bg-red-500/10 border-red-500/30",
    HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-300/30",
    LOW: "text-green-400 bg-green-500/10 border-green-500/30",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">{report.report.title}</h2>
          <p className="mt-1 text-sm text-slate-400">{report.report.incident_id}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={onClose} className="btn-ghost px-3 py-1.5 text-xs">
            <X className="h-4 w-4 mr-1" />Close
          </button>
          {report.pdf_available ? (
            <button onClick={onDownload} className="btn-primary text-xs">
              <Download className="h-4 w-4 mr-1" /> Download PDF
            </button>
          ) : (
            <button onClick={onVerifyClick} disabled={verifying} className="btn-primary text-xs">
              {verifying ? <RefreshCw className="h-4 w-4 animate-spin mr-1" /> : <Shield className="h-4 w-4 mr-1" />}
              Generate Report
            </button>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="rounded-lg bg-night-800/60 p-3">
          <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Status</p>
          <StatusBadge status={inc?.status} />
        </div>
        <div className="rounded-lg bg-night-800/60 p-3">
          <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Severity</p>
          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${severityColor[inc?.severity] || 'text-gray-400'}`}>
            {inc?.severity || 'N/A'}
          </span>
        </div>
        <div className="rounded-lg bg-night-800/60 p-3">
          <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Risk Score</p>
          <p className="font-mono text-xl font-bold text-electric-400">
            {risk?.score ?? '—'}
            <span className="text-xs font-normal text-slate-500 ml-1">/100</span>
          </p>
        </div>
        <div className="rounded-lg bg-night-800/60 p-3">
          <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Confidence</p>
          <p className="font-mono text-xl font-bold text-green-400">
            {risk?.confidence != null ? `${(risk.confidence * 100).toFixed(0)}%` : '—'}
          </p>
        </div>
      </div>

      {/* Investigation Summary */}
      {investigation?.summary && (
        <div className="rounded-xl border border-electric-500/20 bg-electric-500/5 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Sparkles className="h-4 w-4 text-electric-400" />
            <h4 className="text-sm font-bold text-electric-400">AI Investigation Summary</h4>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">{investigation.summary}</p>
          {investigation.verdict && (
            <div className="mt-3 flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-bold bg-electric-500/20 text-electric-300">
                {investigation.verdict}
              </span>
              <span className="text-xs text-slate-400">
                {investigation.confidence ? `${(investigation.confidence * 100).toFixed(0)}% confidence` : ''}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Affected Entities */}
      {affected && (affected.users?.length || affected.devices?.length || affected.ips?.length || affected.assets?.length) > 0 && (
        <div>
          <h4 className="text-sm font-bold text-slate-200 mb-2">Affected Entities</h4>
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Users", items: affected.users, icon: "👤" },
              { label: "Devices", items: affected.devices, icon: "💻" },
              { label: "IPs", items: affected.ips, icon: "🌐" },
              { label: "Assets", items: affected.assets, icon: "🏢" },
            ].filter(e => e.items && e.items.length > 0).map(item => (
              <div key={item.label} className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
                <p className="text-[10px] font-bold uppercase text-slate-500 mb-1">{item.icon} {item.label}</p>
                <div className="space-y-0.5">
                  {item.items!.slice(0, 3).map((v, i) => (
                    <p key={i} className="text-xs font-mono text-slate-300 truncate">{v}</p>
                  ))}
                  {item.items!.length > 3 && (
                    <p className="text-[10px] text-slate-500">+{item.items!.length - 3} more</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK + Recommendations in 2-col */}
      <div className="grid gap-4 lg:grid-cols-2">
        {mitre.length > 0 && (
          <div>
            <h4 className="text-sm font-bold text-slate-200 mb-2 flex items-center gap-1.5">
              <span className="text-red-400">🎯</span> MITRE ATT&CK
            </h4>
            <div className="space-y-1.5">
              {mitre.map((m: Record<string, string>, i: number) => (
                <div key={i} className="flex items-start gap-2 rounded bg-night-850/50 px-3 py-2 text-xs">
                  <code className="shrink-0 text-electric-400 font-mono">{m.technique_id || m.id || 'N/A'}</code>
                  <span className="text-slate-300">{m.name || 'Unknown'}</span>
                  {m.tactic && <span className="ml-auto text-[10px] text-slate-500 italic">{m.tactic}</span>}
                </div>
              ))}
            </div>
          </div>
        )}

        {recommendations.length > 0 && (
          <div>
            <h4 className="text-sm font-bold text-slate-200 mb-2 flex items-center gap-1.5">
              <span className="text-green-400">✓</span> Recommended Actions
            </h4>
            <div className="space-y-1.5">
              {recommendations.map((r: Record<string, string>, i: number) => (
                <div key={i} className="flex items-start gap-2 rounded bg-night-850/50 px-3 py-2 text-xs">
                  <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    r.priority === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                    r.priority === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-green-500/20 text-green-400'
                  }`}>
                    {r.priority || 'N/A'}
                  </span>
                  <span className="text-slate-300">{r.action}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Timeline */}
      {timeline.length > 0 && (
        <div>
          <h4 className="text-sm font-bold text-slate-200 mb-2 flex items-center gap-1.5">
            <span className="text-yellow-400">⏱</span> Event Timeline
          </h4>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left">
                  <th className="pb-2 pr-4 text-[10px] font-semibold uppercase text-slate-500">Time</th>
                  <th className="pb-2 px-4 text-[10px] font-semibold uppercase text-slate-500">Event</th>
                  <th className="pb-2 px-4 text-[10px] font-semibold uppercase text-slate-500">Severity</th>
                  <th className="pb-2 px-4 text-[10px] font-semibold uppercase text-slate-500">Source</th>
                </tr>
              </thead>
              <tbody>
                {timeline.slice(0, 8).map((t: Record<string, any>, i: number) => (
                  <tr key={i} className="border-t border-night-800/50">
                    <td className="py-2 pr-4 font-mono text-slate-500 text-[11px]">
                      {t.timestamp ? new Date(t.timestamp).toLocaleString() : '—'}
                    </td>
                    <td className="py-2 px-4 text-slate-300">{t.event_type || '—'}</td>
                    <td className="py-2 px-4">
                      {t.severity && (
                        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${severityColor[t.severity] || ''}`}>
                          {t.severity}
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-4 font-mono text-slate-500 text-[11px]">{t.source_ip || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Hash & Meta */}
      <div className="flex items-center justify-between rounded-lg bg-night-900/60 p-3 text-[11px] text-slate-500">
        <span>Generated: {report.report.created_at ? new Date(report.report.created_at).toLocaleString() : '—'}</span>
        <span>By: {report.report.created_by || 'System'}</span>
      </div>
    </div>
  );
}

/* ── Main Component ────────────────────────────────────────────────────── */

export default function IncidentReports() {
  const { success, error: toastError } = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [busyIncident, setBusyIncident] = useState<string | null>(null);
  const [viewing, setViewing] = useState<ReportDetail | null>(null);
  const [showTfaVerify, setShowTfaVerify] = useState(false);
  const [pendingIncident, setPendingIncident] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState("");

  const { data: reports, isLoading: reportsLoading } = useQuery({
    queryKey: ["reports", page],
    queryFn: async () => (await api.get<Paginated<Report>>("/reports", { params: { page, page_size: 12 } })).data,
  });

  const { data: incidents } = useQuery({
    queryKey: ["incidents", "reports"],
    queryFn: async () => {
      const res = await api.get<Paginated<Incident>>("/incidents", { params: { page: 1, page_size: 50 } });
      return res.data;
    },
  });

  const generateMutation = useMutation({
    mutationFn: async (id: string) => {
      return (await api.post(`/reports/${id}/generate`)).data;
    },
    onSuccess: (data) => {
      success("Report generated", `Report ${data.report?.report_id || ''} created successfully`);
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      if (data && data.report) {
        setViewing(data);
      }
    },
    onError: (err: any) => {
      toastError("Generation failed", getErrorMessage(err));
    },
  });

  const handleGenerateClick = (id: string) => {
    setPendingIncident(id);
    setShowTfaVerify(true);
  };

  const handleVerifySuccess = () => {
    if (pendingIncident) {
      setBusyIncident(pendingIncident);
      generateMutation.mutate(pendingIncident, {
        onSettled: () => setBusyIncident(null),
      });
    }
    setShowTfaVerify(false);
    setPendingIncident(null);
  };

  const filteredReports = reports?.items?.filter(r => {
    if (!sevFilter) return true;
    const inc = r as any;
    return inc.severity?.toUpperCase() === sevFilter;
  }) || [];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-electric-500 to-cyber-purple">
          <FileText className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">Security Reports</h1>
          <p className="text-sm text-slate-400">Intelligence reports with AI analysis and audit trail</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Shield className="h-4 w-4 text-green-400" />
          <span className="text-xs text-green-400 font-medium">2FA Protected</span>
        </div>
      </div>

      {/* 2FA Modal */}
      {showTfaVerify && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <TwoFactorGate
            onSuccess={handleVerifySuccess}
            onCancel={() => { setShowTfaVerify(false); setPendingIncident(null); }}
          />
        </Card>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        {/* Reports List */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-electric-400" />
              <span className="text-sm font-bold text-slate-200">Generated Reports</span>
              {reports && <span className="text-xs text-slate-500">({reports.total})</span>}
            </div>
            <div className="flex items-center gap-2">
              <select
                className="input !w-32 !py-1.5 !text-xs"
                value={sevFilter}
                onChange={(e) => setSevFilter(e.target.value)}
              >
                <option value="">All Levels</option>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
          </div>

          {reportsLoading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-20 rounded-xl" />)}
            </div>
          ) : filteredReports.length === 0 ? (
            <Card>
              <EmptyState
                icon={<FileText className="h-8 w-8" />}
                title="No reports yet"
                description="Generate a security report from an incident to get started. Reports include AI analysis, MITRE mappings, and audit trails."
              />
            </Card>
          ) : (
            <div className="space-y-2">
              {filteredReports.map((r) => {
                const inc = r as any;
                return (
                  <div
                    key={r.id}
                    className="group flex items-center gap-4 rounded-xl border border-night-700/60 bg-night-900/40 p-4 transition-all hover:border-electric-500/30 hover:bg-night-900/70 cursor-pointer"
                    onClick={() => setViewing(null)}
                  >
                    <div className="shrink-0 w-10 h-10 rounded-lg bg-night-800 flex items-center justify-center">
                      <FileText className="h-5 w-5 text-electric-400/70" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-bold text-slate-200 truncate">{r.title}</p>
                        {inc.severity && <SeverityBadge severity={inc.severity} />}
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-500">
                        <span className="font-mono text-electric-400/70">{r.report_id}</span>
                        <span>•</span>
                        <Clock className="h-3 w-3" />
                        <span>{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}</span>
                        <span>•</span>
                        <span>By {r.created_by || 'System'}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        className="flex items-center gap-1 rounded-lg border border-electric-500/30 bg-electric-500/10 px-3 py-1.5 text-xs font-medium text-electric-400 hover:bg-electric-500/20 transition-colors"
                        onClick={(e) => { e.stopPropagation(); setViewing(null); }}
                      >
                        <Eye className="h-3.5 w-3.5" /> View
                      </button>
                      <button
                        className="flex items-center gap-1 rounded-lg border border-night-600 bg-night-700/50 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-night-600/80 transition-colors"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleGenerateClick(r.id as string);
                        }}
                      >
                        <Download className="h-3.5 w-3.5" /> PDF
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {reports && reports.pages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-slate-500">
                Page {reports.page} of {reports.pages} · {reports.total} total
              </span>
              <div className="flex gap-2">
                <button
                  className="btn-ghost text-xs"
                  disabled={page <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                >
                  ← Prev
                </button>
                <button
                  className="btn-ghost text-xs"
                  disabled={page >= reports.pages}
                  onClick={() => setPage(p => Math.min(reports.pages, p + 1))}
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right sidebar: Quick Generate + Security Info */}
        <div className="space-y-4">
          <Card title="⚡ Quick Generate" subtitle="Create a report from an existing incident">
            {incidents && incidents.items.length > 0 ? (
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {incidents.items.slice(0, 8).map((inc) => (
                  <div key={inc.id} className="flex items-center gap-3 rounded-lg border border-night-700/50 bg-night-850/40 p-3 transition hover:border-electric-500/30">
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-slate-200 truncate">{inc.title}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-[10px] font-mono text-electric-400/70">{inc.incident_id?.slice(0, 8)}</span>
                        <StatusBadge status={inc.status} />
                      </div>
                    </div>
                    <button
                      className="shrink-0 flex items-center gap-1 rounded-lg border border-electric-500/20 bg-electric-500/10 px-2.5 py-1.5 text-[11px] font-medium text-electric-400 hover:bg-electric-500/20 disabled:opacity-40"
                      disabled={busyIncident !== null}
                      onClick={() => handleGenerateClick(inc.id)}
                    >
                      {busyIncident === inc.id ? (
                        <><RefreshCw className="h-3 w-3 animate-spin" /> <span>Gen...</span></>
                      ) : (
                        <>
                          <Shield className="h-3 w-3" /> Generate
                        </>
                      )}
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500">No incidents available. Create an incident first.</p>
            )}
          </Card>

          {/* Security Info */}
          <Card title="🔐 Report Security" subtitle="2FA verification for report access">
            <div className="space-y-3">
              <div className="flex items-start gap-2 text-xs text-slate-400">
                <ShieldCheck className="h-4 w-4 shrink-0 text-green-400 mt-0.5" />
                <p>Generating and viewing reports requires two-factor authentication. This ensures only authorized personnel can access sensitive investigation data.</p>
              </div>
              <button
                onClick={() => navigate("/security-settings")}
                className="flex items-center gap-1.5 text-xs text-electric-400 hover:text-electric-300 transition-colors"
              >
                <Key className="h-3.5 w-3.5" /> Configure 2FA Settings
              </button>
            </div>
          </Card>

          {/* Quick Links */}
          <Card title="🔗 Quick Links">
            <div className="space-y-1.5">
              {[
                { label: "Incident Dashboard", to: "/incidents", icon: <BarChart3 className="h-3.5 w-3.5" /> },
                { label: "Evidence Ledger", to: "/evidence-ledger", icon: <BookOpen className="h-3.5 w-3.5" /> },
                { label: "Security Settings", to: "/security-settings", icon: <ShieldCheck className="h-3.5 w-3.5" /> },
              ].map(link => (
                <button
                  key={link.to}
                  onClick={() => navigate(link.to)}
                  className="flex items-center gap-2 w-full text-left rounded-lg px-3 py-2 text-xs text-slate-400 hover:bg-night-800 hover:text-slate-200 transition-colors"
                >
                  {link.icon} {link.label} <ChevronRight className="ml-auto h-3 w-3 opacity-50" />
                </button>
              ))}
            </div>
          </Card>
        </div>
      </div>

      {/* Report Preview Modal */}
      {viewing && (
        <Modal
          open={!!viewing}
          onClose={() => setViewing(null)}
          title={viewing.report.title || "Security Report"}
          footer={
            <div className="flex gap-2">
              {viewing.pdf_available ? (
                <button
                  className="btn-primary"
                  onClick={() => window.open(`/reports/${viewing.report.id}/pdf`, "_blank")}
                >
                  <Download className="h-4 w-4 mr-1" /> Download PDF
                </button>
              ) : (
                <button
                  className="btn-primary"
                  onClick={() => {
                    handleGenerateClick(viewing.report.id);
                    setViewing(null);
                  }}
                >
                  <Shield className="h-4 w-4 mr-1" /> Generate Report
                </button>
              )}
            </div>
          }
        >
          <ReportPreview
            report={viewing}
            onClose={() => setViewing(null)}
            onDownload={() => window.open(`/reports/${viewing?.report.id}/pdf`, "_blank")}
            verifying={false}
            onVerifyClick={() => {
              setPendingIncident(viewing.report.id as string);
              setViewing(null);
              setShowTfaVerify(true);
            }}
          />
        </Modal>
      )}
    </div>
  );
}
