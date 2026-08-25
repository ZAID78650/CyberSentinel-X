import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, ArrowRight, Building2, CheckCircle2, ChevronRight, Clock, Eye, FileText, Loader2, MapPin, Shield, Target, TrendingUp, Users, Zap,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, Skeleton, StatCard } from "../components/ui";

/* ── Types ────────────────────────────────────────────────────────────── */

interface LeaData {
  alerts_summary: {
    total: number;
    critical: number;
    high: number;
    pending_action: number;
    actioned: number;
  };
  complaint_stats: {
    total: number;
    total_amount: number;
    high_risk_zones: number;
  };
  critical_alerts: Array<{
    alert_id: string;
    risk_level: string;
    risk_probability: number;
    confidence: number;
    predicted_zone: string;
    time_window: string;
    crime_pattern: string;
    related_complaints: number;
    state: string;
    district: string;
  }>;
  high_alerts: Array<{
    alert_id: string;
    risk_level: string;
    risk_probability: number;
    confidence: number;
    predicted_zone: string;
    time_window: string;
    crime_pattern: string;
    related_complaints: number;
    state: string;
    district: string;
  }>;
  recent_cases: Array<{
    complaint_id: string;
    fraud_type: string;
    amount: number;
    status: string;
    risk_score: number;
    location: string;
    time: string;
  }>;
  intervention_workflow: {
    current_stage: string;
    pipeline: Array<{
      stage: string;
      status: string;
      count: number;
    }>;
  };
}

interface BankAlert {
  alert_id: string;
  risk_level: string;
  risk_probability: number;
  predicted_zone: string;
  crime_pattern: string;
  confidence: number;
  related_complaints: number;
  time_window: string;
}

interface BankData {
  alerts: BankAlert[];
  bank_summary: Array<{
    bank: string;
    complaints: number;
    amount: number;
    fraud_types: number;
  }>;
}

/* ── Workflow Pipeline ────────────────────────────────────────────────── */

function InterventionPipeline({ pipeline }: { pipeline: LeaData["intervention_workflow"]["pipeline"] }) {
  return (
    <Card title="⚡ Proactive Intervention Pipeline" subtitle="From complaint to prevention — the CyberSentinel-X workflow">
      <div className="flex items-center gap-1 overflow-x-auto pb-2">
        {pipeline.map((stage, i) => {
          const isActive = stage.status === "active";
          const isCompleted = stage.status === "completed";
          const isPending = stage.status === "pending";
          const color = isCompleted ? "#4ade80" : isActive ? "#38bdf8" : "#64748b";

          return (
            <div key={stage.stage} className="flex items-center">
              <div className={`relative shrink-0 rounded-lg border px-4 py-3 text-center transition-all ${
                isActive ? "border-electric-500/50 bg-electric-500/10 shadow-glow" :
                isCompleted ? "border-cyber-green/30 bg-cyber-green/5" :
                "border-night-700 bg-night-850/50"
              }`}>
                <div className="flex items-center justify-center gap-1.5">
                  {isCompleted && <CheckCircle2 className="h-3.5 w-3.5 text-cyber-green" />}
                  {isActive && <Zap className="h-3.5 w-3.5 text-electric-400 animate-pulse" />}
                  <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color }}>{stage.stage}</span>
                </div>
                <p className="mt-1 font-mono text-lg font-bold" style={{ color }}>{stage.count}</p>
              </div>
              {i < pipeline.length - 1 && (
                <ArrowRight className="mx-1 h-4 w-4 shrink-0 text-slate-600" />
              )}
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-[11px] text-slate-600">
        The central story: <span className="font-semibold text-electric-400">Complaint → AI Prediction → Alert → Intervention → Potential Prevention</span>
      </p>
    </Card>
  );
}

/* ── Alert Row ────────────────────────────────────────────────────────── */

function AlertRow({ alert, priority }: { alert: any; priority: "critical" | "high" }) {
  const color = priority === "critical" ? "#f87171" : "#fb923c";
  return (
    <div className="flex items-center gap-3 rounded-lg border border-night-700/70 bg-night-850/50 px-4 py-3 transition hover:border-electric-500/30">
      <div className="relative shrink-0">
        <div className="flex h-8 w-8 items-center justify-center rounded-full" style={{ background: `${color}20`, border: `1.5px solid ${color}50` }}>
          <Target className="h-4 w-4" style={{ color }} />
        </div>
        {priority === "critical" && (
          <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full" style={{ background: color }}>
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" style={{ background: color }} />
          </span>
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] font-bold" style={{ color }}>{alert.alert_id}</span>
          <span className="badge border text-[9px]" style={{ borderColor: `${color}40`, background: `${color}10`, color }}>
            {(alert.risk_probability * 100).toFixed(0)}%
          </span>
        </div>
        <p className="mt-0.5 truncate text-xs font-medium text-slate-200">{alert.predicted_zone}</p>
        <p className="text-[10px] text-slate-500">{alert.crime_pattern} · {alert.time_window} · {alert.related_complaints} cases</p>
      </div>
      <div className="text-right">
        <p className="font-mono text-[10px] text-slate-500">{alert.state}</p>
        <p className="font-mono text-[10px] text-slate-600">conf: {(alert.confidence * 100).toFixed(0)}%</p>
      </div>
    </div>
  );
}

/* ── Main Page ────────────────────────────────────────────────────────── */

export default function LeaDashboard() {
  const [tab, setTab] = useState<"overview" | "alerts" | "bank">("overview");

  const { data: leaData, isLoading: leaLoading, error: leaError } = useQuery({
    queryKey: ["lea-dashboard"],
    queryFn: async () => (await api.get<LeaData>("/financial/lea/dashboard")).data,
  });

  const { data: bankData, isLoading: bankLoading } = useQuery({
    queryKey: ["bank-alerts"],
    queryFn: async () => (await api.get<BankData>("/financial/bank/alerts")).data,
    enabled: tab === "bank",
  });

  if (leaLoading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}</div>
        <Skeleton className="h-32" />
        <div className="grid gap-5 lg:grid-cols-2">{Array.from({ length: 2 }).map((_, i) => <Skeleton key={i} className="h-72" />)}</div>
      </div>
    );
  }

  if (leaError || !leaData) {
    return (
      <div className="glass p-8 text-center">
        <AlertTriangle className="mx-auto h-10 w-10 text-cyber-red" />
        <p className="mt-3 text-sm text-slate-300">Failed to load: {getErrorMessage(leaError)}</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Critical Alerts" value={leaData.alerts_summary.critical} color="#f87171" icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard label="Pending Action" value={leaData.alerts_summary.pending_action} color="#fb923c" icon={<Clock className="h-4 w-4" />} />
        <StatCard label="High Risk Zones" value={leaData.complaint_stats.high_risk_zones} color="#facc15" icon={<MapPin className="h-4 w-4" />} />
        <StatCard label="Total Cases" value={leaData.complaint_stats.total} color="#38bdf8" icon={<FileText className="h-4 w-4" />} />
      </div>

      {/* Intervention Pipeline */}
      <InterventionPipeline pipeline={leaData.intervention_workflow.pipeline} />

      {/* Tab navigation */}
      <div className="flex gap-1 rounded-lg border border-night-700/70 bg-night-850/50 p-1">
        {[
          { key: "overview" as const, label: "Overview", icon: <Eye className="h-3.5 w-3.5" /> },
          { key: "alerts" as const, label: "Alerts", icon: <AlertTriangle className="h-3.5 w-3.5" /> },
          { key: "bank" as const, label: "Bank/FI Alerts", icon: <Building2 className="h-3.5 w-3.5" /> },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-1.5 rounded-md px-3 py-2 text-xs font-semibold transition ${
              tab === t.key ? "bg-electric-500/10 text-electric-400" : "text-slate-500 hover:text-slate-300"
            }`}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "overview" && (
        <div className="grid gap-5 lg:grid-cols-2">
          {/* Critical alerts */}
          <Card title="🔴 Critical Alerts" subtitle="Immediate intervention required">
            <div className="space-y-2.5">
              {leaData.critical_alerts.length === 0 ? (
                <EmptyState title="No critical alerts" />
              ) : (
                leaData.critical_alerts.map((a) => <AlertRow key={a.alert_id} alert={a} priority="critical" />)
              )}
            </div>
          </Card>

          {/* High alerts */}
          <Card title="🟠 High Risk Alerts" subtitle="Elevated attention recommended">
            <div className="space-y-2.5">
              {leaData.high_alerts.length === 0 ? (
                <EmptyState title="No high risk alerts" />
              ) : (
                leaData.high_alerts.map((a) => <AlertRow key={a.alert_id} alert={a} priority="high" />)
              )}
            </div>
          </Card>
        </div>
      )}

      {tab === "alerts" && (
        <Card title="🚨 All Predictive Alerts" subtitle="Full alert list with filtering">
          <a href="/predictive-alerts" className="btn-primary">
            <Target className="h-4 w-4" /> Open Predictive Alerts Dashboard
          </a>
        </Card>
      )}

      {tab === "bank" && (
        <div className="space-y-5">
          {bankLoading ? (
            <Skeleton className="h-64" />
          ) : bankData ? (
            <>
              <Card title="🏦 Bank / FI Alert Summary" subtitle="Cybercrime alerts by financial institution">
                <div className="overflow-x-auto">
                  <table className="table-base">
                    <thead>
                      <tr>
                        <th>Bank</th>
                        <th>Complaints</th>
                        <th>Total Amount</th>
                        <th>Fraud Types</th>
                        <th>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bankData.bank_summary.map((b) => (
                        <tr key={b.bank}>
                          <td className="font-medium text-slate-200">{b.bank}</td>
                          <td className="font-mono text-xs">{b.complaints}</td>
                          <td className="font-mono text-xs">₹{(b.amount / 1000).toFixed(0)}K</td>
                          <td className="text-xs text-slate-400">{b.fraud_types} types</td>
                          <td>
                            <div className="h-2 w-20 overflow-hidden rounded-full bg-night-800">
                              <div className="h-full rounded-full bg-gradient-to-r from-cyber-green to-cyber-red" style={{ width: `${Math.min(100, b.complaints / 2)}%` }} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>

              <Card title="🚨 Bank/FI Alerts" subtitle="Alerts for financial institutions">
                <div className="space-y-2.5">
                  {bankData.alerts.slice(0, 10).map((a) => (
                    <div key={a.alert_id} className="flex items-center gap-3 rounded-lg border border-night-700/70 bg-night-850/50 px-3 py-2">
                      <span className="badge border text-[10px]" style={{
                        borderColor: a.risk_level === "CRITICAL" ? "rgba(248,113,113,0.4)" : a.risk_level === "HIGH" ? "rgba(251,146,60,0.4)" : "rgba(250,204,21,0.4)",
                        background: a.risk_level === "CRITICAL" ? "rgba(248,113,113,0.1)" : a.risk_level === "HIGH" ? "rgba(251,146,60,0.1)" : "rgba(250,204,21,0.1)",
                        color: a.risk_level === "CRITICAL" ? "#f87171" : a.risk_level === "HIGH" ? "#fb923c" : "#facc15",
                      }}>{a.risk_level}</span>
                      <span className="font-mono text-[10px] text-electric-400">{a.alert_id}</span>
                      <span className="flex-1 text-xs text-slate-200">{a.predicted_zone}</span>
                      <span className="text-[10px] text-slate-500">{a.crime_pattern}</span>
                    </div>
                  ))}
                </div>
              </Card>
            </>
          ) : null}
        </div>
      )}

      {/* Recent cases timeline */}
      <Card title="📋 Recent Cases Timeline" subtitle="Latest cybercrime complaints">
        <div className="space-y-2">
          {leaData.recent_cases.map((c) => {
            const riskColor = c.risk_score >= 0.85 ? "#f87171" : c.risk_score >= 0.6 ? "#fb923c" : c.risk_score >= 0.3 ? "#facc15" : "#4ade80";
            return (
              <div key={c.complaint_id} className="flex items-center gap-3 rounded-lg border border-night-800/60 px-3 py-2.5 transition hover:bg-night-850/40">
                <div className="h-2 w-2 shrink-0 rounded-full" style={{ background: riskColor }} />
                <span className="font-mono text-[10px] text-electric-400">{c.complaint_id}</span>
                <span className="flex-1 text-xs text-slate-200">{c.fraud_type}</span>
                <span className="text-xs text-slate-400">{c.location}</span>
                <span className="font-mono text-xs">₹{c.amount.toLocaleString()}</span>
                <span className="badge border text-[9px]" style={{
                  borderColor: c.status === "INVESTIGATING" ? "rgba(56,189,248,0.4)" : c.status === "RESOLVED" ? "rgba(74,222,128,0.4)" : "rgba(100,116,139,0.4)",
                  background: c.status === "INVESTIGATING" ? "rgba(56,189,248,0.1)" : c.status === "RESOLVED" ? "rgba(74,222,128,0.1)" : "rgba(100,116,139,0.1)",
                  color: c.status === "INVESTIGATING" ? "#38bdf8" : c.status === "RESOLVED" ? "#4ade80" : "#94a3b8",
                }}>{c.status}</span>
                <span className="text-[10px] text-slate-600">{new Date(c.time).toLocaleDateString()}</span>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}
