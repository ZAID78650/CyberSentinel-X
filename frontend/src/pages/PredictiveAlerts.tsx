import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Brain, CheckCircle2, Clock, Cpu, Eye, Loader2, Shield, Target, TrendingUp, X,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, Skeleton, StatCard } from "../components/ui";

/* ── Types ────────────────────────────────────────────────────────────── */

interface PredictiveAlert {
  alert_id: string;
  risk_level: string;
  risk_probability: number;
  confidence: number;
  predicted_zone: string;
  zone_id: string;
  time_window: string;
  crime_pattern: string;
  related_complaints: number;
  total_amount: number;
  model_version: string;
  latitude: number;
  longitude: number;
  state: string;
  district: string;
  contributing_features: Record<string, number>;
  is_actioned: boolean;
}

/* ── Alert Card (the hero component) ──────────────────────────────────── */

function AlertCard({ alert, onExpand }: { alert: PredictiveAlert; onExpand: () => void }) {
  const LEVEL_CONFIG: Record<string, { color: string; bg: string; border: string; label: string; pulse: boolean }> = {
    CRITICAL: { color: "#f87171", bg: "rgba(248,113,113,0.08)", border: "rgba(248,113,113,0.3)", label: "CRITICAL", pulse: true },
    HIGH: { color: "#fb923c", bg: "rgba(251,146,60,0.08)", border: "rgba(251,146,60,0.3)", label: "HIGH", pulse: true },
    MEDIUM: { color: "#facc15", bg: "rgba(250,204,21,0.06)", border: "rgba(250,204,21,0.25)", label: "MEDIUM", pulse: false },
    LOW: { color: "#4ade80", bg: "rgba(74,222,128,0.06)", border: "rgba(74,222,128,0.2)", label: "LOW", pulse: false },
  };
  const cfg = LEVEL_CONFIG[alert.risk_level] ?? LEVEL_CONFIG.MEDIUM;

  return (
    <div
      className="relative overflow-hidden rounded-xl border p-5 transition-all hover:shadow-lg cursor-pointer"
      style={{ background: cfg.bg, borderColor: cfg.border, boxShadow: `inset 0 0 40px ${cfg.bg}` }}
      onClick={onExpand}
    >
      {/* Top accent line */}
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: cfg.color, boxShadow: `0 0 12px ${cfg.color}` }} />

      {/* Pulse dot for critical/high */}
      {cfg.pulse && (
        <div className="absolute right-4 top-4">
          <span className="relative flex h-3 w-3">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" style={{ background: cfg.color }} />
            <span className="relative inline-flex h-3 w-3 rounded-full" style={{ background: cfg.color }} />
          </span>
        </div>
      )}

      {/* Header */}
      <div className="mb-3 flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg" style={{ background: `${cfg.color}20`, border: `1px solid ${cfg.color}40` }}>
          <Target className="h-5 w-5" style={{ color: cfg.color }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold" style={{ color: cfg.color }}>PREDICTIVE ALERT #{alert.alert_id}</span>
            {alert.is_actioned && <span className="badge border border-cyber-green/40 bg-cyber-green/10 text-cyber-green text-[9px]">ACTIONED</span>}
          </div>
          <p className="mt-0.5 text-sm font-bold text-slate-100">{alert.predicted_zone}</p>
        </div>
      </div>

      {/* Key metrics grid */}
      <div className="mb-3 grid grid-cols-2 gap-3">
        <MetricItem label="Risk Level" value={cfg.label} color={cfg.color} icon={<Shield className="h-3 w-3" />} />
        <MetricItem label="Confidence" value={`${(alert.confidence * 100).toFixed(1)}%`} color="#38bdf8" icon={<Brain className="h-3 w-3" />} />
        <MetricItem label="Time Window" value={alert.time_window} color="#a78bfa" icon={<Clock className="h-3 w-3" />} />
        <MetricItem label="Related Cases" value={String(alert.related_complaints)} color="#22d3ee" icon={<AlertTriangle className="h-3 w-3" />} />
      </div>

      {/* Bottom details */}
      <div className="flex items-center justify-between border-t pt-3" style={{ borderColor: `${cfg.color}20` }}>
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span className="flex items-center gap-1"><TrendingUp className="h-3 w-3" /> {alert.crime_pattern}</span>
          <span>·</span>
          <span>₹{(alert.total_amount / 1000).toFixed(0)}K total</span>
        </div>
        <span className="flex items-center gap-1 text-[10px] text-slate-600">
          <Cpu className="h-3 w-3" /> {alert.model_version}
        </span>
      </div>
    </div>
  );
}

function MetricItem({ label, value, color, icon }: { label: string; value: string; color: string; icon: React.ReactNode }) {
  return (
    <div className="rounded-lg bg-night-900/50 px-3 py-2">
      <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-500">
        <span style={{ color }}>{icon}</span> {label}
      </div>
      <p className="font-mono text-sm font-bold" style={{ color }}>{value}</p>
    </div>
  );
}

/* ── Alert Detail Modal ───────────────────────────────────────────────── */

function AlertDetailModal({ alertId, onClose }: { alertId: string; onClose: () => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ["prediction-detail", alertId],
    queryFn: async () => (await api.get<{ alert: PredictiveAlert; prediction_detail: any; recommended_actions: any[]; evidence_chain: any }>(`/financial/predictions/${alertId}`)).data,
  });

  const queryClient = useQueryClient();
  const [actioning, setActioning] = useState(false);

  const handleAction = async (action: string) => {
    setActioning(true);
    try {
      await api.post(`/financial/predictions/${alertId}/action?action=${action}`);
      await queryClient.invalidateQueries({ queryKey: ["predictions"] });
      onClose();
    } finally {
      setActioning(false);
    }
  };

  if (isLoading) return <Skeleton className="h-96" />;
  if (!data) return null;

  const { alert, prediction_detail, recommended_actions, evidence_chain } = data;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="glass max-h-[85vh] w-full max-w-3xl overflow-y-auto p-0" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-night-700/70 px-6 py-4">
          <div>
            <h2 className="text-sm font-bold text-slate-100">Alert #{alert.alert_id} — Full Analysis</h2>
            <p className="text-xs text-slate-500">Predictive withdrawal intelligence with explainability</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white"><X className="h-5 w-5" /></button>
        </div>

        <div className="space-y-5 p-6">
          {/* Risk meter */}
          <div className="flex items-center gap-6">
            <div className="relative h-24 w-24 shrink-0">
              <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="8" />
                <circle cx="50" cy="50" r="42" fill="none"
                  stroke={alert.risk_level === "CRITICAL" ? "#f87171" : alert.risk_level === "HIGH" ? "#fb923c" : "#facc15"}
                  strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={`${alert.risk_probability * 264} 264`} />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-mono text-xl font-bold text-slate-100">{(alert.risk_probability * 100).toFixed(0)}%</span>
                <span className="text-[8px] uppercase text-slate-500">probability</span>
              </div>
            </div>
            <div className="flex-1 space-y-1.5 text-xs">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Model Explanation</p>
              <p className="leading-relaxed text-slate-400">{prediction_detail?.explanation}</p>
            </div>
          </div>

          {/* Feature contributions */}
          <div>
            <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Feature Contributions</p>
            <div className="space-y-1.5">
              {prediction_detail?.feature_contributions?.slice(0, 6).map((fc: any) => (
                <div key={fc.feature} className="flex items-center gap-3 rounded bg-night-900/40 px-3 py-1.5 text-[11px]">
                  <span className="w-32 truncate text-slate-400">{fc.feature.replace(/_/g, " ")}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-night-800">
                    <div className="h-full rounded-full bg-electric-500" style={{ width: `${fc.value * 100}%` }} />
                  </div>
                  <span className="w-12 text-right font-mono text-slate-300">{fc.value.toFixed(3)}</span>
                  <span className="w-12 text-right font-mono text-electric-400">{fc.contribution.toFixed(4)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Recommended actions */}
          <div>
            <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Recommended Actions</p>
            <div className="space-y-2">
              {recommended_actions?.map((ra: any, i: number) => (
                <div key={i} className="flex items-center gap-3 rounded-lg border border-night-700/70 bg-night-850/50 px-3 py-2">
                  <span className={`badge border text-[9px] ${
                    ra.priority === "HIGH" ? "border-cyber-red/40 bg-cyber-red/10 text-cyber-red" :
                    ra.priority === "MEDIUM" ? "border-cyber-orange/40 bg-cyber-orange/10 text-cyber-orange" :
                    "border-cyber-green/40 bg-cyber-green/10 text-cyber-green"
                  }`}>{ra.priority}</span>
                  <span className="flex-1 text-xs text-slate-300">{ra.action}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence chain */}
          <div className="rounded-lg border border-cyber-purple/30 bg-cyber-purple/5 p-3">
            <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-cyber-purple">🔒 Evidence Integrity Chain</p>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div><span className="text-slate-500">Prediction Hash:</span> <span className="font-mono text-slate-300">{evidence_chain?.prediction_hash}</span></div>
              <div><span className="text-slate-500">Model:</span> <span className="font-mono text-slate-300">{evidence_chain?.model_version}</span></div>
              <div><span className="text-slate-500">Timestamp:</span> <span className="font-mono text-slate-300">{new Date(evidence_chain?.timestamp).toLocaleString()}</span></div>
              <div><span className="text-slate-500">Features:</span> <span className="font-mono text-slate-300">{Object.keys(evidence_chain?.features_snapshot ?? {}).length} used</span></div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-2 border-t border-night-700/70 pt-4">
            <button className="btn-ghost" onClick={onClose}>Close</button>
            <button className="btn-ghost" onClick={() => handleAction("escalate")} disabled={actioning}>
              <AlertTriangle className="h-4 w-4" /> Escalate
            </button>
            <button className="btn-primary" onClick={() => handleAction("acknowledge")} disabled={actioning}>
              {actioning ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
              Acknowledge
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Main Page ────────────────────────────────────────────────────────── */

export default function PredictiveAlerts() {
  const [filterLevel, setFilterLevel] = useState("");
  const [filterState, setFilterState] = useState("");
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["predictions", filterLevel, filterState],
    queryFn: async () => {
      const params: Record<string, string | number> = { limit: 30 };
      if (filterLevel) params.risk_level = filterLevel;
      if (filterState) params.state = filterState;
      return (await api.get<{ alerts: PredictiveAlert[]; total: number; model_version: string }>("/financial/predictions", { params })).data;
    },
  });

  const alerts = data?.alerts ?? [];
  const criticalCount = alerts.filter((a) => a.risk_level === "CRITICAL").length;
  const highCount = alerts.filter((a) => a.risk_level === "HIGH").length;
  const pendingCount = alerts.filter((a) => !a.is_actioned).length;

  return (
    <div className="space-y-5">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total Predictions" value={data?.total ?? 0} color="#38bdf8" icon={<Brain className="h-4 w-4" />} />
        <StatCard label="Critical Alerts" value={criticalCount} color="#f87171" icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard label="High Risk" value={highCount} color="#fb923c" icon={<TrendingUp className="h-4 w-4" />} />
        <StatCard label="Pending Action" value={pendingCount} color="#a78bfa" icon={<Clock className="h-4 w-4" />} />
      </div>

      {/* Filters */}
      <Card
        title="🚨 Predictive Withdrawal Alerts"
        subtitle="AI-predicted high-risk withdrawal zones with confidence scores"
        actions={
          <div className="flex items-center gap-2">
            <select className="input !w-36 !py-1.5 text-xs" value={filterLevel} onChange={(e) => setFilterLevel(e.target.value)}>
              <option value="">All Levels</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
            <select className="input !w-44 !py-1.5 text-xs" value={filterState} onChange={(e) => setFilterState(e.target.value)}>
              <option value="">All States</option>
              {["Maharashtra", "Delhi", "Karnataka", "Tamil Nadu", "Uttar Pradesh", "Gujarat", "West Bengal"].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        }
      >
        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-48" />)}</div>
        ) : error ? (
          <EmptyState icon={<AlertTriangle className="h-8 w-8" />} title="Failed to load predictions" description={getErrorMessage(error)} />
        ) : alerts.length === 0 ? (
          <EmptyState icon={<Brain className="h-8 w-8" />} title="No predictions" description="Generate financial crime data to see predictions." />
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            {alerts.map((alert) => (
              <AlertCard key={alert.alert_id} alert={alert} onExpand={() => setExpandedAlert(alert.alert_id)} />
            ))}
          </div>
        )}
      </Card>

      {/* Explanation panel */}
      <Card title="ℹ️ Understanding Predictions" subtitle="How the model works and what probabilities mean">
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            { title: "Risk Probability", desc: "The model's estimated probability of high-risk withdrawal activity in this zone. 84% means the model is 84% confident — NOT that there's an 84% chance of crime.", color: "#38bdf8", icon: <Brain className="h-4 w-4" /> },
            { title: "Confidence Score", desc: "How certain the model is about its own prediction, based on data quality and feature coverage. Higher confidence means more reliable prediction.", color: "#a78bfa", icon: <Eye className="h-4 w-4" /> },
            { title: "Feature Contributions", desc: "Each input feature (complaint density, transaction volume, etc.) contributes to the final risk score. The top contributors explain WHY the zone is flagged.", color: "#22d3ee", icon: <TrendingUp className="h-4 w-4" /> },
          ].map((item) => (
            <div key={item.title} className="rounded-lg border border-night-700/70 bg-night-850/50 p-4">
              <div className="flex items-center gap-2" style={{ color: item.color }}>
                {item.icon}
                <p className="text-xs font-bold">{item.title}</p>
              </div>
              <p className="mt-2 text-[11px] leading-relaxed text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </Card>

      {/* Detail modal */}
      {expandedAlert && (
        <AlertDetailModal alertId={expandedAlert} onClose={() => setExpandedAlert(null)} />
      )}
    </div>
  );
}
