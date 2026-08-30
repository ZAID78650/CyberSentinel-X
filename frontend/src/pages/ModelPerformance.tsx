import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, Cpu, GitBranch, LineChart,
  RefreshCcw, Shield, Target, TrendingUp, Zap,
} from "lucide-react";
import {
  Bar, BarChart, CartesianGrid, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api } from "../services/api";
import { Card, EmptyState, Skeleton, StatCard } from "../components/ui";

/* ── Types ─────────────────────────────────────────────────────────────── */

interface ModelInfo {
  models: Record<string, {
    model_name: string;
    version: string;
    feature_version: string;
    trained_at: string;
    training_samples: number;
    feature_importance: Record<string, number>;
  }>;
  performance: Record<string, any>;
  feature_importance: {
    top_features: Array<{ name: string; importance: number }>;
    total_features: number;
  };
  model_info: {
    classification: { algorithm: string; strategy: string; class_weights: string; };
    regression: { algorithm: string; strategy: string; };
    anomaly_detection: { algorithms: string[]; ensemble_strategy: string; };
    geospatial: { algorithm: string; clustering: string; };
  };
  data_leakage_prevention: Record<string, any>;
  evaluation_metrics: Record<string, any>;
  timestamp: string;
}

interface DriftData {
  drift_level: string;
  status: string;
  psi: number;
  kl_divergence: number;
  brier_score: number;
  reference_samples: number;
  current_samples: number;
  thresholds: Record<string, number>;
  recommendation: string[];
}

/* ── Color Palette ─────────────────────────────────────────────────────── */

const COLORS = ['#38bdf8', '#a78bfa', '#f87171', '#4ade80', '#facc15', '#fb923c', '#22d3ee', '#e879f9', '#34d399', '#f472b6'];

const ChartTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-night-700 bg-night-900/95 px-3 py-2 font-mono text-[11px] shadow-panel backdrop-blur">
      {label && <p className="mb-1 text-slate-400">{label}</p>}
      {payload.map((p: any, i: number) => (
        <p key={i} className="flex items-center gap-2 text-slate-200">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color }} />
          {p.name}: <b>{typeof p.value === 'number' ? p.value.toFixed(4) : p.value}</b>
        </p>
      ))}
    </div>
  );
};

/* ── Main Component ────────────────────────────────────────────────────── */

export default function ModelPerformance() {
  const [showDrift, setShowDrift] = useState(false);

  const { data: modelData, isLoading: modelLoading, refetch: refetchModel } = useQuery({
    queryKey: ['model-info-v2'],
    queryFn: async () => (await api.get('/v2/model/info')).data as ModelInfo,
  });

  const { data: driftData, isLoading: driftLoading, refetch: refetchDrift } = useQuery({
    queryKey: ['model-drift'],
    queryFn: async () => (await api.get('/v2/model/drift')).data as DriftData,
    enabled: showDrift,
  });

  const { data: perfData, isLoading: perfLoading } = useQuery({
    queryKey: ['performance-bench'],
    queryFn: async () => (await api.get('/v2/monitoring/performance')).data,
  });

  if (modelLoading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-80" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (!modelData) {
    return (
      <div className="glass p-8 text-center">
        <AlertTriangle className="mx-auto h-10 w-10 text-cyber-red" />
        <p className="mt-3 text-sm text-slate-300">Failed to load model data</p>
        <button className="btn-ghost mt-3" onClick={() => refetchModel()}>Retry</button>
      </div>
    );
  }

  const { models, performance, feature_importance, model_info, data_leakage_prevention } = modelData;
  const featureImportanceData = feature_importance.top_features.map(f => ({
    name: f.name.replace(/_/g, ' '),
    value: f.importance,
  }));

  const accuracy = performance.classification?.accuracy
    ? (performance.classification.accuracy * 100).toFixed(1)
    : '0.0';
  const precision = performance.classification?.precision
    ? (performance.classification.precision * 100).toFixed(1)
    : '0.0';
  const recall = performance.classification?.recall
    ? (performance.classification.recall * 100).toFixed(1)
    : '0.0';
  const f1Score = performance.classification?.f1
    ? (performance.classification.f1 * 100).toFixed(1)
    : '0.0';

  const driftColor = (level: string) =>
    level === 'HIGH' ? '#f87171' : level === 'MODERATE' ? '#facc15' : '#4ade80';

  return (
    <div className="space-y-5">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Model Accuracy" value={`${accuracy}%`} color="#4ade80" icon={<Target className="h-4 w-4" />} />
        <StatCard label="Precision" value={`${precision}%`} color="#38bdf8" icon={<Shield className="h-4 w-4" />} />
        <StatCard label="Recall" value={`${recall}%`} color="#a78bfa" icon={<TrendingUp className="h-4 w-4" />} />
        <StatCard label="F1 Score" value={`${f1Score}%`} color="#fb923c" icon={<Zap className="h-4 w-4" />} />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Model Info */}
        <Card
          title="ML Ensemble Architecture"
          subtitle="Model versions and training details"
          actions={<button className="btn-ghost" onClick={() => refetchModel()}><RefreshCcw className="h-3.5 w-3.5" /></button>}
        >
          <div className="space-y-3">
            {Object.entries(model_info).map(([key, info]: [string, any]) => (
              <div key={key} className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-electric-400" />
                    <span className="text-xs font-bold uppercase tracking-wide text-slate-200">
                      {key.replace(/_/g, ' ')}
                    </span>
                  </div>
                  {models[key] && (
                    <span className="font-mono text-[10px] text-slate-500">v{models[key].version}</span>
                  )}
                </div>
                <div className="mt-2 space-y-1 text-[11px] text-slate-400">
                  <div><span className="text-slate-500">Algorithm:</span> {info.algorithm}</div>
                  <div><span className="text-slate-500">Strategy:</span> {info.strategy}</div>
                  {info.class_weights && (
                    <div><span className="text-slate-500">Balance:</span> {info.class_weights}</div>
                  )}
                  {models[key] && (
                    <div><span className="text-slate-500">Trained on:</span> {models[key].training_samples?.toLocaleString()} samples ({new Date(models[key].trained_at).toLocaleString()})</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Feature Importance */}
        <Card
          title="Feature Importance"
          subtitle={`Top ${feature_importance.top_features.length} of ${feature_importance.total_features} features`}
        >
          <ResponsiveContainer width="100%" height={350}>
            <BarChart data={featureImportanceData} layout="vertical" margin={{ top: 5, right: 30, left: 120, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" horizontal={false} />
              <XAxis type="number" domain={[0, 1]} tickFormatter={(v: number) => v.toFixed(2)} stroke="#64748b" fontSize={10} />
              <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} width={120} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="value" name="Importance" radius={[0, 4, 4, 0]} animationDuration={800}>
                {featureImportanceData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} fillOpacity={0.8} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Evaluation Metrics */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* Classification */}
        <Card title="Classification Metrics" subtitle="Evaluated on time-split test set">
          <div className="space-y-3">
            {[
              { label: 'Accuracy', value: performance.classification?.accuracy, format: 'pct' },
              { label: 'Precision', value: performance.classification?.precision, format: 'pct' },
              { label: 'Recall', value: performance.classification?.recall, format: 'pct' },
              { label: 'F1 Score', value: performance.classification?.f1, format: 'pct' },
              { label: 'ROC AUC', value: performance.classification?.roc_auc, format: 'num' },
            ].map(m => (
              <div key={m.label} className="flex items-center justify-between rounded bg-night-850/50 px-3 py-2">
                <span className="text-xs text-slate-400">{m.label}</span>
                <span className="font-mono text-sm font-bold text-electric-400">
                  {m.value != null ? (m.format === 'pct' ? `${(m.value * 100).toFixed(1)}%` : m.value.toFixed(4)) : '—'}
                </span>
              </div>
            ))}
            {performance.classification?.class_distribution && (
              <div className="mt-2">
                <p className="mb-1 text-[10px] text-slate-500">Class Distribution</p>
                {Object.entries(performance.classification.class_distribution).map(([k, v]: any) => (
                  <div key={k} className="flex items-center gap-2 text-[11px]">
                    <span className="w-16 text-slate-400">{k}</span>
                    <div className="h-1.5 flex-1 bg-night-800 rounded-full overflow-hidden">
                      <div className="h-full rounded-full bg-electric-500" style={{ width: `${(v / Math.max(...Object.values(performance.classification.class_distribution) as number[])) * 100}%` }} />
                    </div>
                    <span className="w-8 font-mono text-slate-300">{v}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>

        {/* Performance Benchmarks */}
        <Card title="Performance Benchmarks" subtitle="Prediction latency percentiles">
          {perfLoading ? (
            <Skeleton className="h-40" />
          ) : perfData?.latency_ms ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'P50', value: perfData.latency_ms.median, color: '#4ade80' },
                  { label: 'P90', value: perfData.latency_ms.p90, color: '#38bdf8' },
                  { label: 'P95', value: perfData.latency_ms.p95, color: '#facc15' },
                  { label: 'P99', value: perfData.latency_ms.p99, color: '#f87171' },
                ].map(p => (
                  <div key={p.label} className="rounded bg-night-850/50 p-3 text-center">
                    <p className="text-[10px] uppercase text-slate-500">{p.label}</p>
                    <p className="font-mono text-lg font-bold" style={{ color: p.color }}>{p.value}ms</p>
                  </div>
                ))}
              </div>
              <div className="rounded bg-night-850/50 p-3 text-center">
                <p className="text-[10px] uppercase text-slate-500">Throughput</p>
                <p className="font-mono text-lg font-bold text-cyber-green">{perfData.throughput_per_second} pred/s</p>
              </div>
              <p className="text-[10px] text-slate-500">
                Sample size: {perfData.sample_size} predictions · Model: {perfData.model}
              </p>
            </div>
          ) : (
            <EmptyState title="No performance data" />
          )}
        </Card>

        {/* Model Drift */}
        <Card
          title="Model Drift Monitor"
          subtitle="Population stability and distribution drift"
          actions={
            <button className="btn-ghost" onClick={() => { setShowDrift(true); refetchDrift(); }}>
              <RefreshCcw className="h-3.5 w-3.5" />
            </button>
          }
        >
          {driftLoading ? (
            <Skeleton className="h-40" />
          ) : driftData && driftData.drift_level ? (
            <div className="space-y-3">
              <div className="rounded-lg p-4 text-center" style={{ background: `${driftColor(driftData.drift_level)}15`, border: `1px solid ${driftColor(driftData.drift_level)}30` }}>
                <p className="text-sm font-bold" style={{ color: driftColor(driftData.drift_level) }}>{driftData.drift_level}</p>
                <p className="mt-1 text-xs text-slate-400">{driftData.status}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded bg-night-850/50 p-2.5 text-center">
                  <p className="text-[10px] text-slate-500">PSI</p>
                  <p className="font-mono text-lg font-bold text-slate-200">{driftData.psi}</p>
                </div>
                <div className="rounded bg-night-850/50 p-2.5 text-center">
                  <p className="text-[10px] text-slate-500">KL Divergence</p>
                  <p className="font-mono text-lg font-bold text-slate-200">{driftData.kl_divergence}</p>
                </div>
              </div>
              {driftData.recommendation && (
                <div className="space-y-1">
                  {driftData.recommendation.map((r: string, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-[11px] text-slate-400">
                      <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyber-yellow" />
                      {r}
                    </div>
                  ))}
                </div>
              )}
              <p className="text-[10px] text-slate-500">
                Reference: {driftData.reference_samples} | Current: {driftData.current_samples}
              </p>
            </div>
          ) : (
            <div className="text-center">
              <button className="btn-ghost" onClick={() => { setShowDrift(true); refetchDrift(); }}>
                <LineChart className="h-4 w-4" /> Run Drift Detection
              </button>
            </div>
          )}
        </Card>
      </div>

      {/* Data Leakage Prevention */}
      <Card title="🛡️ Data Leakage Prevention" subtitle="How model validity is maintained">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {[
            { label: 'Strategy', value: data_leakage_prevention?.strategy, icon: <Shield className="h-4 w-4 text-cyber-green" /> },
            { label: 'Feature Version', value: data_leakage_prevention?.feature_version, icon: <GitBranch className="h-4 w-4 text-electric-400" /> },
            { label: 'Note', value: data_leakage_prevention?.note, icon: <AlertTriangle className="h-4 w-4 text-cyber-yellow" /> },
          ].map(item => (
            <div key={item.label} className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <div className="flex items-center gap-2 mb-1">
                {item.icon}
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{item.label}</span>
              </div>
              <p className="text-xs text-slate-400">{item.value}</p>
            </div>
          ))}
        </div>
      </Card>

      {/* Model Capabilities */}
      <Card title="🎯 Model Capabilities & Evaluation" subtitle="Comprehensive model quality assessment">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          {Object.entries(modelData.evaluation_metrics).map(([category, metrics]: [string, any]) => (
            <div key={category} className="rounded-lg border border-night-700/70 bg-night-850/50 p-4">
              <h4 className="mb-2 text-xs font-bold uppercase tracking-wider text-slate-300">{category.replace(/_/g, ' ')}</h4>
              {metrics.metrics && (
                <div className="space-y-1">
                  {metrics.metrics.map((m: string) => (
                    <div key={m} className="flex items-center gap-2 text-[11px] text-slate-400">
                      <span className="h-1 w-1 rounded-full bg-electric-400" />
                      {m.replace(/_/g, ' ')}
                    </div>
                  ))}
                </div>
              )}
              {metrics.method && (
                <p className="mt-1 text-[10px] text-slate-500">Method: {metrics.method}</p>
              )}
              {metrics.balance_strategy && (
                <p className="mt-1 text-[10px] text-slate-500">Strategy: {metrics.balance_strategy}</p>
              )}
              {metrics.purpose && (
                <p className="mt-1 text-[10px] text-slate-500">Purpose: {metrics.purpose}</p>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
