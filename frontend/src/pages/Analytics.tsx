import { useQuery } from "@tanstack/react-query";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { BarChart3, ShieldCheck } from "lucide-react";
import { api } from "../services/api";
import { AccuracyGauge, Card, Skeleton } from "../components/ui";
import type { Analytics as AnalyticsData } from "../types";

const SEV_COLORS: Record<string, string> = { CRITICAL: "#f87171", HIGH: "#fb923c", MEDIUM: "#facc15", LOW: "#4ade80" };
const PIE_COLORS = ["#38bdf8", "#a78bfa", "#f87171", "#4ade80", "#facc15", "#fb923c", "#22d3ee", "#f472b6"];

export default function Analytics() {
  const { data, isLoading } = useQuery({
    queryKey: ["analytics"],
    queryFn: async () => (await api.get<AnalyticsData>("/analytics")).data,
  });

  if (isLoading || !data) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4"><Skeleton className="h-24" /><Skeleton className="h-24" /><Skeleton className="h-24" /><Skeleton className="h-24" /></div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  const sevData = Object.entries(data.alerts_by_severity).map(([name, value]) => ({ name, value }));
  const typeData = Object.entries(data.events_by_type).map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value).slice(0, 10);
  const riskData = data.risk_over_time.length ? data.risk_over_time : [{ date: "today", avg_risk: 0 }];
  const incidentStatus = Object.entries(data.incidents_by_status).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <BarChart3 className="h-5 w-5 text-electric-400" />
        <h2 className="text-lg font-bold text-slate-100">Analytics</h2>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[
          { label: "Total Events", value: data.events_total, color: "#38bdf8" },
          { label: "Total Alerts", value: data.alerts_total, color: "#fb923c" },
          { label: "Total Incidents", value: data.incidents_total, color: "#f87171" },
          { label: "Audit Actions", value: data.actions_executed, color: "#4ade80" },
        ].map((k) => (
          <div key={k.label} className="glass glass-hover p-4">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{k.label}</p>
            <p className="font-mono text-3xl font-semibold" style={{ color: k.color }}>{k.value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      {/* Detection accuracy panel */}
      {data.detection_accuracy && (
        <Card
          title="Detection Engine Accuracy"
          subtitle={`Measured live on ${data.detection_accuracy.total_events} labeled events (${data.detection_accuracy.attack_events} attack / ${data.detection_accuracy.benign_events} benign) · ${data.detection_accuracy.method}`}
          actions={
            <span className="flex items-center gap-1.5 text-xs text-cyber-green">
              <ShieldCheck className="h-3.5 w-3.5" /> Model verified
            </span>
          }
        >
          <div className="flex flex-wrap items-center justify-between gap-6">
            <AccuracyGauge
              accuracy={data.detection_accuracy.accuracy}
              precision={data.detection_accuracy.precision}
              recall={data.detection_accuracy.recall}
              f1={data.detection_accuracy.f1}
            />
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "True Positives", value: data.detection_accuracy.true_positives, color: "#4ade80" },
                { label: "True Negatives", value: data.detection_accuracy.true_negatives, color: "#38bdf8" },
                { label: "False Positives", value: data.detection_accuracy.false_positives, color: "#fb923c" },
                { label: "False Negatives", value: data.detection_accuracy.false_negatives, color: "#f87171" },
              ].map((m) => (
                <div key={m.label} className="rounded-lg border border-night-700 bg-night-850/50 px-4 py-2.5 text-center">
                  <p className="font-mono text-xl font-bold" style={{ color: m.color }}>{m.value}</p>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{m.label}</p>
                </div>
              ))}
            </div>
          </div>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Risk Score Over Time" subtitle="Daily average risk">
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={riskData}>
              <defs>
                <linearGradient id="ar" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f87171" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
              <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: "#0d1526", border: "1px solid #1a2540", borderRadius: 8 }} />
              <Area type="monotone" dataKey="avg_risk" stroke="#f87171" strokeWidth={2} fill="url(#ar)" />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Events by Type" subtitle="Top 10 event types">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={typeData} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
              <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={10} width={130} />
              <Tooltip contentStyle={{ background: "#0d1526", border: "1px solid #1a2540", borderRadius: 8 }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]} fill="#38bdf8" />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Alerts by Severity">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={sevData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#0d1526", border: "1px solid #1a2540", borderRadius: 8 }} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {sevData.map((s) => <Cell key={s.name} fill={SEV_COLORS[s.name] ?? "#38bdf8"} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Incidents by Status">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={incidentStatus} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                {incidentStatus.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "#0d1526", border: "1px solid #1a2540", borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Top Threat Sources">
          <div className="space-y-2.5">
            {data.top_threat_sources.map((s) => (
              <div key={s.source} className="flex items-center gap-3">
                <span className="w-32 truncate font-mono text-[11px] text-slate-400">{s.source}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-night-800">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-electric-500 to-cyber-red"
                    style={{ width: `${(s.count / Math.max(1, data.top_threat_sources[0].count)) * 100}%` }}
                  />
                </div>
                <span className="w-8 text-right font-mono text-xs">{s.count}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Top ATT&CK Techniques">
          <div className="space-y-2.5">
            {data.top_attack_techniques.map((t) => (
              <div key={t.technique_id} className="flex items-center gap-3">
                <span className="font-mono text-xs font-bold text-electric-400">{t.technique_id}</span>
                <span className="flex-1 truncate text-xs text-slate-300">{t.name}</span>
                <span className="text-[10px] uppercase text-slate-600">{t.tactic}</span>
                <span className="w-8 text-right font-mono text-xs">{t.count}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
