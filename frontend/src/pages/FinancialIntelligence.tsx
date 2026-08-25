import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, BarChart3, Brain, ChevronRight, CreditCard, DollarSign, Globe, Layers, MapPin, RefreshCw, TrendingUp,
} from "lucide-react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, Skeleton, StatCard } from "../components/ui";

/* ── Chart Tooltip ────────────────────────────────────────────────────── */

function ChartTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: Array<{ name: string; value: number | string; color: string }>;
  label?: string | number;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-night-700 bg-night-900/95 px-3 py-2 font-mono text-[11px] shadow-panel backdrop-blur">
      {label !== undefined && <p className="mb-1 text-slate-400">{String(label)}</p>}
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2 text-slate-200">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color }} />
          {p.name}: <b>{typeof p.value === "number" ? p.value.toLocaleString() : p.value}</b>
        </p>
      ))}
    </div>
  );
}

/* ── Types ────────────────────────────────────────────────────────────── */

interface FinancialDashboardData {
  summary: {
    total_complaints: number;
    total_amount: number;
    avg_complaint_amount: number;
    high_risk_zones: number;
    total_zones: number;
    suspicious_transactions: number;
    active_alerts: number;
    unique_accounts: number;
  };
  time_series: Array<{ month: string; complaints: number; amount: number }>;
  fraud_breakdown: Array<{ type: string; count: number; percentage: number }>;
  state_breakdown: Array<{ state: string; count: number }>;
  risk_distribution: Record<string, number>;
  top_alerts: Array<{
    alert_id: string;
    risk_level: string;
    risk_probability: number;
    predicted_zone: string;
    crime_pattern: string;
    confidence: number;
    related_complaints: number;
  }>;
}

/* ── Color Palette ────────────────────────────────────────────────────── */

const PIE_COLORS = ["#38bdf8", "#a78bfa", "#f87171", "#4ade80", "#facc15", "#fb923c", "#22d3ee", "#e879f9", "#34d399", "#f472b6", "#818cf8", "#fbbf24"];
const RISK_COLORS: Record<string, string> = { CRITICAL: "#f87171", HIGH: "#fb923c", MEDIUM: "#facc15", LOW: "#4ade80" };

/* ── Main Page ────────────────────────────────────────────────────────── */

export default function FinancialIntelligence() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["financial-dashboard"],
    queryFn: async () => (await api.get<FinancialDashboardData>("/financial/dashboard")).data,
  });

  if (isLoading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}</div>
        <div className="grid gap-5 lg:grid-cols-2">{Array.from({ length: 2 }).map((_, i) => <Skeleton key={i} className="h-72" />)}</div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="glass p-8 text-center">
        <AlertTriangle className="mx-auto h-10 w-10 text-cyber-red" />
        <p className="mt-3 text-sm text-slate-300">Failed to load: {getErrorMessage(error)}</p>
        <button className="btn-ghost mt-4" onClick={() => refetch()}>Retry</button>
      </div>
    );
  }

  const { summary, time_series, fraud_breakdown, state_breakdown, risk_distribution, top_alerts } = data;
  const riskData = Object.entries(risk_distribution).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-5">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total Complaints" value={summary.total_complaints} color="#38bdf8" icon={<AlertTriangle className="h-4 w-4" />} hint="Cybercrime complaints filed" />
        <StatCard label="Total Amount at Risk" value={`₹${(summary.total_amount / 100000).toFixed(1)}L`} color="#f87171" icon={<DollarSign className="h-4 w-4" />} hint="Cumulative fraud amount" />
        <StatCard label="High Risk Zones" value={summary.high_risk_zones} color="#fb923c" icon={<MapPin className="h-4 w-4" />} hint={`of ${summary.total_zones} total zones`} />
        <StatCard label="Active Alerts" value={summary.active_alerts} color="#a78bfa" icon={<Brain className="h-4 w-4" />} hint="Predictive withdrawal alerts" />
      </div>

      {/* Time series + risk distribution */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="📈 Complaint Trend" subtitle="Monthly complaint volume and amount">
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={time_series} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <defs>
                <linearGradient id="complaintGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="amountGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f87171" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#f87171" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" vertical={false} />
              <XAxis dataKey="month" stroke="#64748b" fontSize={10} tickLine={false} axisLine={{ stroke: "#1a2540" }} />
              <YAxis yAxisId="left" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis yAxisId="right" orientation="right" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Area yAxisId="left" type="monotone" dataKey="complaints" name="Complaints" stroke="#38bdf8" strokeWidth={2} fill="url(#complaintGrad)" dot={{ r: 3, fill: "#38bdf8" }} />
              <Area yAxisId="right" type="monotone" dataKey="amount" name="Amount (₹)" stroke="#f87171" strokeWidth={2} fill="url(#amountGrad)" dot={{ r: 3, fill: "#f87171" }} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="🎯 Risk Zone Distribution" subtitle="Zone risk level breakdown">
          <div className="flex items-center gap-6">
            <ResponsiveContainer width="50%" height={220}>
              <PieChart>
                <Pie data={riskData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={85} paddingAngle={3} stroke="none" animationDuration={700}>
                  {riskData.map((r) => (
                    <Cell key={r.name} fill={RISK_COLORS[r.name] ?? "#64748b"} style={{ filter: `drop-shadow(0 0 5px ${RISK_COLORS[r.name] ?? "#64748b"})` }} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-3">
              {riskData.map((r) => (
                <div key={r.name} className="flex items-center gap-3">
                  <span className="h-3 w-3 rounded-full" style={{ background: RISK_COLORS[r.name] }} />
                  <div>
                    <p className="text-xs font-semibold text-slate-200">{r.name}</p>
                    <p className="font-mono text-[10px] text-slate-500">{r.value} zones</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Fraud type + state breakdown */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="🏷️ Fraud Type Breakdown" subtitle="Distribution by cybercrime category">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={fraud_breakdown} layout="vertical" margin={{ top: 6, right: 20, left: 10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" horizontal={false} />
              <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} axisLine={{ stroke: "#1a2540" }} />
              <YAxis dataKey="type" type="category" stroke="#64748b" fontSize={9} tickLine={false} axisLine={false} width={120} />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(56,189,248,0.06)" }} />
              <Bar dataKey="count" name="Complaints" radius={[0, 6, 6, 0]} animationDuration={700}>
                {fraud_breakdown.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card title="🗺️ State Distribution" subtitle="Top states by complaint volume">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={state_breakdown} margin={{ top: 6, right: 6, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" vertical={false} />
              <XAxis dataKey="state" stroke="#64748b" fontSize={9} tickLine={false} axisLine={{ stroke: "#1a2540" }} angle={-35} textAnchor="end" height={70} />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(56,189,248,0.06)" }} />
              <Bar dataKey="count" name="Complaints" radius={[6, 6, 0, 0]} animationDuration={700}>
                {state_breakdown.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Top alerts table */}
      <Card
        title="🚨 Top Predictive Alerts"
        subtitle="Highest risk predicted withdrawal zones"
        actions={<a href="/predictive-alerts" className="text-xs font-semibold text-electric-400 hover:underline">View all <ChevronRight className="inline h-3 w-3" /></a>}
      >
        {top_alerts.length === 0 ? (
          <EmptyState title="No alerts yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Zone</th>
                  <th>Risk</th>
                  <th>Confidence</th>
                  <th>Pattern</th>
                  <th>Cases</th>
                </tr>
              </thead>
              <tbody>
                {top_alerts.map((a) => (
                  <tr key={a.alert_id}>
                    <td className="font-mono text-xs text-electric-400">{a.alert_id}</td>
                    <td className="text-sm text-slate-200">{a.predicted_zone}</td>
                    <td>
                      <span className="badge border text-[10px]" style={{
                        borderColor: `${RISK_COLORS[a.risk_level]}50`,
                        background: `${RISK_COLORS[a.risk_level]}15`,
                        color: RISK_COLORS[a.risk_level],
                      }}>{a.risk_level} ({(a.risk_probability * 100).toFixed(0)}%)</span>
                    </td>
                    <td className="font-mono text-xs text-slate-300">{(a.confidence * 100).toFixed(1)}%</td>
                    <td className="text-xs text-slate-400">{a.crime_pattern}</td>
                    <td className="font-mono text-xs text-slate-300">{a.related_complaints}</td>
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
