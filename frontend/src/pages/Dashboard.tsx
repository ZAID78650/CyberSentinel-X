import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  AlertTriangle, Brain, ChevronRight, FileText as FileTextIcon, Globe,
  Loader2, MapPin, PlayCircle, Radar, ShieldCheck, ShieldHalf,
  Siren, Target, TrendingUp, Zap, Bot,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { useSocket } from "../contexts/WebSocketContext";
import { useToast } from "../components/ui/Toast";
import { AccuracyGauge, Card, EmptyState, SeverityBadge, Skeleton, StatCard, StatusBadge } from "../components/ui";
import type { DashboardSummary, SecurityEvent } from "../types";
import { useAuth } from "../contexts/AuthContext";

/* ── Intelligence Flow Banner ────────────────────────────────────────── */

const FLOW_STEPS = [
  { label: "SCAN", icon: <Radar className="h-3.5 w-3.5" />, color: "#3b82f6" },
  { label: "UNDERSTAND", icon: <Brain className="h-3.5 w-3.5" />, color: "#06b6d4" },
  { label: "CORRELATE", icon: <Globe className="h-3.5 w-3.5" />, color: "#8b5cf6" },
  { label: "PREDICT", icon: <TrendingUp className="h-3.5 w-3.5" />, color: "#a855f7" },
  { label: "LOCATE", icon: <MapPin className="h-3.5 w-3.5" />, color: "#f59e0b" },
  { label: "ALERT", icon: <AlertTriangle className="h-3.5 w-3.5" />, color: "#f97316" },
  { label: "INTERVENE", icon: <ShieldCheck className="h-3.5 w-3.5" />, color: "#22c55e" },
];

function IntelligenceFlow() {
  return (
    <div className="intel-card p-4">
      <div className="flex items-center justify-between">
        {FLOW_STEPS.map((step, i) => (
          <div key={step.label} className="flex items-center">
            <div className="flex flex-col items-center gap-1.5">
              <div
                className="flex h-8 w-8 items-center justify-center rounded-lg transition-all duration-200"
                style={{ background: `${step.color}15`, color: step.color, border: `1px solid ${step.color}30` }}
              >
                {step.icon}
              </div>
              <span className="text-2xs font-bold tracking-wider" style={{ color: step.color }}>{step.label}</span>
            </div>
            {i < FLOW_STEPS.length - 1 && (
              <div className="mx-2 h-px w-6 md:w-10 lg:w-16" style={{ background: `linear-gradient(90deg, ${step.color}40, ${FLOW_STEPS[i + 1].color}40)` }} />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Chart Tooltip ───────────────────────────────────────────────────── */

function ChartTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: Array<{ name: string; value: number | string; color: string }>;
  label?: string | number;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="intel-card rounded-lg px-3 py-2 font-mono text-2xs">
      {label !== undefined && <p className="mb-1" style={{ color: "var(--text-muted)" }}>{String(label)}</p>}
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color }} />
          {p.name}: <b>{typeof p.value === "number" ? p.value.toLocaleString() : p.value}</b>
        </p>
      ))}
    </div>
  );
}

/* ── Live Event Feed ─────────────────────────────────────────────────── */

function useSocketEvent(event: string, handler: (data: Record<string, unknown>) => void) {
  const { on } = useSocket();
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  useEffect(() => on(event, (data) => handlerRef.current(data)), [on, event]);
}

function LiveEventFeed() {
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const { connected } = useSocket();

  useEffect(() => {
    api.get<SecurityEvent[]>("/events/live", { params: { limit: 8 } }).then((res) => {
      setEvents(res.data.map((e) => ({ ...e })));
    }).catch(() => undefined);
  }, []);

  useSocketEvent("new_event", (data) => {
    setEvents((prev) => [{ ...data, timestamp: (data.timestamp as string) ?? new Date().toISOString() }, ...prev].slice(0, 10));
  });

  return (
    <Card
      title="Live Events"
      subtitle={connected ? "Streaming via WebSocket" : "Most recent events"}
      actions={<Link to="/live-events" className="text-xs font-semibold text-blue-400 hover:underline">View all <ChevronRight className="inline h-3 w-3" /></Link>}
    >
      {events.length === 0 && (
        <EmptyState icon={<Siren className="h-8 w-8" />} title="No events yet" description="Run a simulation or ingest a dataset to stream live events." />
      )}
      <div className="space-y-1.5">
        {events.map((e) => (
          <div key={e.event_id as string} className="flex items-center gap-3 rounded-lg px-3 py-2 font-mono text-2xs" style={{ background: "var(--bg-tertiary)" }}>
            <SeverityBadge severity={e.severity as string} />
            <span className="flex-1 truncate" style={{ color: "var(--text-secondary)" }}>{e.event_type as string}</span>
            {Boolean(e.is_anomalous) && (
              <span className="badge bg-red-500/15 text-red-400 border border-red-500/30">ANOMALY</span>
            )}
            <span className="hidden sm:inline" style={{ color: "var(--text-muted)" }}>{new Date(e.timestamp as string).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* ── AI Insights Panel ───────────────────────────────────────────────── */

function AIInsightsPanel({ data }: { data: DashboardSummary }) {
  const insights: Array<{ text: string; severity: "info" | "warning" | "critical"; icon: ReactNode }> = [];

  if (data.kpis.some((k) => (k.value as number) > 50)) {
    insights.push({ text: "Elevated threat activity detected across multiple vectors.", severity: "warning", icon: <AlertTriangle className="h-3.5 w-3.5" /> });
  }
  if (data.ai_investigation_summary) {
    insights.push({ text: `Latest investigation: ${data.ai_investigation_summary.verdict} with ${data.ai_investigation_summary.confidence}% confidence.`, severity: "critical", icon: <Brain className="h-3.5 w-3.5" /> });
  }
  if (data.recent_incidents.length > 3) {
    insights.push({ text: `${data.recent_incidents.length} incidents require attention.`, severity: "warning", icon: <ShieldHalf className="h-3.5 w-3.5" /> });
  }
  if (insights.length === 0) {
    insights.push({ text: "System operating within normal parameters.", severity: "info", icon: <ShieldCheck className="h-3.5 w-3.5" /> });
  }

  const severityColors = { info: "#3b82f6", warning: "#f59e0b", critical: "#ef4444" };

  return (
    <Card title="AI Insights" subtitle="Automated intelligence analysis">
      <div className="space-y-2">
        {insights.map((insight, i) => (
          <div key={i} className="flex items-start gap-3 rounded-lg px-3 py-2.5" style={{ background: "var(--bg-tertiary)" }}>
            <span className="mt-0.5 shrink-0" style={{ color: severityColors[insight.severity] }}>{insight.icon}</span>
            <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{insight.text}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* ── Simulator Panel ─────────────────────────────────────────────────── */

function SimulatorPanel() {
  const { success, error } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { hasRole } = useAuth();
  const [running, setRunning] = useState<string | null>(null);

  const scenarios = [
    { key: "account-takeover", label: "Account Takeover", color: "#ef4444" },
    { key: "brute-force", label: "Brute Force Attack", color: "#f97316" },
    { key: "malware", label: "Malware Detection", color: "#8b5cf6" },
    { key: "data-exfiltration", label: "Data Exfiltration", color: "#06b6d4" },
  ];

  const run = async (key: string) => {
    setRunning(key);
    try {
      const res = await api.post(`/simulations/${key}`);
      success("Simulation complete", res.data.message as string);
      await queryClient.invalidateQueries();
      if (res.data.incident_id) setTimeout(() => navigate(`/incidents?open=${res.data.incident_id}`), 600);
    } catch (err) {
      error("Simulation failed", getErrorMessage(err));
    } finally {
      setRunning(null);
    }
  };

  if (!hasRole("ADMIN", "SECURITY_ANALYST")) return null;

  return (
    <Card title="SIH Demo" subtitle="Run synthetic attack scenarios">
      <div className="grid grid-cols-2 gap-2">
        {scenarios.map((s) => (
          <button
            key={s.key}
            onClick={() => run(s.key)}
            disabled={running !== null}
            className="group flex items-center gap-2 rounded-lg border px-3 py-2.5 text-left transition-all duration-150 hover:border-[var(--border-secondary)] disabled:opacity-50"
            style={{ borderColor: "var(--border-primary)", background: "var(--bg-tertiary)" }}
          >
            {running === s.key ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color: s.color }} />
            ) : (
              <PlayCircle className="h-3.5 w-3.5" style={{ color: s.color }} />
            )}
            <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>{s.label}</span>
          </button>
        ))}
      </div>
    </Card>
  );
}

/* ── Main Dashboard ──────────────────────────────────────────────────── */

const SEVERITY_COLORS: Record<string, string> = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#22c55e" };

export default function Dashboard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { warning, success, error: toastError } = useToast();
  const [reporting, setReporting] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => (await api.get<DashboardSummary>("/dashboard/summary")).data,
  });
  const { data: accuracy } = useQuery({
    queryKey: ["accuracy"],
    queryFn: async () => (await api.get<{ accuracy: number; precision: number; recall: number; f1: number }>("/security/detection-accuracy")).data,
  });
  const { data: finData } = useQuery({
    queryKey: ["financial-dashboard"],
    queryFn: async () => (await api.get<any>("/financial/dashboard")).data,
  });
  const { data: predData } = useQuery({
    queryKey: ["predictions"],
    queryFn: async () => (await api.get<any>("/financial/predictions", { params: { limit: 5 } })).data,
  });

  useSocketEvent("new_incident", () => queryClient.invalidateQueries({ queryKey: ["dashboard"] }));
  useSocketEvent("incident_updated", () => queryClient.invalidateQueries({ queryKey: ["dashboard"] }));
  useSocketEvent("new_alert", (d) => { warning("New alert", (d.title as string) ?? "Alert created"); queryClient.invalidateQueries({ queryKey: ["dashboard"] }); });

  const generateReport = async (incidentId?: string) => {
    setReporting(true);
    try {
      const res = incidentId
        ? await api.post(`/reports/${incidentId}/generate`).catch(() => api.post("/reports/generate-latest"))
        : await api.post("/reports/generate-latest");
      const d = res.data as { pdf_url?: string; report?: { report_id?: string } };
      if (d.pdf_url) { success("Report generated", `Opening PDF…`); window.open(d.pdf_url, "_blank"); }
      else success("Report generated", `${d.report?.report_id ?? ""} generated`);
    } catch (err) { toastError("Report failed", getErrorMessage(err)); }
    finally { setReporting(false); }
  };

  if (error) return (
    <div className="intel-card p-8 text-center">
      <AlertTriangle className="mx-auto h-10 w-10 text-red-400" />
      <p className="mt-3 text-sm" style={{ color: "var(--text-secondary)" }}>Failed to load dashboard: {getErrorMessage(error)}</p>
      <button className="btn-ghost mt-4" onClick={() => queryClient.invalidateQueries({ queryKey: ["dashboard"] })}>Retry</button>
    </div>
  );

  if (isLoading || !data) return (
    <div className="space-y-5">
      <Skeleton className="h-16" />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}</div>
      <div className="grid gap-5 lg:grid-cols-3"><Skeleton className="h-64 lg:col-span-2" /><Skeleton className="h-64" /></div>
    </div>
  );

  const sevData = Object.entries(data.alerts_by_severity).map(([name, value]) => ({ name, value }));
  const statusData = Object.entries(data.recent_incidents.reduce<Record<string, number>>((acc, i) => { acc[i.status] = (acc[i.status] ?? 0) + 1; return acc; }, {})).map(([name, value]) => ({ name, value }));
  const riskData = data.risk_over_time.length ? data.risk_over_time : [{ date: "today", avg_risk: 0 }];

  return (
    <div className="space-y-5">
      {/* Intelligence Flow */}
      <IntelligenceFlow />

      {/* Hero: Financial Intelligence Summary */}
      {finData && (
        <div className="intel-card relative overflow-hidden p-5">
          <div className="absolute inset-0 opacity-5" style={{ backgroundImage: "radial-gradient(circle at 50% 50%, #3b82f6, transparent 70%)" }} />
          <div className="relative flex items-start justify-between">
            <div>
              <h2 className="text-sm font-bold tracking-wide" style={{ color: "var(--text-primary)" }}>Predictive Cybercrime Intelligence</h2>
              <p className="mt-0.5 text-xs" style={{ color: "var(--text-muted)" }}>SIH26184 — AI-powered withdrawal prediction & proactive intervention</p>
            </div>
            <Link to="/financial-intelligence" className="btn-ghost btn-sm">Full View <ChevronRight className="h-3 w-3" /></Link>
          </div>
          <div className="relative mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            {[
              { label: "Total Complaints", value: finData.summary.total_complaints, color: "#3b82f6" },
              { label: "Amount at Risk", value: `₹${(finData.summary.total_amount / 100000).toFixed(1)}L`, color: "#ef4444" },
              { label: "High Risk Zones", value: `${finData.summary.high_risk_zones} / ${finData.summary.total_zones}`, color: "#f97316" },
              { label: "Active Alerts", value: finData.summary.active_alerts, color: "#8b5cf6" },
            ].map((kpi) => (
              <div key={kpi.label} className="rounded-lg border px-3 py-2.5" style={{ borderColor: "var(--border-primary)", background: "var(--bg-tertiary)" }}>
                <p className="text-2xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{kpi.label}</p>
                <p className="mt-1 font-mono text-lg font-bold" style={{ color: kpi.color }}>{kpi.value}</p>
              </div>
            ))}
          </div>
          {predData?.alerts?.length > 0 && (
            <div className="relative mt-4 rounded-lg border border-red-500/20 bg-red-500/5 p-3">
              <p className="mb-1.5 flex items-center gap-1.5 text-2xs font-bold uppercase tracking-wider text-red-400">
                <Target className="h-3 w-3" /> Top Predictive Alert
              </p>
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs font-bold text-red-400">{predData.alerts[0].alert_id}</span>
                <span className="text-xs" style={{ color: "var(--text-secondary)" }}>{predData.alerts[0].predicted_zone}</span>
                <span className="badge bg-red-500/15 text-red-400 border border-red-500/30">{(predData.alerts[0].risk_probability * 100).toFixed(0)}% risk</span>
                <Link to="/predictive-alerts" className="ml-auto text-2xs font-semibold text-blue-400 hover:underline">View All →</Link>
              </div>
            </div>
          )}
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {data.kpis.slice(0, 4).map((k) => (
          <StatCard key={k.label} label={k.label} value={k.value} color={k.color ?? "#3b82f6"} />
        ))}
      </div>

      {/* Main content: Map + Alerts + AI */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* Left: Charts + Incidents */}
        <div className="space-y-5 lg:col-span-2">
          {/* Risk Trend + Severity Distribution */}
          <div className="grid gap-5 md:grid-cols-2">
            <Card title="Risk Score Trend" subtitle="Average risk over time">
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={riskData} margin={{ top: 6, right: 6, left: -14, bottom: 0 }}>
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#ef4444" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" vertical={false} />
                  <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="var(--text-muted)" fontSize={10} domain={[0, 100]} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Area type="monotone" dataKey="avg_risk" name="Avg Risk" stroke="#ef4444" strokeWidth={2} fill="url(#riskGrad)" dot={{ r: 2, fill: "#ef4444" }} />
                </AreaChart>
              </ResponsiveContainer>
            </Card>

            <Card title="Alerts by Severity">
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={sevData} margin={{ top: 6, right: 6, left: -14, bottom: 0 }}>
                  <defs>
                    {Object.entries(SEVERITY_COLORS).map(([k, c]) => (
                      <linearGradient key={k} id={`sevGrad${k}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={c} stopOpacity={0.9} />
                        <stop offset="100%" stopColor={c} stopOpacity={0.3} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" vertical={false} />
                  <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="var(--text-muted)" fontSize={10} allowDecimals={false} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Bar dataKey="value" name="Alerts" radius={[6, 6, 2, 2]}>
                    {sevData.map((s) => <Cell key={s.name} fill={`url(#sevGrad${s.name})`} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Card>
          </div>

          {/* Detection Accuracy */}
          <Card title="Detection Engine" subtitle="Model performance metrics">
            {accuracy ? (
              <AccuracyGauge accuracy={accuracy.accuracy} precision={accuracy.precision} recall={accuracy.recall} f1={accuracy.f1} />
            ) : <Skeleton className="h-28" />}
          </Card>

          {/* AI Investigation */}
          {data.ai_investigation_summary && (
            <Card title="Latest AI Investigation" subtitle="Automated threat analysis">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{data.ai_investigation_summary.incident_title}</p>
                  <p className="mt-0.5 font-mono text-2xs" style={{ color: "var(--text-muted)" }}>{data.ai_investigation_summary.incident_id}</p>
                </div>
                <div className="text-right">
                  <span className="badge bg-red-500/15 text-red-400 border border-red-500/30">{data.ai_investigation_summary.verdict}</span>
                  <p className="mt-1 font-mono text-lg font-bold text-blue-400">{data.ai_investigation_summary.confidence}%</p>
                </div>
              </div>
              <p className="mt-3 text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{data.ai_investigation_summary.summary}</p>
              <div className="mt-3 flex gap-2">
                <button className="btn-ghost btn-sm" onClick={() => navigate(`/incidents?open=${data.ai_investigation_summary?.incident_id}`)}>Investigate</button>
                <button className="btn-primary btn-sm" onClick={() => generateReport(data.ai_investigation_summary?.incident_id)} disabled={reporting}>
                  {reporting ? <Loader2 className="h-3 w-3 animate-spin" /> : <FileTextIcon className="h-3 w-3" />}
                  {reporting ? "Generating..." : "Report"}
                </button>
              </div>
            </Card>
          )}

          {/* Recent Incidents */}
          <Card title="Recent Incidents" actions={<Link to="/incidents" className="text-xs font-semibold text-blue-400 hover:underline">All incidents <ChevronRight className="inline h-3 w-3" /></Link>}>
            {data.recent_incidents.length === 0 ? (
              <EmptyState icon={<Siren className="h-8 w-8" />} title="No incidents" description="Ingested attacks and simulated threats will appear here." />
            ) : (
              <div className="overflow-x-auto">
                <table className="table-base">
                  <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Risk</th><th>Created</th></tr></thead>
                  <tbody>
                    {data.recent_incidents.map((inc) => (
                      <tr key={inc.id} className="cursor-pointer" onClick={() => navigate(`/incidents?open=${inc.id}`)}>
                        <td className="font-mono text-2xs text-blue-400">{inc.incident_id}</td>
                        <td className="max-w-[200px] truncate text-xs font-medium" style={{ color: "var(--text-primary)" }}>{inc.title}</td>
                        <td><SeverityBadge severity={inc.severity} /></td>
                        <td><StatusBadge status={inc.status} /></td>
                        <td className="font-mono text-2xs">{inc.risk_score != null ? `${Math.round(inc.risk_score)}` : "—"}</td>
                        <td className="text-2xs" style={{ color: "var(--text-muted)" }}>{new Date(inc.created_at).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>

        {/* Right sidebar: Alerts + AI + Simulator */}
        <div className="space-y-5">
          <LiveEventFeed />
          <AIInsightsPanel data={data} />
          <SimulatorPanel />
          {data.agent_statuses.length > 0 && (
            <Card title="Agent Status" subtitle="AI orchestration health">
              <div className="space-y-2">
                {data.agent_statuses.map((a) => {
                  const color = a.status === "ONLINE" || a.status === "COMPLETED" ? "#22c55e" : a.status === "RUNNING" ? "#3b82f6" : "#f59e0b";
                  return (
                    <div key={a.name} className="flex items-center gap-2 rounded-lg px-3 py-2" style={{ background: "var(--bg-tertiary)" }}>
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
                      <span className="flex-1 text-xs font-medium" style={{ color: "var(--text-secondary)" }}>{a.name}</span>
                      <span className="text-2xs font-semibold" style={{ color }}>{a.status}</span>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
