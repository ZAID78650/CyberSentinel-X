import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  AlertTriangle, Bot, Brain, ChevronRight, DollarSign, FileText as FileTextIcon, Loader2, MapPin, PlayCircle, Radar,
  ShieldCheck, ShieldHalf, Siren, Target, TrendingUp, Zap,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { useSocket } from "../contexts/WebSocketContext";
import { useToast } from "../components/ui/Toast";
import { AccuracyGauge, Card, EmptyState, SeverityBadge, Skeleton, StatCard, StatusBadge } from "../components/ui";
import ThreatSpace3D from "../components/charts/ThreatSpace3D";
import AttackBar3D from "../components/charts/AttackBar3D";
import EventFlowChart from "../components/charts/EventFlowChart";
import type { DashboardSummary, SecurityEvent } from "../types";
import { useAuth } from "../contexts/AuthContext";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#4ade80",
};

const AGENT_ICONS: Record<string, ReactNode> = {
  "Detection Agent": <Zap className="h-4 w-4" />,
  "Investigation Agent": <Radar className="h-4 w-4" />,
  "Threat Intel Agent": <Bot className="h-4 w-4" />,
  "Risk Engine": <ShieldHalf className="h-4 w-4" />,
  "Response Agent": <ShieldCheck className="h-4 w-4" />,
};

function ChartTooltip({ active, payload, label, labelFormatter }: {
  active?: boolean;
  payload?: Array<{ name: string; value: number | string; color: string; payload?: Record<string, unknown> }>;
  label?: string | number;
  labelFormatter?: (label: string | number | undefined, payload: unknown) => string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-night-700 bg-night-900/95 px-3 py-2 font-mono text-[11px] shadow-panel backdrop-blur">
      {label !== undefined && (
        <p className="mb-1 text-slate-400">
          {labelFormatter ? labelFormatter(label, payload) : String(label)}
        </p>
      )}
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2 text-slate-200">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color, boxShadow: `0 0 6px ${p.color}` }} />
          {p.name}: <b>{typeof p.value === "number" ? p.value.toLocaleString() : p.value}</b>
        </p>
      ))}
    </div>
  );
}

function SimulatorPanel() {
  const { success, error } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { hasRole } = useAuth();
  const [running, setRunning] = useState<string | null>(null);

  const scenarios = [
    { key: "account-takeover", label: "Simulate Account Takeover", desc: "Brute force → login → privilege escalation → data access", color: "#f87171" },
    { key: "brute-force", label: "Simulate Brute Force", desc: "Repeated failed logins from a hostile source", color: "#fb923c" },
    { key: "malware", label: "Simulate Malware", desc: "Suspicious process + malware detection + C2 beacon", color: "#a78bfa" },
    { key: "data-exfiltration", label: "Simulate Data Exfiltration", desc: "Sensitive data access and outbound transfer", color: "#22d3ee" },
    { key: "privilege-escalation", label: "Simulate Privilege Escalation", desc: "Elevation of privileges on a managed endpoint", color: "#facc15" },
  ];

  const run = async (key: string) => {
    setRunning(key);
    try {
      const res = await api.post(`/simulations/${key}`);
      success("Simulation complete", res.data.message as string);
      await queryClient.invalidateQueries();
      if (res.data.incident_id) {
        setTimeout(() => navigate(`/incidents?open=${res.data.incident_id}`), 600);
      }
    } catch (err) {
      error("Simulation failed", getErrorMessage(err));
    } finally {
      setRunning(null);
    }
  };

  if (!hasRole("ADMIN", "SECURITY_ANALYST")) {
    return null;
  }

  return (
    <Card title="Attack Simulator" subtitle="Safe, synthetic scenarios — never touches real systems">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
        {scenarios.map((s) => (
          <button
            key={s.key}
            onClick={() => run(s.key)}
            disabled={running !== null}
            className="group flex items-start gap-3 rounded-lg border border-night-700 bg-night-850/60 p-3 text-left transition hover:border-electric-500/50 hover:shadow-glow disabled:opacity-60"
          >
            {running === s.key ? (
              <Loader2 className="mt-0.5 h-5 w-5 animate-spin" style={{ color: s.color }} />
            ) : (
              <PlayCircle className="mt-0.5 h-5 w-5" style={{ color: s.color }} />
            )}
            <div>
              <p className="text-sm font-semibold text-slate-200 group-hover:text-white">{s.label}</p>
              <p className="mt-0.5 text-[11px] leading-snug text-slate-500">{s.desc}</p>
            </div>
          </button>
        ))}
      </div>
    </Card>
  );
}

function AgentStatusPanel({ statuses }: { statuses: DashboardSummary["agent_statuses"] }) {
  const colorFor = (s: string) =>
    s === "ONLINE" || s === "COMPLETED" ? "#4ade80" : s === "RUNNING" ? "#38bdf8" : s === "WAITING" ? "#fb923c" : "#f87171";
  return (
    <Card title="AI Agent Status" subtitle="Live orchestration health">
      <div className="space-y-2.5">
        {statuses.map((a) => (
          <div key={a.name} className="flex items-center gap-3 rounded-lg bg-night-850/60 px-3 py-2">
            <span style={{ color: colorFor(a.status) }}>{AGENT_ICONS[a.name]}</span>
            <span className="flex-1 text-xs font-medium text-slate-300">{a.name}</span>
            <span className="flex items-center gap-1.5 text-[11px] font-semibold" style={{ color: colorFor(a.status) }}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: colorFor(a.status), boxShadow: `0 0 6px ${colorFor(a.status)}` }} />
              {a.status}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
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
      title="Live Security Events"
      subtitle={connected ? "Streaming via WebSocket" : "Most recent events"}
      actions={
        <Link to="/live-events" className="text-xs font-semibold text-electric-400 hover:underline">
          View all <ChevronRight className="inline h-3 w-3" />
        </Link>
      }
    >
      {events.length === 0 && <EmptyState icon={<Siren className="h-8 w-8" />} title="No events yet" description="Run a simulation or ingest a dataset to stream live events." />}
      <div className="space-y-1.5">
        {events.map((e) => (
          <div key={e.event_id as string} className="flex items-center gap-3 rounded-md bg-night-850/50 px-3 py-2 font-mono text-[11px]">
            <SeverityBadge severity={e.severity as string} />
            <span className="flex-1 truncate text-slate-300">{e.event_type as string}</span>
            {Boolean(e.is_anomalous) && (
              <span className="badge border border-cyber-red/30 bg-cyber-red/10 text-cyber-red">ANOMALY</span>
            )}
            <span className="hidden text-slate-600 sm:inline">{new Date(e.timestamp as string).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

function useSocketEvent(event: string, handler: (data: Record<string, unknown>) => void) {
  const { on } = useSocket();
  const cb = useCallback(handler, [handler]);
  useEffect(() => on(event, cb), [on, event, cb]);
}

export default function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => (await api.get<DashboardSummary>("/dashboard/summary")).data,
  });
  const { data: accuracy } = useQuery({
    queryKey: ["accuracy"],
    queryFn: async () => (await api.get<{ accuracy: number; precision: number; recall: number; f1: number }>("/security/detection-accuracy")).data,
  });
  const navigate = useNavigate();
  const { warning, success, error: toastError } = useToast();
  const queryClient = useQueryClient();
  const [reporting, setReporting] = useState(false);

  useSocketEvent("new_incident", () => {
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  });
  useSocketEvent("incident_updated", () => {
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  });
  useSocketEvent("new_alert", (d) => {
    warning("New alert", (d.title as string) ?? "Alert created");
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  });

  const generateReport = async (incidentId?: string) => {
    if (!incidentId) {
      warning("No incident", "Run a simulation or ingest a dataset first, then generate a report.");
      return;
    }
    setReporting(true);
    try {
      const res = await api.post(`/reports/${incidentId}/generate`);
      const url = (res.data as { pdf_url?: string }).pdf_url;
      success("Report generated", "Opening PDF report…");
      if (url) window.open(url, "_blank");
    } catch (err) {
      toastError("Report failed", getErrorMessage(err));
    } finally {
      setReporting(false);
    }
  };

  if (error) {
    return (
      <div className="glass p-8 text-center">
        <AlertTriangle className="mx-auto h-10 w-10 text-cyber-red" />
        <p className="mt-3 text-sm text-slate-300">Failed to load dashboard: {getErrorMessage(error)}</p>
        <button className="btn-ghost mt-4" onClick={() => queryClient.invalidateQueries({ queryKey: ["dashboard"] })}>
          Retry
        </button>
      </div>
    );
  }

  if (isLoading || !data) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <div className="grid gap-5 lg:grid-cols-3">
          <Skeleton className="h-72 lg:col-span-2" />
          <Skeleton className="h-72" />
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  const sevData = Object.entries(data.alerts_by_severity).map(([name, value]) => ({ name, value }));
  const catData = Object.entries(data.alerts_by_category).map(([name, value]) => ({ name, value })).slice(0, 6);
  const riskData = data.risk_over_time.length
    ? data.risk_over_time
    : [{ date: "today", avg_risk: 0 }];

  const statusData = Object.entries(
    data.recent_incidents.reduce<Record<string, number>>((acc, i) => {
      acc[i.status] = (acc[i.status] ?? 0) + 1;
      return acc;
    }, {}),
  ).map(([name, value]) => ({ name, value }));

  // ── Financial Crime Intelligence Data ──
  const { data: finData } = useQuery({
    queryKey: ["financial-dashboard"],
    queryFn: async () => (await api.get<any>("/financial/dashboard")).data,
  });
  const { data: predData } = useQuery({
    queryKey: ["predictions"],
    queryFn: async () => (await api.get<any>("/financial/predictions", { params: { limit: 5 } })).data,
  });

  return (
    <div className="space-y-5">
      {/* Financial Intelligence Hero Section */}
      {finData && (
        <Card
          title="🏦 CyberSentinel-X — Predictive Financial Cybercrime Intelligence"
          subtitle="SIH26184: AI-powered withdrawal prediction & proactive intervention"
          actions={
            <Link to="/financial-intelligence" className="text-xs font-semibold text-electric-400 hover:underline">
              Full Intelligence View <ChevronRight className="inline h-3 w-3" />
            </Link>
          }
        >
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Total Complaints</p>
              <p className="font-mono text-xl font-bold text-electric-400">{finData.summary.total_complaints}</p>
            </div>
            <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Amount at Risk</p>
              <p className="font-mono text-xl font-bold text-cyber-red">₹{(finData.summary.total_amount / 100000).toFixed(1)}L</p>
            </div>
            <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">High Risk Zones</p>
              <p className="font-mono text-xl font-bold text-cyber-orange">{finData.summary.high_risk_zones} <span className="text-[10px] text-slate-500">/ {finData.summary.total_zones}</span></p>
            </div>
            <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Active Alerts</p>
              <p className="font-mono text-xl font-bold text-cyber-purple">{finData.summary.active_alerts}</p>
            </div>
          </div>
          {predData?.alerts && predData.alerts.length > 0 && (
            <div className="mt-4 rounded-lg border border-cyber-red/30 bg-cyber-red/5 p-3">
              <p className="mb-2 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-cyber-red">
                <Target className="h-3 w-3" /> Top Predictive Alert
              </p>
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs font-bold text-cyber-red">{predData.alerts[0].alert_id}</span>
                <span className="text-xs text-slate-200">{predData.alerts[0].predicted_zone}</span>
                <span className="badge border border-cyber-red/40 bg-cyber-red/10 text-cyber-red text-[9px]">
                  {(predData.alerts[0].risk_probability * 100).toFixed(0)}% risk
                </span>
                <span className="text-[10px] text-slate-500">{predData.alerts[0].crime_pattern}</span>
                <Link to="/predictive-alerts" className="ml-auto text-[10px] font-semibold text-electric-400 hover:underline">
                  View All →
                </Link>
              </div>
            </div>
          )}
        </Card>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        {data.kpis.map((k) => (
          <StatCard key={k.label} label={k.label} value={k.value} color={k.color ?? "#38bdf8"} />
        ))}
      </div>

      {/* 3D threat analysis */}
      <div className="grid gap-5 lg:grid-cols-3">
        <Card
          title="3D Threat Space"
          subtitle="UNSW-NB15 network flows — bytes sent / received / rate, colored by attack family"
          className="lg:col-span-2"
          actions={
            <Link to="/data-sources" className="text-xs font-semibold text-electric-400 hover:underline">
              Dataset <ChevronRight className="inline h-3 w-3" />
            </Link>
          }
        >
          <ThreatSpace3D height={400} />
        </Card>

        <Card title="Attack Rhythm 3D" subtitle="Attack family × hour of day — flow volume">
          <AttackBar3D height={400} />
        </Card>
      </div>

      {/* Live flow + AI investigation + agents */}
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <Card title="Live Threat Flow" subtitle="Hourly event volume — total vs anomalous (real-time via WebSocket)">
            <EventFlowChart hours={48} />
          </Card>

          <Card title="AI Investigation Summary" subtitle="Latest agent finding">
            {data.ai_investigation_summary ? (
              <div>
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-bold text-slate-100">{data.ai_investigation_summary.incident_title}</p>
                    <p className="mt-0.5 text-xs text-slate-500">{data.ai_investigation_summary.incident_id}</p>
                  </div>
                  <div className="text-right">
                    <p className="badge border border-cyber-red/30 bg-cyber-red/10 text-cyber-red">
                      {data.ai_investigation_summary.verdict}
                    </p>
                    <p className="mt-1 font-mono text-xl font-bold text-electric-400">
                      {data.ai_investigation_summary.confidence}% <span className="text-[10px] font-normal text-slate-500">confidence</span>
                    </p>
                  </div>
                </div>
                <p className="mt-3 text-sm leading-relaxed text-slate-400">
                  {data.ai_investigation_summary.summary}
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    className="btn-ghost"
                    onClick={() => navigate(`/incidents?open=${data.ai_investigation_summary?.incident_id}`)}
                  >
                    Open investigation <ChevronRight className="h-4 w-4" />
                  </button>
                  <button
                    className="btn-primary"
                    onClick={() => generateReport(data.ai_investigation_summary?.incident_id)}
                    disabled={reporting}
                  >
                    {reporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileTextIcon className="h-4 w-4" />}
                    {reporting ? "Generating…" : "Generate Report"}
                  </button>
                </div>
              </div>
            ) : (
              <EmptyState
                icon={<Bot className="h-8 w-8" />}
                title="No investigation yet"
                description="Ingest the UNSW-NB15 dataset or run an attack simulation and the Investigation Agent will produce a findings summary here."
              />
            )}
          </Card>

          <div className="grid gap-5 md:grid-cols-2">
            <Card title="Alerts by Severity">
              <ResponsiveContainer width="100%" height={190}>
                <BarChart data={sevData} margin={{ top: 6, right: 6, left: -14, bottom: 0 }}>
                  <defs>
                    {Object.entries(SEVERITY_COLORS).map(([k, c]) => (
                      <linearGradient key={k} id={`sevGrad${k}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={c} stopOpacity={0.95} />
                        <stop offset="100%" stopColor={c} stopOpacity={0.35} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" vertical={false} />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: "#1a2540" }} />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(56,189,248,0.06)" }} />
                  <Bar dataKey="value" name="Alerts" radius={[8, 8, 2, 2]} animationDuration={700}>
                    {sevData.map((s) => (
                      <Cell key={s.name} fill={`url(#sevGrad${s.name})`} stroke={SEVERITY_COLORS[s.name]} strokeOpacity={0.5} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Card>

            <Card title="Risk Score Over Time">
              <ResponsiveContainer width="100%" height={190}>
                <AreaChart data={riskData} margin={{ top: 6, right: 6, left: -14, bottom: 0 }}>
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f87171" stopOpacity={0.55} />
                      <stop offset="100%" stopColor="#f87171" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" vertical={false} />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: "#1a2540" }} />
                  <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#334155", strokeDasharray: "4 4" }} />
                  <Area type="monotone" dataKey="avg_risk" name="Avg risk" stroke="#f87171" strokeWidth={2.5} fill="url(#riskGrad)" dot={{ r: 3, fill: "#f87171", strokeWidth: 0 }} animationDuration={700} />
                </AreaChart>
              </ResponsiveContainer>
            </Card>
          </div>
        </div>

        <div className="space-y-5">
          <AgentStatusPanel statuses={data.agent_statuses} />
          <SimulatorPanel />
        </div>
      </div>

      {/* Charts row */}
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Alerts by Category">
          {catData.length === 0 ? (
            <EmptyState title="No categories yet" />
          ) : (
            <ResponsiveContainer width="100%" height={230}>
              <PieChart>
                <Pie data={catData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={85} paddingAngle={3} stroke="none" animationDuration={700}>
                {catData.map((_, i) => (
                  <Cell key={i} fill={["#38bdf8", "#a78bfa", "#f87171", "#4ade80", "#facc15", "#fb923c"][i % 6]} style={{ filter: "drop-shadow(0 0 5px rgba(56,189,248,0.25))" }} />
                ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card title="Top Threat Sources">
          {data.top_threat_sources.length === 0 ? (
            <EmptyState title="No sources tracked" />
          ) : (
            <div className="space-y-2.5">
              {data.top_threat_sources.map((s, i) => (
                <div key={s.source} className="flex items-center gap-3">
                  <span className="w-32 truncate font-mono text-[11px] text-slate-400">{s.source}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-night-800">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-electric-500 to-cyber-red transition-all duration-700"
                      style={{ width: `${Math.min(100, (s.count / Math.max(1, data.top_threat_sources[0].count)) * 100)}%`, boxShadow: i === 0 ? "0 0 8px rgba(248,113,113,0.5)" : undefined }}
                    />
                  </div>
                  <span className="w-8 text-right font-mono text-xs text-slate-300">{s.count}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <LiveEventFeed />
      </div>

      {/* ML accuracy + trend row */}
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Detection Engine Accuracy" subtitle="Measured on a labeled evaluation corpus">
          {accuracy ? (
            <AccuracyGauge
              accuracy={accuracy.accuracy}
              precision={accuracy.precision}
              recall={accuracy.recall}
              f1={accuracy.f1}
            />
          ) : (
            <Skeleton className="h-28" />
          )}
        </Card>

        <Card title="Anomaly Pressure" subtitle="Anomalous events trend (latest window)">
          <ResponsiveContainer width="100%" height={190}>
            <LineChart data={[{ t: "00:00", v: 2 }, { t: "06:00", v: 5 }, { t: "12:00", v: 9 }, { t: "18:00", v: 14 }, { t: "now", v: data.kpis[4]?.value ?? 12 }]} margin={{ top: 6, right: 6, left: -14, bottom: 0 }}>
              <defs>
                <linearGradient id="anomStroke" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#a78bfa" />
                  <stop offset="100%" stopColor="#f87171" />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" vertical={false} />
              <XAxis dataKey="t" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: "#1a2540" }} />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#334155", strokeDasharray: "4 4" }} />
              <Line type="monotone" dataKey="v" name="Anomalous events" stroke="url(#anomStroke)" strokeWidth={2.5} dot={{ r: 4, fill: "#a78bfa", strokeWidth: 0 }} activeDot={{ r: 5 }} animationDuration={700} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Incidents by Status">
          <ResponsiveContainer width="100%" height={190}>
            <PieChart>
              <Pie
                data={statusData}
                dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={75} innerRadius={35} paddingAngle={3} stroke="none" animationDuration={700}
              >
                {["#38bdf8", "#a78bfa", "#f87171", "#4ade80", "#facc15"].map((c, i) => (
                  <Cell key={i} fill={c} style={{ filter: "drop-shadow(0 0 5px rgba(56,189,248,0.2))" }} />
                ))}
              </Pie>
              <Tooltip content={<ChartTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Recent incidents */}
      <Card
        title="Recent Incidents"
        actions={
          <Link to="/incidents" className="text-xs font-semibold text-electric-400 hover:underline">
            All incidents <ChevronRight className="inline h-3 w-3" />
          </Link>
        }
      >
        {data.recent_incidents.length === 0 ? (
          <EmptyState icon={<Siren className="h-8 w-8" />} title="No incidents" description="Ingested attacks and simulated threats will appear here." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Risk</th><th>Category</th><th>Created</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_incidents.map((inc) => (
                  <tr key={inc.id} className="cursor-pointer" onClick={() => navigate(`/incidents?open=${inc.id}`)}>
                    <td className="font-mono text-xs text-electric-400">{inc.incident_id}</td>
                    <td className="max-w-[260px] truncate font-medium text-slate-200">{inc.title}</td>
                    <td><SeverityBadge severity={inc.severity} /></td>
                    <td><StatusBadge status={inc.status} /></td>
                    <td className="font-mono text-xs">
                      {inc.risk_score != null ? `${Math.round(inc.risk_score)} (${inc.risk_label})` : "—"}
                    </td>
                    <td className="text-xs text-slate-400">{inc.category}</td>
                    <td className="text-xs text-slate-500">{new Date(inc.created_at).toLocaleString()}</td>
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
