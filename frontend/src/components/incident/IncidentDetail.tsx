import { useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowRight, Bot, CheckCircle2, ChevronLeft, FileText, GitBranch, Gauge,
  ListChecks, Loader2, Radar, XCircle,
} from "lucide-react";
import { api, getErrorMessage } from "../../services/api";
import { useToast } from "../ui/Toast";
import { Card, EmptyState, ProgressBar, RiskGauge, SeverityBadge, Skeleton, StatusBadge } from "../ui";
import type { AttackGraph as AttackGraphData, InvestigationDetail, Incident, Recommendation, Risk } from "../../types";

type Tab = "investigation" | "graph" | "risk" | "response" | "timeline";

export default function IncidentDetail({ incidentId, backTo }: { incidentId: string; backTo?: string }) {
  const [tab, setTab] = useState<Tab>("investigation");
  const navigate = useNavigate();

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: async () => (await api.get<Incident>(`/incidents/${incidentId}`)).data,
    refetchInterval: (q) => (q.state.data?.status === "INVESTIGATING" || q.state.data?.status === "OPEN" ? 4000 : false),
  });

  const { data: inv } = useQuery({
    queryKey: ["investigation", incidentId],
    queryFn: async () => (await api.get<InvestigationDetail>(`/investigations/${incidentId}`)).data,
    enabled: !!incident,
    refetchInterval: 4000,
    retry: false,
  });

  const { data: risk } = useQuery({
    queryKey: ["risk", incidentId],
    queryFn: async () => (await api.get<Risk>(`/risk/${incidentId}`)).data,
    enabled: !!incident,
  });

  const { data: graph } = useQuery({
    queryKey: ["attack-graph", incidentId],
    queryFn: async () => (await api.get<AttackGraphData>(`/attack-graph/${incidentId}`)).data,
    enabled: !!incident,
  });

  const { data: recs } = useQuery({
    queryKey: ["recommendations", incidentId],
    queryFn: async () => (await api.get<Recommendation[]>(`/response-recommendations/${incidentId}`)).data,
    enabled: !!incident,
  });

  if (isLoading || !incident) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  const tabs: Array<{ key: Tab; label: string; icon: ReactNode }> = [
    { key: "investigation", label: "AI Investigation", icon: <Radar className="h-4 w-4" /> },
    { key: "graph", label: "Attack Graph", icon: <GitBranch className="h-4 w-4" /> },
    { key: "risk", label: "Risk", icon: <Gauge className="h-4 w-4" /> },
    { key: "response", label: "Response", icon: <ListChecks className="h-4 w-4" /> },
    { key: "timeline", label: "Timeline", icon: <FileText className="h-4 w-4" /> },
  ];

  return (
    <div className="space-y-4">
      <button
        onClick={() => (backTo ? navigate(backTo) : navigate("/incidents"))}
        className="flex items-center gap-1 text-xs font-semibold text-slate-500 hover:text-electric-400"
      >
        <ChevronLeft className="h-4 w-4" /> Back to incidents
      </button>

      {/* Header */}
      <div className="glass flex flex-wrap items-center gap-4 p-5">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-bold text-electric-400">{incident.incident_id}</span>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
          <h2 className="mt-1.5 text-lg font-bold text-slate-100">{incident.title}</h2>
          {incident.description && <p className="mt-1 text-xs text-slate-500">{incident.description}</p>}
        </div>
        <div className="flex items-center gap-6">
          <div className="text-center">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Risk</p>
            <p className="font-mono text-2xl font-bold" style={{ color: (incident.risk_score ?? 0) > 60 ? "#f87171" : "#38bdf8" }}>
              {incident.risk_score != null ? Math.round(incident.risk_score) : "—"}
            </p>
            <p className="text-[10px] text-slate-500">{incident.risk_label ?? ""}</p>
          </div>
          <div className="text-center">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Confidence</p>
            <p className="font-mono text-2xl font-bold text-electric-400">{(incident.confidence * 100).toFixed(0)}%</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-1 border-b border-night-700/70">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-semibold transition-colors ${
              tab === t.key
                ? "border-electric-500 text-electric-400"
                : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            {t.icon} {t.label}
          </button>
        ))}
        <Link
          to={`/incidents/${incidentId}/war-room`}
          className="ml-auto flex items-center gap-1 px-3 py-2.5 text-xs font-semibold text-cyber-green hover:underline"
        >
          <Radar className="h-3.5 w-3.5" /> War Room
        </Link>
        <Link
          to={`/attack-graph?incident=${incidentId}`}
          className="flex items-center gap-1 px-3 py-2.5 text-xs font-semibold text-electric-400 hover:underline"
        >
          Full-screen graph <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">{renderTab(tab, { inv, risk, graph, recs, incidentId })}</div>
        <div className="space-y-5">{renderSidebar(tab, { inv, risk })}</div>
      </div>
    </div>
  );
}

function renderTab(
  tab: Tab,
  ctx: { inv?: InvestigationDetail; risk?: Risk; graph?: AttackGraphData; recs?: Recommendation[]; incidentId: string },
) {
  switch (tab) {
    case "investigation":
      return <InvestigationTab inv={ctx.inv} />;
    case "graph":
      return <GraphTab graph={ctx.graph} incidentId={ctx.incidentId} />;
    case "risk":
      return <RiskTab risk={ctx.risk} />;
    case "response":
      return <ResponseTab recs={ctx.recs} incidentId={ctx.incidentId} />;
    case "timeline":
      return <TimelineTab inv={ctx.inv} />;
  }
}

function renderSidebar(_tab: Tab, ctx: { inv?: InvestigationDetail; risk?: Risk }) {
  return (
    <>
      <Card title="Verdict" subtitle="Investigation Agent conclusion">
        {ctx.inv ? (
          <div>
            <p
              className={`badge border ${
                ctx.inv.investigation.verdict?.startsWith("HIGH")
                  ? "border-cyber-red/40 bg-cyber-red/10 text-cyber-red"
                  : ctx.inv.investigation.verdict?.startsWith("SUSPICIOUS")
                    ? "border-cyber-yellow/40 bg-cyber-yellow/10 text-cyber-yellow"
                    : "border-cyber-green/40 bg-cyber-green/10 text-cyber-green"
              }`}
            >
              {ctx.inv.investigation.verdict ?? "PENDING"}
            </p>
            <div className="mt-3">
              <div className="mb-1 flex justify-between text-xs text-slate-500">
                <span>Confidence</span>
                <span className="font-mono text-electric-400">{ctx.inv.investigation.confidence}%</span>
              </div>
              <ProgressBar value={ctx.inv.investigation.confidence} color="#38bdf8" />
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Investigation running…
          </div>
        )}
      </Card>

      {ctx.risk && (
        <Card title="Risk Breakdown" subtitle="Explainable score">
          <RiskGauge score={ctx.risk.score} label={ctx.risk.severity_label} />
          <div className="mt-3 space-y-2">
            {ctx.risk.factors.map((f) => (
              <div key={f.name}>
                <div className="mb-0.5 flex justify-between text-[11px]">
                  <span className="text-slate-400">{f.name}</span>
                  <span className="font-mono text-slate-300">{Math.round(f.contribution * 100)}%</span>
                </div>
                <ProgressBar value={f.contribution * 100} color="#a78bfa" className="h-1.5" />
              </div>
            ))}
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-slate-500">{ctx.risk.reason}</p>
        </Card>
      )}
    </>
  );
}

function InvestigationTab({ inv }: { inv?: InvestigationDetail }) {
  if (!inv) {
    return (
      <Card>
        <div className="flex flex-col items-center gap-3 py-12">
          <Loader2 className="h-8 w-8 animate-spin text-electric-400" />
          <p className="text-sm text-slate-400">The Investigation Agent is correlating events, querying threat intelligence and mapping MITRE techniques…</p>
        </div>
      </Card>
    );
  }
  return (
    <Card>
      <div className="flex items-start gap-2">
        <Bot className="mt-0.5 h-5 w-5 shrink-0 text-electric-400" />
        <p className="text-sm leading-relaxed text-slate-300">{inv.investigation.summary}</p>
      </div>

      <h4 className="mb-3 mt-6 text-xs font-bold uppercase tracking-wider text-slate-500">Evidence</h4>
      <div className="space-y-2">
        {inv.evidence.map((e, i) => (
          <div key={i} className="flex items-start gap-2.5 rounded-lg bg-night-850/60 px-3 py-2.5">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-cyber-green" />
            <div>
              <p className="text-xs font-medium text-slate-200">{e.description}</p>
              <p className="mt-0.5 text-[10px] uppercase tracking-wide text-slate-600">{e.source}</p>
            </div>
          </div>
        ))}
      </div>

      <h4 className="mb-3 mt-6 text-xs font-bold uppercase tracking-wider text-slate-500">MITRE ATT&CK Mapping</h4>
      <div className="grid gap-2 sm:grid-cols-2">
        {inv.mitre_mappings.map((m) => (
          <a
            key={m.technique_id}
            href={`https://attack.mitre.org/techniques/${m.technique_id}/`}
            target="_blank"
            rel="noreferrer"
            className="rounded-lg border border-night-700 bg-night-850/60 p-3 transition hover:border-electric-500/50"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-electric-400">{m.technique_id}</span>
              <span className="font-mono text-[10px] text-slate-500">{(m.confidence * 100).toFixed(0)}%</span>
            </div>
            <p className="mt-1 text-xs font-semibold text-slate-200">{m.name}</p>
            <p className="text-[10px] uppercase tracking-wide text-slate-600">{m.tactic}</p>
          </a>
        ))}
      </div>
    </Card>
  );
}

function GraphTab({ graph, incidentId }: { graph?: AttackGraphData; incidentId: string }) {
  if (!graph) {
    return (
      <Card>
        <EmptyState icon={<GitBranch className="h-8 w-8" />} title="Attack graph not built yet" description="It is reconstructed once the investigation completes." />
      </Card>
    );
  }
  const typeColors: Record<string, string> = {
    IP: "#fb923c", USER: "#22d3ee", DEVICE: "#a78bfa", PROCESS: "#fbbf24", SERVER: "#60a5fa",
    DATABASE: "#f472b6", DOMAIN: "#34d399", MALWARE: "#ef4444", TECHNIQUE: "#facc15", ASSET: "#818cf8", ATTACKER: "#f87171",
  };
  return (
    <Card>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {graph.nodes.map((n) => (
          <div key={n.node_key} className="rounded-lg border border-night-700 bg-night-850/60 p-3">
            <span
              className="badge mb-1.5 border"
              style={{ color: typeColors[n.node_type] ?? "#94a3b8", borderColor: `${typeColors[n.node_type] ?? "#94a3b8"}44`, background: `${typeColors[n.node_type] ?? "#94a3b8"}11` }}
            >
              {n.node_type}
            </span>
            <p className="truncate font-mono text-xs font-semibold text-slate-200">{n.label}</p>
          </div>
        ))}
      </div>
      <h4 className="mb-2 mt-5 text-xs font-bold uppercase tracking-wider text-slate-500">Relationships</h4>
      <div className="space-y-1.5">
        {graph.edges.map((e) => (
          <div key={e.id} className="flex items-center gap-2 rounded-md bg-night-850/50 px-3 py-1.5 font-mono text-[11px] text-slate-400">
            <span className="text-slate-200">{e.source_key.split(":")[1] ?? e.source_key}</span>
            <ArrowRight className="h-3 w-3 text-electric-500" />
            <span className="badge border border-electric-500/30 bg-electric-500/10 text-electric-400">{e.edge_type}</span>
            <ArrowRight className="h-3 w-3 text-electric-500" />
            <span className="text-slate-200">{e.target_key.split(":")[1] ?? e.target_key}</span>
          </div>
        ))}
      </div>
      <Link to={`/attack-graph?incident=${incidentId}`} className="btn-primary mt-4">
        Open interactive graph <GitBranch className="h-4 w-4" />
      </Link>
    </Card>
  );
}

function RiskTab({ risk }: { risk?: Risk }) {
  if (!risk) return <Card><Skeleton className="h-64" /></Card>;
  return (
    <Card title="Dynamic Risk Score" subtitle={`Model v1 · ${new Date(risk.computed_at).toLocaleString()}`}>
      <div className="flex flex-wrap items-center gap-8">
        <RiskGauge score={risk.score} label={risk.severity_label} />
        <div className="flex-1 space-y-2.5">
          {risk.factors.map((f) => (
            <div key={f.name}>
              <div className="mb-0.5 flex items-center justify-between text-xs">
                <span className="font-medium text-slate-300">
                  {f.name} <span className="text-slate-600">({Math.round(f.weight * 100)}%)</span>
                </span>
                <span className="font-mono text-slate-400">{Math.round(f.contribution * 100)} pts</span>
              </div>
              <ProgressBar value={f.contribution * 100} color="#38bdf8" className="h-1.5" />
              <p className="mt-0.5 text-[10px] text-slate-600">{f.evidence}</p>
            </div>
          ))}
        </div>
      </div>
      <p className="mt-4 rounded-lg border border-night-700 bg-night-850/60 p-3 text-xs leading-relaxed text-slate-400">
        {risk.reason}
      </p>
    </Card>
  );
}

function ResponseTab({ recs, incidentId }: { recs?: Recommendation[]; incidentId: string }) {
  const { success, error: toastError } = useToast();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);

  if (!recs) return <Card><Skeleton className="h-64" /></Card>;

  const decide = async (recId: string, decision: "approve" | "reject") => {
    setBusy(recId);
    try {
      const res = await api.post(`/approvals/${recId}/${decision}`, { reason: "Analyst decision from Response Center" });
      success(decision === "approve" ? "Action approved" : "Action rejected", res.data.message as string);
      queryClient.invalidateQueries({ queryKey: ["recommendations", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
    } catch (err) {
      toastError("Decision failed", getErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const impactColor: Record<string, string> = { HIGH: "#f87171", MEDIUM: "#fb923c", LOW: "#4ade80" };

  return (
    <Card title="Recommended Actions" subtitle="Generated by the Response Agent · execution is simulated">
      <div className="space-y-3">
        {recs.map((r) => (
          <div key={r.id} className="rounded-lg border border-night-700 bg-night-850/60 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-slate-100">{r.action}</span>
              <span className="badge border" style={{ color: impactColor[r.impact], borderColor: `${impactColor[r.impact]}44`, background: `${impactColor[r.impact]}11` }}>
                IMPACT {r.impact}
              </span>
              <StatusBadge status={r.status} />
            </div>
            {r.evidence && <p className="mt-2 text-xs leading-relaxed text-slate-400">{r.evidence}</p>}
            {r.execution_summary && (
              <p className="mt-2 flex items-center gap-1.5 rounded-md bg-cyber-green/5 px-3 py-1.5 text-[11px] text-cyber-green">
                <CheckCircle2 className="h-3.5 w-3.5" /> {r.execution_summary}
              </p>
            )}
            {r.status === "PENDING" && (
              <div className="mt-3 flex gap-2">
                <button className="btn-primary" disabled={busy !== null} onClick={() => decide(r.id, "approve")}>
                  {busy === r.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
                  Approve
                </button>
                <button className="btn-ghost" disabled={busy !== null} onClick={() => decide(r.id, "reject")}>
                  <XCircle className="h-4 w-4" /> Reject
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}

function TimelineTab({ inv }: { inv?: InvestigationDetail }) {
  if (!inv) return <Card><EmptyState icon={<FileText className="h-8 w-8" />} title="Timeline pending" description="Appears after correlation completes." /></Card>;
  const timeline = useMemo(
    () => (inv.investigation.timeline as Array<{ timestamp: string; event: string; detail?: Record<string, unknown> }>) ?? [],
    [inv],
  );
  return (
    <Card title="Correlated Event Timeline">
      {timeline.length === 0 ? (
        <EmptyState title="No timeline events" />
      ) : (
        <div className="relative space-y-0 pl-5">
          <div className="absolute bottom-2 left-[7px] top-2 w-px bg-night-700" />
          {timeline.map((t, i) => (
            <div key={i} className="relative pb-4">
              <span className="absolute -left-5 top-1 h-3 w-3 rounded-full border-2 border-electric-500 bg-night-900" />
              <p className="font-mono text-[11px] text-slate-500">{new Date(t.timestamp).toLocaleString()}</p>
              <p className="text-sm font-medium text-slate-200">{t.event}</p>
              {typeof t.detail?.source_ip === "string" && <p className="text-[11px] text-slate-600">from {t.detail.source_ip}</p>}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
