import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ReactFlow, Background, Controls, MarkerType,
  type Edge, type Node, type NodeMouseHandler, type EdgeMouseHandler,
} from "@xyflow/react";
import { Activity, Bug, Cpu, Download, GitBranch, Pause, Play, Radar, ScanSearch, ShieldAlert, ShieldCheck, SlidersHorizontal, Target, Users } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, ProgressBar } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { AttackGraph as AttackGraphData, AttackNode, AttackEdge, GraphValidation, Incident, Paginated } from "../types";

const NODE_COLORS: Record<string, string> = {
  IP: "#fb923c",
  USER: "#22d3ee",
  DEVICE: "#a78bfa",
  PROCESS: "#fbbf24",
  SERVER: "#60a5fa",
  DATABASE: "#f472b6",
  DOMAIN: "#34d399",
  MALWARE: "#ef4444",
  TECHNIQUE: "#facc15",
  ASSET: "#818cf8",
  ATTACKER: "#f87171",
};

const EDGE_COLORS: Record<string, string> = {
  CONNECTED_TO: "#64748b",
  ACCESSED: "#f472b6",
  AUTHENTICATED: "#22d3ee",
  EXECUTED: "#facc15",
  ESCALATED: "#fb923c",
  EXFILTRATED: "#f87171",
  MOVED_TO: "#34d399",
};

const RISK_COLOR = (r: number) => (r >= 80 ? "#f87171" : r >= 60 ? "#fb923c" : r >= 40 ? "#facc15" : "#4ade80");

export default function AttackGraph() {
  const [params] = useSearchParams();
  const [selected, setSelected] = useState<string | null>(params.get("incident"));
  const [selectedNode, setSelectedNode] = useState<AttackNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<AttackEdge | null>(null);
  const [typeFilter, setTypeFilter] = useState<Record<string, boolean>>({});
  const [riskCutoff, setRiskCutoff] = useState(0);
  const [cut, setCut] = useState(1);
  const [playing, setPlaying] = useState(false);
  const [audit, setAudit] = useState<GraphValidation | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  const { data: incidents } = useQuery({
    queryKey: ["incidents", "graph"],
    queryFn: async () => (await api.get<Paginated<Incident>>("/incidents", { params: { page: 1, page_size: 50 } })).data,
  });

  useEffect(() => {
    if (!selected && incidents && incidents.items.length > 0) {
      setSelected(incidents.items[0].id);
    }
  }, [incidents, selected]);

  const { data: graph } = useQuery({
    queryKey: ["attack-graph", selected],
    queryFn: async () => (await api.get<AttackGraphData>(`/attack-graph/${selected}`)).data,
    enabled: !!selected,
  });

  // Initialize filters from the graph's node types
  useEffect(() => {
    if (graph) {
      const next: Record<string, boolean> = {};
      graph.nodes.forEach((n) => { next[n.node_type] = true; });
      setTypeFilter((prev) => (Object.keys(next).length ? next : prev));
      setSelectedNode(null);
      setSelectedEdge(null);
      setCut(1);
      setPlaying(false);
    }
  }, [graph]);

  // Timeline replay loop
  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      setCut((c) => {
        if (c >= 1) { setPlaying(false); return 1; }
        return Math.min(1, c + 0.02);
      });
    }, 130);
    return () => clearInterval(id);
  }, [playing]);

  const bounds = useMemo(() => {
    let min = Infinity, max = -Infinity;
    graph?.nodes.forEach((n) => {
      const f = n.properties.first_seen, l = n.properties.last_seen;
      if (typeof f === "string" && f) min = Math.min(min, Date.parse(f));
      if (typeof l === "string" && l) max = Math.max(max, Date.parse(l));
    });
    if (min === Infinity) { min = Date.now() - 3600e3; max = Date.now(); }
    return { min, max };
  }, [graph]);

  const cutTime = bounds.min + (bounds.max - bounds.min) * cut;

  const criticalPathKeys = useMemo(() => {
    if (!graph?.critical_path) return new Set<string>();
    const keys = new Set<string>();
    graph.critical_path.nodes.forEach((k) => keys.add(k));
    return keys;
  }, [graph]);

  const criticalEdges = useMemo(() => {
    if (!graph?.critical_path) return new Set<string>();
    const set = new Set<string>();
    const nodes = graph.critical_path.nodes;
    for (let i = 0; i + 1 < nodes.length; i++) set.add(`${nodes[i]}->${nodes[i + 1]}`);
    return set;
  }, [graph]);

  const visibleNodeKeys = useMemo(() => {
    const keys = new Set<string>();
    graph?.nodes.forEach((n) => {
      if (!typeFilter[n.node_type]) return;
      const risk = typeof n.properties.risk_score === "number" ? n.properties.risk_score : 0;
      if (riskCutoff > 0 && risk < riskCutoff) return;
      const first = n.properties.first_seen;
      if (typeof first === "string" && first) {
        if (Date.parse(first) > cutTime) return;
      }
      keys.add(n.node_key);
    });
    return keys;
  }, [graph, typeFilter, riskCutoff, cutTime]);

  const { nodes, edges } = useMemo(() => {
    if (!graph) return { nodes: [], edges: [] };
    const nodes: Node[] = graph.nodes
      .filter((n) => visibleNodeKeys.has(n.node_key))
      .map((n) => {
        const color = NODE_COLORS[n.node_type] ?? "#94a3b8";
        const risk = typeof n.properties.risk_score === "number" ? n.properties.risk_score : 0;
        const onPath = criticalPathKeys.has(n.node_key);
        const borderWidth = 1.5 + Math.min(2.5, risk / 40);
        return {
          id: n.node_key,
          position: {
            x: typeof n.properties.x === "number" ? n.properties.x : 80,
            y: typeof n.properties.y === "number" ? n.properties.y : 80,
          },
          data: {
            label: (
              <div style={{ maxWidth: 200 }} title={`${n.node_type} · ${n.label} · risk ${risk.toFixed(1)}/100`}>
                <div className="flex items-center gap-2">
                  <span style={{ fontSize: 9, fontWeight: 800, letterSpacing: 1.2, color }}>{n.node_type}</span>
                  {risk > 0 && (
                    <span
                      className="rounded px-1 font-mono"
                      style={{ fontSize: 9, fontWeight: 700, color: RISK_COLOR(risk), background: `${RISK_COLOR(risk)}1f`, border: `1px solid ${RISK_COLOR(risk)}55` }}
                    >
                      {Math.round(risk)}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "#e2e8f0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {n.label}
                </div>
              </div>
            ),
          },
          style: {
            border: `${borderWidth}px solid ${color}${onPath ? "ff" : "66"}`,
            background: `${color}14`,
            borderRadius: 10,
            padding: "9px 13px",
            boxShadow: onPath
              ? `0 0 0 1.5px ${color}, 0 0 18px ${color}aa`
              : `0 0 ${6 + risk / 12}px ${color}${Math.min(0.5, 0.15 + risk / 250).toString(16).padStart(2, "0")}`,
          },
        };
      });
    const edges: Edge[] = graph.edges
      .filter((e) => visibleNodeKeys.has(e.source_key) && visibleNodeKeys.has(e.target_key))
      .filter((e) => {
        const ls = e.properties.last_seen;
        if (typeof ls === "string" && ls) return Date.parse(ls) <= cutTime;
        return true;
      })
      .map((e) => {
        const onPath = criticalEdges.has(`${e.source_key}->${e.target_key}`);
        const color = onPath ? "#f87171" : (EDGE_COLORS[e.edge_type] ?? "#64748b");
        const risk = typeof e.properties.risk_score === "number" ? e.properties.risk_score : 0;
        return {
          id: e.id,
          source: e.source_key,
          target: e.target_key,
          label: e.edge_type + (risk > 0 ? ` ${Math.round(risk)}` : ""),
          animated: onPath,
          style: { stroke: color, strokeWidth: onPath ? 3 : 1.8 },
          labelStyle: { fill: color, fontSize: 9.5, fontWeight: 700 },
          labelBgStyle: { fill: "#0d1526", fillOpacity: 0.9 },
          labelBgPadding: [4, 2] as [number, number],
          markerEnd: { type: MarkerType.ArrowClosed, color },
          data: { title: `${e.edge_type} · risk ${risk.toFixed(1)} · ${String(e.properties.event_count ?? 0)} events` },
        };
      });
    return { nodes, edges };
  }, [graph, visibleNodeKeys, criticalPathKeys, criticalEdges, cutTime]);

  const onNodeClick: NodeMouseHandler = (_, node) => {
    const full = graph?.nodes.find((n) => n.node_key === node.id) ?? null;
    setSelectedNode(full);
    setSelectedEdge(null);
  };
  const onEdgeClick: EdgeMouseHandler = (_, edge) => {
    const full = graph?.edges.find((e) => e.id === edge.id) ?? null;
    setSelectedEdge(full);
    setSelectedNode(null);
  };

  const exportJson = () => {
    if (!graph) return;
    const blob = new Blob([JSON.stringify(graph, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attack-graph-${graph.incident_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const stats = graph?.stats;
  const crownLabel = graph?.nodes.find((n) => n.node_key === stats?.crown_jewel)?.label;

  const runAudit = async () => {
    if (!selected) return;
    setAuditLoading(true);
    setAuditError(null);
    try {
      const res = await api.post<GraphValidation>(`/attack-graph/${selected}/validate`);
      setAudit(res.data);
    } catch (err) {
      setAuditError(getErrorMessage(err));
    } finally {
      setAuditLoading(false);
    }
  };

  // Auto-scan accuracy whenever the incident graph loads
  useEffect(() => {
    if (selected) {
      setAudit(null);
      runAudit();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <GitBranch className="h-5 w-5 text-electric-400" />
        <h2 className="text-lg font-bold text-slate-100">Attack Graph Reconstruction</h2>
        <select
          className="input ml-auto w-auto max-w-xs"
          value={selected ?? ""}
          onChange={(e) => setSelected(e.target.value)}
        >
          {incidents?.items.map((inc) => (
            <option key={inc.id} value={inc.id}>
              {inc.incident_id} — {inc.title}
            </option>
          ))}
        </select>
        <button onClick={exportJson} className="flex items-center gap-1.5 rounded-lg border border-night-600 px-3 py-1.5 text-xs font-bold text-slate-300 transition hover:bg-night-800">
          <Download className="h-3.5 w-3.5" /> Export JSON
        </button>
      </div>

      {/* Stats strip */}
      {stats && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <StatBox label="Nodes" value={stats.total_nodes} color="#38bdf8" />
          <StatBox label="Edges" value={stats.total_edges} color="#a78bfa" />
          <StatBox label="Graph density" value={stats.density.toFixed(3)} color="#facc15" />
          <StatBox label="Kill-chain depth" value={stats.max_depth} color="#fb923c" hint="stages from attacker" />
          <StatBox label="Crown jewel risk" value={stats.crown_jewel_risk ?? 0} color="#f87171" hint={crownLabel ?? "—"} />
        </div>
      )}

      {/* Attack-flow analysis */}
      {stats && (
        <div className="glass flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Attack flow</span>
          <AnalysisChip icon={<Bug className="h-3.5 w-3.5" />} label="attackers" value={stats.attackers ?? 0} color="#fb923c" />
          <AnalysisChip icon={<Users className="h-3.5 w-3.5" />} label="users" value={stats.users ?? 0} color="#22d3ee" />
          <AnalysisChip icon={<Target className="h-3.5 w-3.5" />} label="techniques" value={stats.techniques ?? 0} color="#facc15" />
          <AnalysisChip icon={<Cpu className="h-3.5 w-3.5" />} label="assets touched" value={stats.assets ?? 0} color="#818cf8" />
          <AnalysisChip icon={<Activity className="h-3.5 w-3.5" />} label="events analyzed" value={stats.events_analyzed ?? 0} color="#4ade80" />
          {stats.techniques ? (
            <div className="ml-auto flex flex-wrap items-center gap-1.5">
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">MITRE:</span>
              {graph?.nodes
                .filter((n) => n.node_type === "TECHNIQUE")
                .map((n) => (
                  <span key={n.node_key} className="rounded bg-cyber-purple/10 px-1.5 py-0.5 font-mono text-[9px] text-cyber-purple" title={n.label}>
                    {String(n.properties.technique_id ?? "")}
                  </span>
                ))}
            </div>
          ) : null}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* Graph */}
        <Card className="p-0">
          <div className="flex flex-wrap items-center gap-2 border-b border-night-700/70 px-4 py-2.5">
            <SlidersHorizontal className="h-3.5 w-3.5 text-slate-500" />
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Node types</span>
            {Object.keys(typeFilter).map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter((f) => ({ ...f, [t]: !f[t] }))}
                className={`badge border transition ${typeFilter[t] ? "" : "opacity-30 line-through"}`}
                style={{ color: NODE_COLORS[t] ?? "#94a3b8", borderColor: `${NODE_COLORS[t] ?? "#94a3b8"}44`, background: `${NODE_COLORS[t] ?? "#94a3b8"}11` }}
              >
                {t} ({stats?.node_types[t] ?? 0})
              </button>
            ))}
            <div className="ml-auto flex items-center gap-2">
              <label className="flex items-center gap-1.5 text-[10px] font-semibold text-slate-500">
                <input type="checkbox" checked={riskCutoff > 0} onChange={(e) => setRiskCutoff(e.target.checked ? 40 : 0)} className="accent-electric-500" />
                Hide low-risk
              </label>
            </div>
          </div>

          {/* Timeline scrubber */}
          <div className="flex items-center gap-3 border-b border-night-700/70 px-4 py-2.5">
            <button
              onClick={() => { if (cut >= 1) setCut(0); setPlaying((p) => !p); }}
              className="flex items-center gap-1.5 rounded-lg bg-electric-500/15 px-3 py-1.5 text-[11px] font-bold text-electric-400 transition hover:bg-electric-500/25"
            >
              {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              {playing ? "Pause" : cut >= 1 ? "Replay" : "Resume"}
            </button>
            <input
              type="range" min={0} max={100} value={Math.round(cut * 100)}
              onChange={(e) => { setPlaying(false); setCut(Number(e.target.value) / 100); }}
              className="w-full accent-electric-500"
            />
            <span className="whitespace-nowrap font-mono text-[10px] text-slate-500">
              {cut < 1 ? `t+${new Date(cutTime).toLocaleTimeString()}` : "full timeline"}
            </span>
          </div>

          <div className="h-[560px] w-full">
            {nodes.length === 0 ? (
              <div className="flex h-full items-center justify-center">
                <EmptyState icon={<GitBranch className="h-10 w-10" />} title="No attack graph" description="Select an incident that has been investigated." />
              </div>
            ) : (
              <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.3} maxZoom={1.8} nodesDraggable onNodeClick={onNodeClick} onEdgeClick={onEdgeClick} onPaneClick={() => { setSelectedNode(null); setSelectedEdge(null); }}>
                <Background color="#1a2540" gap={28} />
                <Controls />
              </ReactFlow>
            )}
          </div>
        </Card>

        {/* Details panel */}
        <div className="space-y-4">
          <Card title="Inspection" subtitle={selectedNode ? "Selected node" : selectedEdge ? "Selected edge" : "Click a node or edge"}>
            {selectedNode && <NodeDetail node={selectedNode} onPath={criticalPathKeys.has(selectedNode.node_key)} />}
            {selectedEdge && <EdgeDetail edge={selectedEdge} />}
            {!selectedNode && !selectedEdge && (
              <EmptyState icon={<Radar className="h-8 w-8" />} title="Nothing selected" description="Click any node to inspect its risk, events, and role in the attack — or an edge to see the relationship." />
            )}
          </Card>

          <Card
            title="Accuracy Audit"
            subtitle="Industry-standard scanning: grounding · schema · MITRE · timeline · determinism"
            actions={
              <button
                onClick={runAudit}
                disabled={auditLoading || !selected}
                className="flex items-center gap-1.5 rounded-lg border border-electric-500/40 bg-electric-500/10 px-2.5 py-1 text-[10px] font-bold text-electric-400 transition hover:bg-electric-500/20 disabled:opacity-50"
              >
                <ScanSearch className="h-3 w-3" />
                {auditLoading ? "Scanning…" : "Re-scan"}
              </button>
            }
          >
            {auditError ? (
              <p className="text-xs text-cyber-red">{auditError}</p>
            ) : auditLoading && !audit ? (
              <div className="space-y-2">
                {[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-5 w-full" />)}
              </div>
            ) : audit ? (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <div className="relative h-16 w-16 shrink-0">
                    <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                      <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="10" />
                      <circle cx="50" cy="50" r="42" fill="none" stroke={auditColor(audit.label)} strokeWidth="10" strokeLinecap="round"
                        strokeDasharray={`${(audit.accuracy_score / 100) * 264} 264`} style={{ filter: `drop-shadow(0 0 6px ${auditColor(audit.label)})` }} />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="font-mono text-sm font-bold" style={{ color: auditColor(audit.label) }}>{audit.accuracy_score.toFixed(0)}</span>
                      <span className="text-[7px] uppercase tracking-wider text-slate-500">score</span>
                    </div>
                  </div>
                  <div>
                    <span className="badge border" style={{ color: auditColor(audit.label), borderColor: `${auditColor(audit.label)}44`, background: `${auditColor(audit.label)}11` }}>
                      {audit.label}
                    </span>
                    <p className="mt-1 text-[10px] text-slate-500">{audit.counts.grounded_nodes}/{audit.counts.nodes} nodes evidence-backed · {audit.findings.length} findings</p>
                  </div>
                </div>
                <div className="space-y-2">
                  {audit.checks.map((c) => (
                    <div key={c.name}>
                      <div className="mb-0.5 flex items-center justify-between text-[10px]">
                        <span className="font-semibold text-slate-400">{c.name}</span>
                        <span className="font-mono font-bold" style={{ color: c.pass_rate >= 90 ? "#4ade80" : c.pass_rate >= 70 ? "#facc15" : "#f87171" }}>{c.pass_rate.toFixed(0)}%</span>
                      </div>
                      <ProgressBar value={c.pass_rate} color={c.pass_rate >= 90 ? "#4ade80" : c.pass_rate >= 70 ? "#facc15" : "#f87171"} />
                    </div>
                  ))}
                </div>
                {audit.findings.length > 0 ? (
                  <div className="max-h-40 space-y-1.5 overflow-y-auto">
                    {audit.findings.map((f, i) => (
                      <div key={i} className="flex items-start gap-2 rounded-md border border-night-700 bg-night-850/50 p-2">
                        <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0" style={{ color: findingColor(f.severity) }} />
                        <div className="min-w-0">
                          <p className="font-mono text-[9px] font-bold" style={{ color: findingColor(f.severity) }}>{f.item}</p>
                          <p className="text-[10px] leading-snug text-slate-400">{f.issue}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="flex items-center gap-1.5 rounded-md bg-cyber-green/10 p-2 text-[11px] text-cyber-green">
                    <ShieldCheck className="h-3.5 w-3.5" /> All accuracy scans passed — graph is fully evidence-backed and reproducible.
                  </p>
                )}
              </div>
            ) : null}
          </Card>

          <Card title="Critical Path" subtitle="Highest-risk route from attacker to crown jewel">
            {(() => {
              const cp = graph?.critical_path;
              if (!cp || cp.nodes.length === 0) {
                return <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title="No critical path" description="Not enough connected hostile activity to trace a path." />;
              }
              return (
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-cyber-red" />
                    <span className="font-mono text-xl font-bold text-cyber-red">{Math.round(cp.total_risk)}</span>
                    <span className="text-[10px] uppercase tracking-wider text-slate-500">cumulative risk</span>
                  </div>
                  <div className="rounded-lg border border-cyber-red/25 bg-cyber-red/5 p-3">
                    {cp.node_labels.map((l, i) => (
                      <div key={`${l}-${i}`} className="flex items-center gap-1.5">
                        <span className="flex h-4 w-4 items-center justify-center rounded bg-cyber-red/20 font-mono text-[8px] font-bold text-cyber-red">{i + 1}</span>
                        <span className="truncate font-mono text-[11px] text-slate-200">{l}</span>
                        {i < cp.node_labels.length - 1 ? (
                          <span className="font-mono text-[9px] text-cyber-red/70">{cp.edge_types[i]} →</span>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </Card>
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Nodes:</span>
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span key={type} className="badge border" style={{ color, borderColor: `${color}44`, background: `${color}11` }}>
            {type}
          </span>
        ))}
        <span className="ml-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Edges:</span>
        {Object.entries(EDGE_COLORS).map(([type, color]) => (
          <span key={type} className="badge border" style={{ color, borderColor: `${color}44`, background: `${color}11` }}>
            {type}
          </span>
        ))}
        <span className="ml-2 inline-flex items-center gap-1.5 rounded-full border border-cyber-red/40 bg-cyber-red/10 px-3 py-1 text-[10px] font-bold text-cyber-red">
          <span className="inline-block h-2 w-4 rounded" style={{ borderTop: "3px dashed #f87171" }} /> CRITICAL PATH
        </span>
        <ProvenanceBadge source="DATASET" />
      </div>
    </div>
  );
}

function auditColor(label: string): string {
  return label === "HIGH" ? "#4ade80" : label === "GOOD" ? "#38bdf8" : label === "MODERATE" ? "#facc15" : "#f87171";
}

function findingColor(sev: string): string {
  return sev === "HIGH" ? "#f87171" : sev === "MEDIUM" ? "#fb923c" : "#facc15";
}

function AnalysisChip({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span style={{ color }}>{icon}</span>
      <span className="font-mono text-sm font-bold" style={{ color }}>{value}</span>
      <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
    </span>
  );
}

function StatBox({ label, value, color, hint }: { label: string; value: number | string; color: string; hint?: string }) {
  return (
    <div className="glass glass-hover relative overflow-hidden p-3.5">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: color, boxShadow: `0 0 12px ${color}` }} />
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-1 font-mono text-xl font-bold" style={{ color }}>{value}</p>
      {hint && <p className="mt-0.5 truncate text-[10px] text-slate-600">{hint}</p>}
    </div>
  );
}

function NodeDetail({ node, onPath }: { node: AttackNode; onPath: boolean }) {
  const p = node.properties;
  const risk = typeof p.risk_score === "number" ? p.risk_score : 0;
  const color = NODE_COLORS[node.node_type] ?? "#94a3b8";
  const eventCount = typeof p.event_count === "number" ? p.event_count : 0;
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="badge border" style={{ color, borderColor: `${color}44`, background: `${color}11` }}>{node.node_type}</span>
        {onPath && <span className="badge border border-cyber-red/40 bg-cyber-red/10 text-cyber-red">ON CRITICAL PATH</span>}
      </div>
      <p className="text-sm font-bold text-slate-100">{node.label}</p>
      {risk > 0 && (
        <div>
          <div className="mb-1 flex justify-between text-[10px] text-slate-500">
            <span>Node risk</span>
            <span className="font-mono font-bold" style={{ color: RISK_COLOR(risk) }}>{risk.toFixed(1)} · {p.risk_label as string}</span>
          </div>
          <ProgressBar value={risk} color={RISK_COLOR(risk)} />
        </div>
      )}
      <div className="grid grid-cols-2 gap-2 text-[11px]">
        <Info label="Events" value={String(eventCount)} />
        <Info label="Severity" value={String(p.severity ?? "—")} />
        {p.criticality != null ? <Info label="Asset criticality" value={`${p.criticality}/10`} /> : null}
        {p.ip ? <Info label="IP" value={String(p.ip)} /> : null}
        {p.user ? <Info label="User" value={String(p.user)} /> : null}
        {p.technique_id ? <Info label="Technique" value={String(p.technique_id)} /> : null}
        {p.tactic ? <Info label="Tactic" value={String(p.tactic)} /> : null}
      </div>
      {(typeof p.first_seen === "string" || typeof p.last_seen === "string") ? (
        <div className="rounded-md bg-night-850/60 p-2 font-mono text-[9px] text-slate-500">
          {typeof p.first_seen === "string" ? `first: ${p.first_seen.replace("T", " ").slice(0, 19)}` : ""}
          {typeof p.last_seen === "string" ? `\nlast: ${p.last_seen.replace("T", " ").slice(0, 19)}` : ""}
        </div>
      ) : null}
    </div>
  );
}

function EdgeDetail({ edge }: { edge: AttackEdge }) {
  const p = edge.properties;
  const color = EDGE_COLORS[edge.edge_type] ?? "#64748b";
  const risk = typeof p.risk_score === "number" ? p.risk_score : 0;
  const eventCount = typeof p.event_count === "number" ? p.event_count : 0;
  return (
    <div className="space-y-3">
      <span className="badge border" style={{ color, borderColor: `${color}44`, background: `${color}11` }}>{edge.edge_type}</span>
      <div className="flex items-center gap-2 font-mono text-[11px] text-slate-300">
        <span className="truncate">{edge.source_key}</span>
        <span style={{ color }}>→</span>
        <span className="truncate">{edge.target_key}</span>
      </div>
      {risk > 0 && (
        <div>
          <div className="mb-1 flex justify-between text-[10px] text-slate-500">
            <span>Edge risk</span>
            <span className="font-mono font-bold" style={{ color: RISK_COLOR(risk) }}>{risk.toFixed(1)}</span>
          </div>
          <ProgressBar value={risk} color={RISK_COLOR(risk)} />
        </div>
      )}
      <div className="grid grid-cols-2 gap-2 text-[11px]">
        <Info label="Events" value={String(eventCount)} />
        <Info label="Severity" value={String(p.severity ?? "—")} />
        {p.via ? <Info label="Via" value={String(p.via)} /> : null}
      </div>
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-night-850/60 p-2">
      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">{label}</p>
      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-300" title={value}>{value}</p>
    </div>
  );
}
