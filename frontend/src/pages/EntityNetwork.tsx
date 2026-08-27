import { useCallback, useMemo, useState } from "react";
import {
  AlertTriangle, Building2, Cpu, CreditCard, Fingerprint, Globe, MapPin, Network, User, X,
} from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  type NodeTypes,
  MarkerType,
  Handle,
  Position,
} from "@xyflow/react";
import { Card, EmptyState, SeverityBadge } from "../components/ui";

/* ── Types ─────────────────────────────────────────────────────────── */

interface NetworkData {
  nodes: Array<{
    id: string;
    type: string;
    label: string;
    nodeType?: string;
    risk?: number;
    risk_level?: string;
    properties: Record<string, unknown>;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    type: string;
    animated?: boolean;
    label?: string;
    style?: Record<string, unknown>;
    weight?: number;
  }>;
  stats: {
    total_nodes: number;
    total_edges: number;
    node_types: Record<string, number>;
    edge_types: Record<string, number>;
    high_risk_nodes: number;
    suspicious_clusters: number;
  };
}

/* ── Node Colors ───────────────────────────────────────────────────── */

const NODE_STYLES: Record<string, { bg: string; border: string; icon: React.ReactNode; label: string }> = {
  complaint: { bg: "#0ea5e920", border: "#38bdf8", icon: <AlertTriangle className="h-3.5 w-3.5" />, label: "Complaint" },
  account: { bg: "#a78bfa20", border: "#a78bfa", icon: <CreditCard className="h-3.5 w-3.5" />, label: "Account" },
  device: { bg: "#22d3ee20", border: "#22d3ee", icon: <Cpu className="h-3.5 w-3.5" />, label: "Device" },
  ip: { bg: "#fb923c20", border: "#fb923c", icon: <Globe className="h-3.5 w-3.5" />, label: "IP Address" },
  beneficiary: { bg: "#f8717120", border: "#f87171", icon: <User className="h-3.5 w-3.5" />, label: "Beneficiary" },
  atm: { bg: "#facc1520", border: "#facc15", icon: <Building2 className="h-3.5 w-3.5" />, label: "ATM" },
  location: { bg: "#4ade8020", border: "#4ade80", icon: <MapPin className="h-3.5 w-3.5" />, label: "Location" },
  entity: { bg: "#38bdf820", border: "#38bdf8", icon: <Fingerprint className="h-3.5 w-3.5" />, label: "Entity" },
};

/* ── Custom Node Component ─────────────────────────────────────────── */

function CustomNode({ data }: { data: Record<string, unknown> }) {
  const nodeType = (data.nodeType as string) ?? "entity";
  const style = NODE_STYLES[nodeType] ?? NODE_STYLES.entity;
  const risk = (data.risk as number) ?? 0;
  const riskColor = risk >= 0.8 ? "#f87171" : risk >= 0.5 ? "#fb923c" : risk >= 0.3 ? "#facc15" : "#4ade80";

  return (
    <div
      className="relative rounded-xl border px-3 py-2 text-center shadow-panel transition-all hover:shadow-glow"
      style={{
        background: style.bg,
        borderColor: data.selected ? "#38bdf8" : style.border,
        minWidth: 120,
        borderWidth: data.selected ? 2 : 1,
      }}
    >
      <Handle type="target" position={Position.Top} className="!bg-transparent !border-none" />
      <Handle type="source" position={Position.Bottom} className="!bg-transparent !border-none" />

      <div className="flex items-center justify-center gap-1.5">
        <span style={{ color: style.border }}>{style.icon}</span>
        <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: style.border }}>
          {style.label}
        </span>
      </div>
      <p className="mt-0.5 text-xs font-semibold text-slate-200 truncate max-w-[140px]">
        {String(data.label ?? "")}
      </p>
      {risk > 0 && (
        <div className="mt-1 flex items-center justify-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: riskColor }} />
          <span className="font-mono text-[9px]" style={{ color: riskColor }}>
            {Math.round(risk * 100)}% risk
          </span>
        </div>
      )}
    </div>
  );
}

const nodeTypes: NodeTypes = { custom: CustomNode };

/* ── Mock Network Data ─────────────────────────────────────────────── */

function generateMockNetwork(): NetworkData {
  const nodes = [
    { id: "c1", type: "custom", label: "CMP-2026-0841", nodeType: "complaint", risk: 0.92, risk_level: "CRITICAL", properties: { amount: 87500, state: "Maharashtra" } },
    { id: "c2", type: "custom", label: "CMP-2026-0842", nodeType: "complaint", risk: 0.78, risk_level: "HIGH", properties: { amount: 45000, state: "Maharashtra" } },
    { id: "c3", type: "custom", label: "CMP-2026-0843", nodeType: "complaint", risk: 0.65, risk_level: "MEDIUM", properties: { amount: 32000, state: "Delhi" } },
    { id: "a1", type: "custom", label: "ACC-7823451", nodeType: "account", risk: 0.88, properties: { bank: "SBI", balance: 234000 } },
    { id: "a2", type: "custom", label: "ACC-4561289", nodeType: "account", risk: 0.72, properties: { bank: "HDFC", balance: 156000 } },
    { id: "a3", type: "custom", label: "ACC-9082345", nodeType: "account", risk: 0.55, properties: { bank: "ICICI", balance: 89000 } },
    { id: "a4", type: "custom", label: "ACC-3345678", nodeType: "account", risk: 0.45, properties: { bank: "Axis", balance: 67000 } },
    { id: "d1", type: "custom", label: "DEV-iPhone-14", nodeType: "device", risk: 0.82, properties: { os: "iOS 17" } },
    { id: "d2", type: "custom", label: "DEV-Samsung-S24", nodeType: "device", risk: 0.60, properties: { os: "Android 14" } },
    { id: "ip1", type: "custom", label: "103.25.48.12", nodeType: "ip", risk: 0.75, properties: { location: "Mumbai" } },
    { id: "ip2", type: "custom", label: "49.36.128.77", nodeType: "ip", risk: 0.58, properties: { location: "Delhi" } },
    { id: "b1", type: "custom", label: "RAJESH KUMAR", nodeType: "beneficiary", risk: 0.91, properties: { account: "ACC-1122334" } },
    { id: "b2", type: "custom", label: "SUNIL MEHTA", nodeType: "beneficiary", risk: 0.70, properties: { account: "ACC-5566778" } },
    { id: "atm1", type: "custom", label: "ATM-MUM-Z14-007", nodeType: "atm", risk: 0.87, properties: { bank: "SBI", location: "Andheri West" } },
    { id: "atm2", type: "custom", label: "ATM-DEL-03-012", nodeType: "atm", risk: 0.52, properties: { bank: "HDFC", location: "Connaught Place" } },
    { id: "loc1", type: "custom", label: "Mumbai Zone 14", nodeType: "location", risk: 0.85, properties: { lat: 19.076, lng: 72.8777 } },
    { id: "loc2", type: "custom", label: "Delhi Zone 3", nodeType: "location", risk: 0.48, properties: { lat: 28.6139, lng: 77.209 } },
  ];

  const edges = [
    { id: "e-c1-a1", source: "c1", target: "a1", type: "smoothstep", animated: true, style: { stroke: "#38bdf8" } },
    { id: "e-c2-a2", source: "c2", target: "a2", type: "smoothstep", animated: true, style: { stroke: "#38bdf8" } },
    { id: "e-c3-a3", source: "c3", target: "a3", type: "smoothstep", style: { stroke: "#38bdf8" } },
    { id: "e-a1-a2", source: "a1", target: "a2", type: "smoothstep", label: "linked", style: { stroke: "#f87171", strokeDasharray: "5,5" } },
    { id: "e-a1-d1", source: "a1", target: "d1", type: "smoothstep", style: { stroke: "#22d3ee" } },
    { id: "e-a1-ip1", source: "a1", target: "ip1", type: "smoothstep", style: { stroke: "#fb923c" } },
    { id: "e-a2-d2", source: "a2", target: "d2", type: "smoothstep", style: { stroke: "#22d3ee" } },
    { id: "e-a2-ip2", source: "a2", target: "ip2", type: "smoothstep", style: { stroke: "#fb923c" } },
    { id: "e-a1-b1", source: "a1", target: "b1", type: "smoothstep", animated: true, label: "₹87,500", style: { stroke: "#f87171" } },
    { id: "e-a2-b1", source: "a2", target: "b1", type: "smoothstep", label: "₹45,000", style: { stroke: "#f87171" } },
    { id: "e-a3-b2", source: "a3", target: "b2", type: "smoothstep", style: { stroke: "#facc15" } },
    { id: "e-b1-atm1", source: "b1", target: "atm1", type: "smoothstep", animated: true, style: { stroke: "#facc15" } },
    { id: "e-b2-atm2", source: "b2", target: "atm2", type: "smoothstep", style: { stroke: "#facc15" } },
    { id: "e-atm1-loc1", source: "atm1", target: "loc1", type: "smoothstep", style: { stroke: "#4ade80" } },
    { id: "e-atm2-loc2", source: "atm2", target: "loc2", type: "smoothstep", style: { stroke: "#4ade80" } },
    { id: "e-a1-a3", source: "a1", target: "a3", type: "smoothstep", label: "same device", style: { stroke: "#a78bfa", strokeDasharray: "5,5" } },
  ];

  return {
    nodes,
    edges,
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: { complaint: 3, account: 4, device: 2, ip: 2, beneficiary: 2, atm: 2, location: 2 },
      edge_types: { "account-link": 2, "device-link": 2, "ip-link": 2, "beneficiary-link": 3, "atm-link": 2, "location-link": 2 },
      high_risk_nodes: 7,
      suspicious_clusters: 2,
    },
  };
}

/* ── Node Detail Panel ─────────────────────────────────────────────── */

function NodeDetailPanel({ node, onClose }: { node: NetworkData["nodes"][0]; onClose: () => void }) {
  const style = NODE_STYLES[node.nodeType ?? ""] ?? NODE_STYLES.entity;

  return (
    <div className="glass overflow-hidden">
      <div className="flex items-center justify-between border-b border-night-700/70 px-4 py-3">
        <div className="flex items-center gap-2">
          <span style={{ color: style.border }}>{style.icon}</span>
          <div>
            <p className="text-sm font-bold text-slate-100">{node.label}</p>
            <p className="text-[10px] uppercase tracking-wider" style={{ color: style.border }}>{style.label}</p>
          </div>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-white"><X className="h-4 w-4" /></button>
      </div>
      <div className="space-y-3 p-4">
        {node.risk !== undefined && node.risk > 0 && (
          <div className="flex items-center gap-3">
            <div className="relative h-14 w-14 shrink-0">
              <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="8" />
                <circle
                  cx="50" cy="50" r="42" fill="none"
                  stroke={node.risk >= 0.8 ? "#f87171" : node.risk >= 0.5 ? "#fb923c" : "#4ade80"}
                  strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={`${node.risk * 264} 264`}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-mono text-sm font-bold text-cyber-red">{Math.round(node.risk * 100)}%</span>
              </div>
            </div>
            <div className="text-xs">
              <p className="text-slate-500">Risk Score</p>
              <p className="font-mono text-lg font-bold text-slate-200">{Math.round(node.risk * 100)} / 100</p>
              {node.risk_level && <SeverityBadge severity={node.risk_level} />}
            </div>
          </div>
        )}

        <div className="space-y-1.5">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Properties</p>
          {Object.entries(node.properties).map(([key, val]) => (
            <div key={key} className="flex justify-between rounded bg-night-900/40 px-2 py-1 text-[11px]">
              <span className="text-slate-400">{key.replace(/_/g, " ")}</span>
              <span className="font-mono text-slate-200">{String(val)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ── Main Page ─────────────────────────────────────────────────────── */

export default function EntityNetwork() {
  const [selectedNode, setSelectedNode] = useState<NetworkData["nodes"][0] | null>(null);
  const network = useMemo(() => generateMockNetwork(), []);

  const flowNodes: Node[] = useMemo(() => {
    // Layout nodes in a force-directed-ish arrangement
    const positions: Record<string, { x: number; y: number }> = {
      c1: { x: 250, y: 50 }, c2: { x: 450, y: 50 }, c3: { x: 650, y: 50 },
      a1: { x: 200, y: 180 }, a2: { x: 400, y: 180 }, a3: { x: 600, y: 180 }, a4: { x: 800, y: 180 },
      d1: { x: 100, y: 310 }, d2: { x: 500, y: 310 },
      ip1: { x: 300, y: 310 }, ip2: { x: 700, y: 310 },
      b1: { x: 300, y: 440 }, b2: { x: 650, y: 440 },
      atm1: { x: 250, y: 560 }, atm2: { x: 650, y: 560 },
      loc1: { x: 250, y: 680 }, loc2: { x: 650, y: 680 },
    };

    return network.nodes.map((n) => ({
      id: n.id,
      type: "custom",
      position: positions[n.id] ?? { x: 400, y: 300 },
      data: { label: n.label, nodeType: n.nodeType ?? n.type, risk: n.risk, risk_level: n.risk_level, properties: n.properties, selected: selectedNode?.id === n.id } as any,
    }));
  }, [network.nodes, selectedNode]);

  const flowEdges: Edge[] = useMemo(() =>
    network.edges.map((e: any) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      type: e.type as any,
      animated: e.animated,
      label: e.label,
      style: e.style as any,
      markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12, color: (e as any).style?.stroke ?? "#334155" },
    })),
    [network.edges],
  );

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    const n = network.nodes.find((nn) => nn.id === node.id);
    if (n) setSelectedNode(n);
  }, [network.nodes]);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Network className="h-5 w-5 text-electric-400" />
            <h2 className="text-lg font-bold text-slate-100">Financial Cybercrime Network</h2>
          </div>
          <p className="text-xs text-slate-500">
            Entity relationship graph — complaints, accounts, devices, IPs, beneficiaries, ATMs, and locations.
            Click a node for details.
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card>
          <div className="text-center">
            <p className="font-mono text-2xl font-bold text-electric-400">{network.stats.total_nodes}</p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Total Nodes</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="font-mono text-2xl font-bold text-cyber-purple">{network.stats.total_edges}</p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Total Edges</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="font-mono text-2xl font-bold text-cyber-red">{network.stats.high_risk_nodes}</p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">High Risk Nodes</p>
          </div>
        </Card>
        <Card>
          <div className="text-center">
            <p className="font-mono text-2xl font-bold text-cyber-orange">{network.stats.suspicious_clusters}</p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Suspicious Clusters</p>
          </div>
        </Card>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {Object.entries(NODE_STYLES).filter(([k]) => k !== "entity").map(([key, style]) => (
          <div key={key} className="flex items-center gap-1.5 rounded-lg bg-night-850/60 px-2.5 py-1.5">
            <span style={{ color: style.border }}>{style.icon}</span>
            <span className="text-[10px] font-semibold text-slate-400">{style.label}</span>
          </div>
        ))}
      </div>

      {/* Graph + Detail Panel */}
      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <div className="glass overflow-hidden" style={{ height: 600 }}>
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            onNodeClick={onNodeClick}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.3}
            maxZoom={2}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1a2540" gap={24} />
            <Controls className="!bg-night-900 !border-night-700 !shadow-panel" />
            <MiniMap
              nodeColor={(n) => NODE_STYLES[(n.data as any).nodeType]?.border ?? "#334155"}
              className="!bg-night-900 !border-night-700"
              maskColor="rgba(6,10,20,0.7)"
            />
          </ReactFlow>
        </div>

        <div>
          {selectedNode ? (
            <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
          ) : (
            <Card>
              <EmptyState
                icon={<Network className="h-8 w-8" />}
                title="Select a node"
                description="Click on any node in the graph to view its details, risk score, and relationships."
              />
            </Card>
          )}

          {/* Edge types */}
          <Card title="Relationship Types" className="mt-4">
            <div className="space-y-2 text-xs">
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 rounded" style={{ background: "#38bdf8" }} />
                <span className="text-slate-400">Complaint → Account</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 rounded" style={{ background: "#f87171", borderTop: "1px dashed #f87171" }} />
                <span className="text-slate-400">Suspicious Link</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 rounded" style={{ background: "#22d3ee" }} />
                <span className="text-slate-400">Device Association</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 rounded" style={{ background: "#fb923c" }} />
                <span className="text-slate-400">IP Association</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 rounded" style={{ background: "#f87171" }} />
                <span className="text-slate-400">Money Transfer</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 rounded" style={{ background: "#facc15" }} />
                <span className="text-slate-400">ATM Withdrawal</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-0.5 w-6 rounded" style={{ background: "#4ade80" }} />
                <span className="text-slate-400">Geographic Location</span>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
