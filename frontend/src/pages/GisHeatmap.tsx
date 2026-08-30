import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, ChevronRight, Filter, Info, Layers, MapPin, RefreshCw, TrendingUp, X,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, Skeleton, StatCard } from "../components/ui";

/* ── Types ────────────────────────────────────────────────────────────── */

interface HeatmapZone {
  zone_id: string;
  name: string;
  lat: number;
  lng: number;
  risk: number;
  level: string;
  complaints: number;
  amount: number;
  confidence: number;
  time_window: string;
  features: Record<string, number>;
}

interface ZoneDetail {
  zone: HeatmapZone;
  analysis: {
    related_complaints: number;
    total_amount: number;
    fraud_type_breakdown: Record<string, number>;
    historical_withdrawal_concentration: number;
    recent_activity_spike: number;
    risk_probability: number;
    confidence_interval: string;
    contributing_features: Record<string, number>;
    explanation: string;
  };
  recent_complaints: Array<{
    complaint_id: string;
    fraud_type: string;
    amount: number;
    risk_score: number;
    district: string;
    state: string;
    status: string;
    complaint_time: string;
  }>;
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

const LEVEL_COLORS: Record<string, { bg: string; border: string; text: string; glow: string }> = {
  CRITICAL: { bg: "rgba(248,113,113,0.18)", border: "#f87171", text: "#f87171", glow: "0 0 20px rgba(248,113,113,0.4)" },
  HIGH: { bg: "rgba(251,146,60,0.18)", border: "#fb923c", text: "#fb923c", glow: "0 0 16px rgba(251,146,60,0.35)" },
  MEDIUM: { bg: "rgba(250,204,21,0.15)", border: "#facc15", text: "#facc15", glow: "0 0 12px rgba(250,204,21,0.3)" },
  LOW: { bg: "rgba(74,222,128,0.12)", border: "#4ade80", text: "#4ade80", glow: "0 0 10px rgba(74,222,128,0.25)" },
};

function riskColor(risk: number): string {
  if (risk >= 0.85) return "#f87171";
  if (risk >= 0.6) return "#fb923c";
  if (risk >= 0.3) return "#facc15";
  return "#4ade80";
}

/* ── SVG Map ──────────────────────────────────────────────────────────── */

function InteractiveMap({
  zones,
  selectedZone,
  onSelectZone,
}: {
  zones: HeatmapZone[];
  selectedZone: string | null;
  onSelectZone: (id: string) => void;
}) {
  // India bounding box approximation
  const minLat = 6.5, maxLat = 37.0, minLng = 68.0, maxLng = 97.5;
  const width = 600, height = 500;

  const toSVG = (lat: number, lng: number) => ({
    x: ((lng - minLng) / (maxLng - minLng)) * (width - 60) + 30,
    y: ((maxLat - lat) / (maxLat - minLat)) * (height - 60) + 30,
  });

  // Simple India outline (approximate)
  const indiaOutline = "M 110,80 L 140,70 180,60 220,55 260,50 300,45 340,50 380,55 420,60 450,70 470,90 480,120 490,160 500,200 490,240 470,280 450,310 430,340 400,370 370,400 340,430 310,440 280,445 250,440 220,430 190,410 160,380 140,350 120,310 110,270 100,230 95,190 90,150 100,110 Z";

  return (
    <div className="relative overflow-hidden rounded-xl border border-night-700 bg-night-950">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ minHeight: 400 }}>
        {/* Grid lines */}
        {Array.from({ length: 7 }).map((_, i) => (
          <line key={`h${i}`} x1={0} y1={i * 80} x2={width} y2={i * 80} stroke="rgba(56,189,248,0.06)" strokeWidth={0.5} />
        ))}
        {Array.from({ length: 8 }).map((_, i) => (
          <line key={`v${i}`} x1={i * 80} y1={0} x2={i * 80} y2={height} stroke="rgba(56,189,248,0.06)" strokeWidth={0.5} />
        ))}

        {/* India outline */}
        <path d={indiaOutline} fill="rgba(56,189,248,0.03)" stroke="rgba(56,189,248,0.15)" strokeWidth={1.5} />

        {/* Heatmap circles */}
        {zones.map((zone) => {
          const pos = toSVG(zone.lat, zone.lng);
          const color = riskColor(zone.risk);
          const isSelected = selectedZone === zone.zone_id;
          const radius = Math.max(12, Math.min(40, zone.complaints * 1.2 + 8));

          return (
            <g key={zone.zone_id} onClick={() => onSelectZone(zone.zone_id)} className="cursor-pointer">
              {/* Glow effect */}
              <circle cx={pos.x} cy={pos.y} r={radius + 8} fill={color} opacity={0.12}>
                <animate attributeName="r" values={`${radius + 4};${radius + 12};${radius + 4}`} dur="3s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.08;0.18;0.08" dur="3s" repeatCount="indefinite" />
              </circle>
              {/* Risk circle */}
              <circle
                cx={pos.x} cy={pos.y} r={radius}
                fill={color} opacity={isSelected ? 0.5 : 0.3}
                stroke={color} strokeWidth={isSelected ? 2.5 : 1.5}
                strokeOpacity={isSelected ? 1 : 0.6}
                style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: "all 0.2s" }}
              />
              {/* Zone label */}
              <text x={pos.x} y={pos.y - radius - 6} textAnchor="middle" fill={color} fontSize={9} fontWeight="bold" fontFamily="monospace">
                {zone.zone_id}
              </text>
              <text x={pos.x} y={pos.y + 3} textAnchor="middle" fill="white" fontSize={8} fontWeight="bold" fontFamily="monospace">
                {(zone.risk * 100).toFixed(0)}%
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ── Zone Detail Panel ────────────────────────────────────────────────── */

function ZoneDetailPanel({ zoneId, onClose }: { zoneId: string; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["zone-detail", zoneId],
    queryFn: async () => (await api.get<ZoneDetail>(`/financial/heatmap/zone/${zoneId}`)).data,
  });

  if (isLoading) return <Skeleton className="h-96" />;
  if (error || !data) return <div className="glass p-4 text-xs text-cyber-red">{getErrorMessage(error)}</div>;

  const { zone, analysis } = data;
  const color = riskColor(zone.risk);

  return (
    <div className="glass overflow-hidden">
      <div className="flex items-center justify-between border-b border-night-700/70 px-5 py-3">
        <div>
          <h3 className="text-sm font-bold text-slate-100">{zone.name}</h3>
          <p className="text-[11px] text-slate-500">Zone {zone.zone_id}</p>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-white"><X className="h-4 w-4" /></button>
      </div>
      <div className="space-y-4 p-5">
        {/* Risk meter */}
        <div className="flex items-center gap-4">
          <div className="relative h-20 w-20 shrink-0">
            <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
              <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="8" />
              <circle cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
                strokeDasharray={`${zone.risk * 264} 264`}
                style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-mono text-lg font-bold" style={{ color }}>{(zone.risk * 100).toFixed(0)}%</span>
              <span className="text-[8px] uppercase text-slate-500">risk</span>
            </div>
          </div>
          <div className="space-y-1 text-xs">
            <div className="flex justify-between gap-4"><span className="text-slate-500">Confidence</span><span className="font-mono text-slate-200">{(zone.confidence * 100).toFixed(1)}%</span></div>
            <div className="flex justify-between gap-4"><span className="text-slate-500">Time Window</span><span className="font-mono text-slate-200">{zone.time_window}</span></div>
            <div className="flex justify-between gap-4"><span className="text-slate-500">Conf. Interval</span><span className="font-mono text-slate-200">{analysis.confidence_interval}</span></div>
          </div>
        </div>

        {/* Why this area? */}
        <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-slate-500">
            <Info className="h-3.5 w-3.5" /> Why is this area high risk?
          </p>
          <p className="text-xs leading-relaxed text-slate-400">{analysis.explanation}</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="rounded-lg bg-night-900/60 p-2.5">
            <p className="text-[10px] text-slate-500">Related Complaints</p>
            <p className="font-mono text-lg font-bold text-electric-400">{analysis.related_complaints}</p>
          </div>
          <div className="rounded-lg bg-night-900/60 p-2.5">
            <p className="text-[10px] text-slate-500">Total Amount</p>
            <p className="font-mono text-lg font-bold text-cyber-orange">₹{(analysis.total_amount / 1000).toFixed(0)}K</p>
          </div>
          <div className="rounded-lg bg-night-900/60 p-2.5">
            <p className="text-[10px] text-slate-500">Activity Spike</p>
            <p className="font-mono text-lg font-bold text-cyber-purple">{(analysis.recent_activity_spike * 100).toFixed(0)}%</p>
          </div>
          <div className="rounded-lg bg-night-900/60 p-2.5">
            <p className="text-[10px] text-slate-500">Fraud Types</p>
            <p className="font-mono text-lg font-bold text-cyber-red">{Object.keys(analysis.fraud_type_breakdown).length}</p>
          </div>
        </div>

        {/* Fraud breakdown */}
        <div>
          <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Fraud Type Breakdown</p>
          <div className="space-y-1.5">
            {Object.entries(analysis.fraud_type_breakdown).sort((a, b) => b[1] - a[1]).map(([ft, cnt]) => {
              const pct = (cnt / Math.max(analysis.related_complaints, 1)) * 100;
              return (
                <div key={ft} className="flex items-center gap-2">
                  <span className="w-28 truncate text-[11px] text-slate-400">{ft}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-night-800">
                    <div className="h-full rounded-full bg-gradient-to-r from-electric-500 to-cyber-red" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="w-8 text-right font-mono text-[10px] text-slate-300">{cnt}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Contributing features */}
        <div>
          <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Contributing Features</p>
          <div className="space-y-1.5">
            {Object.entries(analysis.contributing_features).map(([key, val]) => (
              <div key={key} className="flex items-center justify-between rounded bg-night-900/40 px-2 py-1 text-[11px]">
                <span className="text-slate-400">{key.replace(/_/g, " ")}</span>
                <span className="font-mono text-slate-200">{typeof val === "number" ? val.toFixed(3) : String(val)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Main Page ────────────────────────────────────────────────────────── */

export default function GisHeatmap() {
  const [selectedZone, setSelectedZone] = useState<string | null>(null);
  const [filterState, setFilterState] = useState("");
  const [filterRisk, setFilterRisk] = useState("");
  const [showFilters, setShowFilters] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["heatmap", filterState, filterRisk],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (filterState) params.state = filterState;
      if (filterRisk) params.risk_level = filterRisk;
      return (await api.get<{ zones: HeatmapZone[]; total_zones: number; high_risk_count: number }>("/financial/heatmap", { params })).data;
    },
  });

  const zones = data?.zones ?? [];

  return (
    <div className="space-y-5">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total Zones" value={data?.total_zones ?? 0} color="#38bdf8" icon={<Layers className="h-4 w-4" />} />
        <StatCard label="High Risk Zones" value={data?.high_risk_count ?? 0} color="#f87171" icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard
          label="Max Risk"
          value={zones.length > 0 ? `${(Math.max(...zones.map((z) => z.risk)) * 100).toFixed(0)}%` : "—"}
          color="#fb923c"
          icon={<TrendingUp className="h-4 w-4" />}
        />
        <StatCard
          label="Avg Confidence"
          value={zones.length > 0 ? `${(zones.reduce((s, z) => s + z.confidence, 0) / zones.length * 100).toFixed(1)}%` : "—"}
          color="#a78bfa"
          icon={<MapPin className="h-4 w-4" />}
        />
      </div>

      {/* Filters bar */}
      <Card
        title="🗺️ GIS Risk Heatmap"
        subtitle="Geographic crime risk distribution — click a zone for explainability"
        actions={
          <div className="flex items-center gap-2">
            <button className="btn-ghost" onClick={() => setShowFilters(!showFilters)}>
              <Filter className="h-4 w-4" /> Filters
            </button>
            <button className="btn-ghost" onClick={() => refetch()}><RefreshCw className="h-4 w-4" /></button>
          </div>
        }
      >
        {showFilters && (
          <div className="mb-4 flex flex-wrap gap-3 rounded-lg border border-night-700/70 bg-night-850/50 p-3">
            <div>
              <label className="label !mb-1">State</label>
              <select className="input !w-48" value={filterState} onChange={(e) => setFilterState(e.target.value)}>
                <option value="">All States</option>
                {["Maharashtra", "Delhi", "Karnataka", "Tamil Nadu", "Uttar Pradesh", "Gujarat", "West Bengal", "Rajasthan", "Telangana", "Kerala"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label !mb-1">Risk Level</label>
              <select className="input !w-40" value={filterRisk} onChange={(e) => setFilterRisk(e.target.value)}>
                <option value="">All Levels</option>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((l) => <option key={l} value={l}>{l}</option>)}
              </select>
            </div>
          </div>
        )}

        <div className="grid gap-5 lg:grid-cols-3">
          {/* Map */}
          <div className="lg:col-span-2">
            {isLoading ? (
              <Skeleton className="h-96" />
            ) : error ? (
              <EmptyState icon={<AlertTriangle className="h-8 w-8" />} title="Failed to load heatmap" description={getErrorMessage(error)} />
            ) : zones.length === 0 ? (
              <EmptyState icon={<MapPin className="h-8 w-8" />} title="No zones found" description="Adjust filters or generate data." />
            ) : (
              <InteractiveMap zones={zones} selectedZone={selectedZone} onSelectZone={setSelectedZone} />
            )}
          </div>

          {/* Detail panel or zone list */}
          <div className="space-y-3">
            {selectedZone ? (
              <ZoneDetailPanel zoneId={selectedZone} onClose={() => setSelectedZone(null)} />
            ) : (
              <>
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Zones by Risk</p>
                <div className="max-h-[500px] space-y-2 overflow-y-auto">
                  {zones.sort((a, b) => b.risk - a.risk).map((zone) => {
                    const color = riskColor(zone.risk);
                    return (
                      <button
                        key={zone.zone_id}
                        onClick={() => setSelectedZone(zone.zone_id)}
                        className="flex w-full items-center gap-3 rounded-lg border border-night-700/70 bg-night-850/50 p-3 text-left transition hover:border-electric-500/50"
                      >
                        <div className="h-8 w-8 shrink-0 rounded-full" style={{ background: LEVEL_COLORS[zone.level]?.bg, border: `1.5px solid ${color}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                          <span className="font-mono text-[9px] font-bold" style={{ color }}>{(zone.risk * 100).toFixed(0)}%</span>
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-xs font-semibold text-slate-200">{zone.name}</p>
                          <p className="text-[10px] text-slate-500">{zone.complaints} complaints · ₹{(zone.amount / 1000).toFixed(0)}K</p>
                        </div>
                        <ChevronRight className="h-3.5 w-3.5 text-slate-600" />
                      </button>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}
