import { useEffect, useState } from "react";
import {
  AlertTriangle, Brain, Globe, MapPin, Target, TrendingUp, X,
} from "lucide-react";
import { Card, EmptyState, StatCard } from "../components/ui";

/* ── Types ─────────────────────────────────────────────────────────── */

interface HotspotZone {
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
}

/* ── India Region Data ─────────────────────────────────────────────── */

const INDIA_HOTSPOTS: HotspotZone[] = [
  { zone_id: "Z14", name: "Mumbai Zone 14", lat: 19.076, lng: 72.8777, risk: 0.91, level: "CRITICAL", complaints: 18, amount: 875000, confidence: 0.87, time_window: "18:00–21:00" },
  { zone_id: "Z03", name: "Delhi Zone 3", lat: 28.6139, lng: 77.209, risk: 0.84, level: "HIGH", complaints: 14, amount: 654000, confidence: 0.81, time_window: "20:00–23:00" },
  { zone_id: "Z07", name: "Bangalore Zone 7", lat: 12.9716, lng: 77.5946, risk: 0.79, level: "HIGH", complaints: 11, amount: 523000, confidence: 0.76, time_window: "16:00–19:00" },
  { zone_id: "Z22", name: "Chennai Zone 22", lat: 13.0827, lng: 80.2707, risk: 0.72, level: "HIGH", complaints: 9, amount: 412000, confidence: 0.72, time_window: "19:00–22:00" },
  { zone_id: "Z11", name: "Hyderabad Zone 11", lat: 17.385, lng: 78.4867, risk: 0.65, level: "MEDIUM", complaints: 7, amount: 321000, confidence: 0.68, time_window: "17:00–20:00" },
  { zone_id: "Z19", name: "Kolkata Zone 19", lat: 22.5726, lng: 88.3639, risk: 0.58, level: "MEDIUM", complaints: 6, amount: 287000, confidence: 0.62, time_window: "15:00–18:00" },
  { zone_id: "Z05", name: "Ahmedabad Zone 5", lat: 23.0225, lng: 72.5714, risk: 0.52, level: "MEDIUM", complaints: 5, amount: 198000, confidence: 0.58, time_window: "14:00–17:00" },
  { zone_id: "Z09", name: "Pune Zone 9", lat: 18.5204, lng: 73.8567, risk: 0.48, level: "MEDIUM", complaints: 4, amount: 156000, confidence: 0.55, time_window: "16:00–19:00" },
  { zone_id: "Z16", name: "Jaipur Zone 16", lat: 26.9124, lng: 75.7873, risk: 0.42, level: "LOW", complaints: 3, amount: 98000, confidence: 0.48, time_window: "13:00–16:00" },
  { zone_id: "Z25", name: "Lucknow Zone 25", lat: 26.8467, lng: 80.9462, risk: 0.35, level: "LOW", complaints: 2, amount: 67000, confidence: 0.42, time_window: "12:00–15:00" },
];

/* ── Animated Globe ────────────────────────────────────────────────── */

function GlobeVisualization({
  hotspots,
  selectedZone,
  onSelectZone,
  layerMode,
}: {
  hotspots: HotspotZone[];
  selectedZone: string | null;
  onSelectZone: (id: string) => void;
  layerMode: "predicted" | "historical" | "current";
}) {
  const [rotation, setRotation] = useState(0);
  const [hoverZone, setHoverZone] = useState<string | null>(null);

  useEffect(() => {
    let raf: number;
    const spin = () => {
      setRotation((r) => (r + 0.12) % 360);
      raf = requestAnimationFrame(spin);
    };
    raf = requestAnimationFrame(spin);
    return () => cancelAnimationFrame(raf);
  }, []);

  const cx = 300, cy = 280, r = 200;
  const toRad = (d: number) => (d * Math.PI) / 180;

  const riskColor = (risk: number) =>
    risk >= 0.8 ? "#f87171" : risk >= 0.6 ? "#fb923c" : risk >= 0.3 ? "#facc15" : "#4ade80";

  // India approximate path
  const indiaPath = "M 180,130 L 210,115 250,105 290,100 330,95 370,100 410,105 440,115 460,135 470,165 480,200 475,240 460,275 440,305 415,330 385,360 355,385 325,400 295,405 265,400 235,390 205,370 180,345 160,310 145,270 135,230 130,190 140,155 160,135 Z";

  return (
    <div className="relative overflow-hidden rounded-xl border border-night-700 bg-night-950">
      <svg viewBox="0 0 600 560" className="w-full" style={{ minHeight: 500 }}>
        <defs>
          <radialGradient id="globeBg" cx="50%" cy="45%">
            <stop offset="0%" stopColor="#111a30" />
            <stop offset="100%" stopColor="#060a14" />
          </radialGradient>
          <radialGradient id="globeGlow2" cx="50%" cy="50%">
            <stop offset="65%" stopColor="transparent" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.06" />
          </radialGradient>
          <clipPath id="globeClip2">
            <circle cx={cx} cy={cy} r={r} />
          </clipPath>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Outer ring */}
        <circle cx={cx} cy={cy} r={r + 20} fill="none" stroke="#38bdf8" strokeWidth="0.5" opacity="0.2">
          <animate attributeName="r" values={`${r + 16};${r + 24};${r + 16}`} dur="5s" repeatCount="indefinite" />
        </circle>

        {/* Globe body */}
        <circle cx={cx} cy={cy} r={r} fill="url(#globeBg)" stroke="#38bdf8" strokeWidth="0.8" opacity="0.7" />
        <circle cx={cx} cy={cy} r={r} fill="url(#globeGlow2)" />

        {/* Grid lines */}
        <g clipPath="url(#globeClip2)" opacity="0.1">
          {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => {
            const offset = (rotation * 0.5 + i * 25) % 360;
            const xPos = cx + r * Math.cos(toRad(offset));
            const rx = r * Math.abs(Math.sin(toRad(offset))) * 0.3;
            return (
              <ellipse key={`vg${i}`} cx={xPos} cy={cy} rx={rx} ry={r}
                fill="none" stroke="#38bdf8" strokeWidth="0.4" />
            );
          })}
          {[-3, -2, -1, 0, 1, 2, 3].map((i) => (
            <ellipse key={`hg${i}`} cx={cx} cy={cy + i * 28} rx={r} ry={r * Math.cos(toRad(i * 12)) * 0.5}
              fill="none" stroke="#38bdf8" strokeWidth="0.4" />
          ))}
        </g>

        {/* India outline */}
        <g clipPath="url(#globeClip2)" opacity="0.25">
          <path d={indiaPath} fill="rgba(56,189,248,0.05)" stroke="#38bdf8" strokeWidth="1.2" />
        </g>

        {/* Hotspot zones */}
        <g clipPath="url(#globeClip2)">
          {hotspots.map((zone) => {
            const angle = toRad(zone.lng + rotation);
            const visible = Math.cos(angle) > -0.2;
            if (!visible) return null;

            const xPos = cx + r * 0.75 * Math.sin(angle);
            const yPos = cy - r * 0.55 * Math.sin(toRad(zone.lat));
            const depth = (Math.cos(angle) + 1) / 2;
            const color = riskColor(zone.risk);
            const isSelected = selectedZone === zone.zone_id;
            const isHovered = hoverZone === zone.zone_id;

            // Risk bar height based on risk level
            const barHeight = zone.risk * 40;

            return (
              <g
                key={zone.zone_id}
                onClick={() => onSelectZone(zone.zone_id)}
                onMouseEnter={() => setHoverZone(zone.zone_id)}
                onMouseLeave={() => setHoverZone(null)}
                className="cursor-pointer"
                opacity={0.4 + depth * 0.6}
              >
                {/* Pulse ring */}
                <circle cx={xPos} cy={yPos} r={12} fill="none" stroke={color} strokeWidth="0.8" opacity={0.3}>
                  <animate attributeName="r" values="8;18;8" dur="3s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.3;0;0.3" dur="3s" repeatCount="indefinite" />
                </circle>

                {/* Risk circle */}
                <circle
                  cx={xPos} cy={yPos}
                  r={Math.max(6, zone.complaints * 0.8)}
                  fill={color}
                  opacity={isSelected ? 0.5 : 0.3}
                  stroke={color}
                  strokeWidth={isSelected ? 2.5 : 1.5}
                  strokeOpacity={isSelected ? 1 : 0.6}
                  style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "all 0.2s" }}
                />

                {/* Risk bar (3D effect) */}
                {layerMode === "predicted" && (
                  <rect
                    x={xPos - 3}
                    y={yPos - barHeight - 4}
                    width={6}
                    height={barHeight}
                    rx={2}
                    fill={color}
                    opacity={0.6}
                    style={{ filter: `drop-shadow(0 0 4px ${color})` }}
                  >
                    <animate attributeName="height" values={`0;${barHeight}`} dur="1s" fill="freeze" />
                    <animate attributeName="y" values={`${yPos - 4};${yPos - barHeight - 4}`} dur="1s" fill="freeze" />
                  </rect>
                )}

                {/* Zone label */}
                <text x={xPos} y={yPos - Math.max(6, zone.complaints * 0.8) - 8} textAnchor="middle"
                  fill={color} fontSize="8" fontWeight="bold" fontFamily="monospace" opacity={depth}>
                  {zone.zone_id}
                </text>

                {/* Risk % */}
                <text x={xPos} y={yPos + 3} textAnchor="middle"
                  fill="white" fontSize="7" fontWeight="bold" fontFamily="monospace">
                  {(zone.risk * 100).toFixed(0)}%
                </text>

                {/* Expanded label on hover */}
                {(isHovered || isSelected) && (
                  <g>
                    <rect x={xPos + 16} y={yPos - 30} width={110} height={48} rx={6}
                      fill="#0d1526" stroke={color} strokeWidth="0.8" opacity="0.95" />
                    <text x={xPos + 22} y={yPos - 16} fill="white" fontSize="8" fontWeight="bold" fontFamily="monospace">
                      {zone.name}
                    </text>
                    <text x={xPos + 22} y={yPos - 4} fill={color} fontSize="7" fontFamily="monospace">
                      Risk: {(zone.risk * 100).toFixed(0)}% · Conf: {(zone.confidence * 100).toFixed(0)}%
                    </text>
                    <text x={xPos + 22} y={yPos + 8} fill="#94a3b8" fontSize="7" fontFamily="monospace">
                      ⏱ {zone.time_window} · 📋 {zone.complaints} cases
                    </text>
                    <text x={xPos + 22} y={yPos + 20} fill="#94a3b8" fontSize="7" fontFamily="monospace">
                      💰 ₹{(zone.amount / 1000).toFixed(0)}K
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </g>

        {/* Scanning line */}
        <line x1={cx - r} y1={cy} x2={cx + r} y2={cy}
          stroke="#22d3ee" strokeWidth="0.8" opacity="0.3" clipPath="url(#globeClip2)">
          <animateTransform attributeName="transform" type="rotate"
            from={`0 ${cx} ${cy}`} to={`360 ${cx} ${cy}`} dur="8s" repeatCount="indefinite" />
        </line>

        {/* Connection lines between hotspots */}
        <g clipPath="url(#globeClip2)" opacity="0.15">
          {hotspots.slice(0, 4).map((zone, i) => {
            const next = hotspots[(i + 1) % 4];
            const a1 = toRad(zone.lng + rotation);
            const a2 = toRad(next.lng + rotation);
            if (Math.cos(a1) < -0.2 || Math.cos(a2) < -0.2) return null;
            return (
              <line
                key={`conn${i}`}
                x1={cx + r * 0.75 * Math.sin(a1)}
                y1={cy - r * 0.55 * Math.sin(toRad(zone.lat))}
                x2={cx + r * 0.75 * Math.sin(a2)}
                y2={cy - r * 0.55 * Math.sin(toRad(next.lat))}
                stroke="#38bdf8" strokeWidth="0.5" strokeDasharray="4 4"
              />
            );
          })}
        </g>
      </svg>
    </div>
  );
}

/* ── Zone Detail Panel ─────────────────────────────────────────────── */

function ZoneDetail({ zone, onClose }: { zone: HotspotZone; onClose: () => void }) {
  const color = zone.risk >= 0.8 ? "#f87171" : zone.risk >= 0.6 ? "#fb923c" : zone.risk >= 0.3 ? "#facc15" : "#4ade80";

  return (
    <div className="glass overflow-hidden">
      <div className="flex items-center justify-between border-b border-night-700/70 px-4 py-3">
        <div>
          <h3 className="text-sm font-bold text-slate-100">{zone.name}</h3>
          <p className="text-[10px] text-slate-500">Zone {zone.zone_id}</p>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-white"><X className="h-4 w-4" /></button>
      </div>
      <div className="space-y-3 p-4">
        <div className="flex items-center gap-4">
          <div className="relative h-16 w-16 shrink-0">
            <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
              <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="8" />
              <circle cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
                strokeDasharray={`${zone.risk * 264} 264`}
                style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-mono text-lg font-bold" style={{ color }}>{(zone.risk * 100).toFixed(0)}%</span>
              <span className="text-[7px] uppercase text-slate-500">risk</span>
            </div>
          </div>
          <div className="space-y-1 text-xs flex-1">
            <div className="flex justify-between"><span className="text-slate-500">Confidence</span><span className="font-mono text-slate-200">{(zone.confidence * 100).toFixed(1)}%</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Time Window</span><span className="font-mono text-slate-200">{zone.time_window}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Complaints</span><span className="font-mono text-slate-200">{zone.complaints}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Amount</span><span className="font-mono text-cyber-red">₹{(zone.amount / 1000).toFixed(0)}K</span></div>
          </div>
        </div>

        <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
          <p className="mb-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500">
            <Brain className="mr-1 inline h-3 w-3" /> Why this zone?
          </p>
          <p className="text-[11px] leading-relaxed text-slate-400">
            Based on {zone.complaints} related complaints, transaction velocity patterns, geographic clustering
            using DBSCAN, and historical withdrawal data. Model confidence: {(zone.confidence * 100).toFixed(0)}%.
          </p>
        </div>
      </div>
    </div>
  );
}

/* ── Main Page ─────────────────────────────────────────────────────── */

export default function ThreatGlobe() {
  const [selectedZone, setSelectedZone] = useState<string | null>(null);
  const [layerMode, setLayerMode] = useState<"predicted" | "historical" | "current">("predicted");

  const selectedData = INDIA_HOTSPOTS.find((z) => z.zone_id === selectedZone);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Globe className="h-5 w-5 text-electric-400" />
            <h2 className="text-lg font-bold text-slate-100">3D Threat Intelligence Globe</h2>
          </div>
          <p className="text-xs text-slate-500">
            Geographic visualization of cybercrime activity, predicted hotspots, and risk intensity across India.
          </p>
        </div>

        {/* Layer toggle */}
        <div className="flex gap-1.5 rounded-lg border border-night-700 bg-night-850/60 p-1">
          {(["predicted", "historical", "current"] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setLayerMode(mode)}
              className={`rounded-md px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider transition ${
                layerMode === mode
                  ? "bg-electric-500/20 text-electric-400"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Active Hotspots" value={INDIA_HOTSPOTS.length} color="#f87171" icon={<MapPin className="h-4 w-4" />} />
        <StatCard label="Critical Zones" value={INDIA_HOTSPOTS.filter((z) => z.level === "CRITICAL").length} color="#f87171" icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard label="Max Risk" value={`${(Math.max(...INDIA_HOTSPOTS.map((z) => z.risk)) * 100).toFixed(0)}%`} color="#fb923c" icon={<TrendingUp className="h-4 w-4" />} />
        <StatCard label="Avg Confidence" value={`${(INDIA_HOTSPOTS.reduce((s, z) => s + z.confidence, 0) / INDIA_HOTSPOTS.length * 100).toFixed(1)}%`} color="#a78bfa" icon={<Target className="h-4 w-4" />} />
      </div>

      {/* Globe + Detail */}
      <div className="grid gap-5 lg:grid-cols-[1fr_340px]">
        <GlobeVisualization
          hotspots={INDIA_HOTSPOTS}
          selectedZone={selectedZone}
          onSelectZone={(id: string) => setSelectedZone(id === selectedZone ? null : id)}
          layerMode={layerMode}
        />

        <div className="space-y-4">
          {selectedData ? (
            <ZoneDetail zone={selectedData} onClose={() => setSelectedZone(null)} />
          ) : (
            <Card>
              <EmptyState
                icon={<Globe className="h-8 w-8" />}
                title="Select a hotspot"
                description="Click on any zone in the globe to view its risk details, predicted time window, and contributing factors."
              />
            </Card>
          )}

          {/* Zone list */}
          <Card title="Top Risk Zones">
            <div className="space-y-2">
              {INDIA_HOTSPOTS.slice(0, 5).map((zone) => {
                const color = zone.risk >= 0.8 ? "#f87171" : zone.risk >= 0.6 ? "#fb923c" : "#facc15";
                return (
                  <button
                    key={zone.zone_id}
                    onClick={() => setSelectedZone(zone.zone_id)}
                    className={`w-full rounded-lg border p-2.5 text-left transition ${
                      selectedZone === zone.zone_id
                        ? "border-electric-500/60 bg-electric-500/5"
                        : "border-night-700/70 bg-night-850/40 hover:bg-night-850/70"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full" style={{ background: color }} />
                        <span className="text-xs font-semibold text-slate-200">{zone.name}</span>
                      </div>
                      <span className="font-mono text-xs font-bold" style={{ color }}>
                        {(zone.risk * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-3 text-[10px] text-slate-500">
                      <span>⏱ {zone.time_window}</span>
                      <span>📋 {zone.complaints}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
