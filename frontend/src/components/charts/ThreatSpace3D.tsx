import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import "echarts-gl";
import { api } from "../../services/api";
import { useSocket } from "../../contexts/WebSocketContext";

export interface ThreatPoint {
  x: number;
  y: number;
  z: number;
  spkts?: number;
  dpkts?: number;
  category: string;
  severity: string;
  is_anomalous: boolean;
  anomaly_score?: number | null;
  event_type: string;
  source_ip?: string | null;
  timestamp?: string | null;
}

// Attack-family palette (kept in sync with the backend attack categories)
const CATEGORY_COLORS: Record<string, string> = {
  "Reconnaissance": "#38bdf8",
  "Fuzzers": "#22d3ee",
  "Analysis": "#a78bfa",
  "Backdoor": "#f87171",
  "DoS": "#fb923c",
  "Exploits": "#f472b6",
  "Generic": "#94a3b8",
  "Shellcode": "#facc15",
  "Worms": "#4ade80",
  "Normal": "#1d3a5f",
};

const FALLBACK_SEVERITY: Record<string, string> = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#38bdf8",
};

function colorFor(p: ThreatPoint): string {
  return CATEGORY_COLORS[p.category] ?? FALLBACK_SEVERITY[p.severity] ?? "#38bdf8";
}

function sizeFor(p: ThreatPoint): number {
  return p.is_anomalous ? 7 : 3;
}

export default function ThreatSpace3D({ height = 380 }: { height?: number }) {
  const [points, setPoints] = useState<ThreatPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const { on } = useSocket();

  const load = async (signal?: AbortSignal) => {
    try {
      const res = await api.get<ThreatPoint[]>("/dashboard/threat-space", {
        params: { limit: 1600 },
        signal,
      });
      setPoints(res.data);
      setLastRefresh(new Date());
    } catch {
      // transient — keep previous points
    } finally {
      setLoading(false);
    }
  };

  // Initial load + periodic refresh
  useEffect(() => {
    const ac = new AbortController();
    void load(ac.signal);
    const timer = window.setInterval(() => void load(), 45_000);
    return () => {
      ac.abort();
      window.clearInterval(timer);
    };
  }, []);

  // Live: when new events stream through the pipeline, refresh the point cloud.
  useEffect(() => {
    let throttle: number | undefined;
    const off = on("new_event", () => {
      if (throttle) return;
      throttle = window.setTimeout(() => {
        throttle = undefined;
        void load();
      }, 8_000);
    });
    return () => {
      off();
      if (throttle) window.clearTimeout(throttle);
    };
  }, [on]);

  const option = useMemo(() => {
    return {
      backgroundColor: "transparent",
      tooltip: {
        backgroundColor: "rgba(10, 16, 31, 0.92)",
        borderColor: "#1a2540",
        borderWidth: 1,
        textStyle: { color: "#cbd5e1", fontSize: 11 },
        formatter: (params: { value: unknown[]; data: unknown }) => {
          const d = (params as unknown as { data: ThreatPoint }).data;
          if (!d) return "";
          return [
            `<div style="font-family:monospace">`,
            `<span style="color:${colorFor(d)}">●</span> <b>${d.category}</b> (${d.severity})`,
            `</div>`,
            `<div style="font-size:10px;color:#64748b;margin-top:2px">${d.event_type}${d.is_anomalous ? " · ⚠ ANOMALY" : ""}</div>`,
            `<div style="font-size:10px;color:#94a3b8">sent ${d.x.toFixed(2)} · recv ${d.y.toFixed(2)} · rate ${d.z.toFixed(2)} (log10)</div>`,
            `<div style="font-size:10px;color:#94a3b8">packets ${d.spkts ?? "-"}/${d.dpkts ?? "-"} · src ${d.source_ip ?? "-"}</div>`,
            `<div style="font-size:10px;color:#475569">anomaly ${d.anomaly_score?.toFixed(3) ?? "-"}</div>`,
          ].join("");
        },
      },
      grid3D: {
        boxWidth: 170,
        boxDepth: 110,
        boxHeight: 90,
        viewControl: {
          autoRotate: true,
          autoRotateSpeed: 4,
          distance: 240,
          minDistance: 120,
          maxDistance: 420,
          alpha: 22,
          beta: 40,
        },
        light: {
          main: { intensity: 1.4, shadow: true, shadowQuality: "high", alpha: 30, beta: 40 },
          ambient: { intensity: 0.35 },
        },
        environment: "transparent",
        axisLine: { lineStyle: { color: "#1a2540" } },
        axisPointer: { lineStyle: { color: "#38bdf8", opacity: 0.6 } },
        splitLine: { lineStyle: { color: "#111a30" } },
        axisLabel: { color: "#64748b", fontSize: 10 },
      },
      xAxis3D: {
        name: "Bytes sent (log10)",
        nameTextStyle: { color: "#38bdf8", fontSize: 11 },
      },
      yAxis3D: {
        name: "Bytes received (log10)",
        nameTextStyle: { color: "#a78bfa", fontSize: 11 },
      },
      zAxis3D: {
        name: "Flow rate (log10)",
        nameTextStyle: { color: "#22d3ee", fontSize: 11 },
      },
      series: [
        {
          type: "scatter3D",
          data: points.map((p) => ({
            value: [p.x, p.y, p.z],
            data: p,
            symbolSize: sizeFor(p),
            itemStyle: {
              color: colorFor(p),
              opacity: p.is_anomalous ? 0.92 : 0.5,
              borderWidth: p.is_anomalous ? 0.6 : 0,
              borderColor: "#e2e8f0",
            },
            emphasis: { itemStyle: { opacity: 1 } },
          })),
        },
      ],
    };
  }, [points]);

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <div className="flex flex-wrap items-center gap-2">
          {Object.entries(CATEGORY_COLORS)
            .filter(([k]) => k !== "Normal")
            .map(([k, c]) => (
              <span key={k} className="flex items-center gap-1 text-[10px] text-slate-500">
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
                {k}
              </span>
            ))}
          <span className="flex items-center gap-1 text-[10px] text-slate-600">
            <span className="h-1.5 w-1.5 rounded-full bg-[#1d3a5f]" />
            Normal
          </span>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-500">
          <span className={`h-1.5 w-1.5 animate-pulse rounded-full ${loading ? "bg-cyber-yellow" : "bg-cyber-green"}`} />
          {loading ? "loading…" : lastRefresh ? `updated ${lastRefresh.toLocaleTimeString()}` : ""}
        </div>
      </div>
      <ReactECharts
        option={option as never}
        notMerge
        lazyUpdate
        style={{ height, width: "100%" }}
        opts={{ renderer: "canvas" }}
      />
      <p className="mt-1 text-[10px] text-slate-600">
        Interactive 3D analysis of network flows — drag to rotate, scroll to zoom. Axis units are log10(byte counts + 1) / log10(rate + 1).
      </p>
    </div>
  );
}
