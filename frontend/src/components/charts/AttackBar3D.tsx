import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import "echarts-gl";
import { api } from "../../services/api";

interface AttackCell {
  category: string;
  hour: number;
  count: number;
}

const CATEGORY_ORDER = [
  "Reconnaissance", "Fuzzers", "Analysis", "Backdoor", "DoS",
  "Exploits", "Generic", "Shellcode", "Worms",
];

export default function AttackBar3D({ height = 380 }: { height?: number }) {
  const [data, setData] = useState<AttackCell[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let ac: AbortController | undefined;
    const load = async () => {
      try {
        const res = await api.get<AttackCell[]>("/dashboard/attack-distribution");
        setData(res.data);
      } catch {
        // keep previous
      } finally {
        setLoading(false);
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), 60_000);
    return () => {
      ac?.abort();
      window.clearInterval(timer);
    };
  }, []);

  const option = useMemo(() => {
    const categories = CATEGORY_ORDER.filter((c) => data.some((d) => d.category === c));
    const hours = Array.from({ length: 24 }, (_, i) => i);
    const maxCount = Math.max(1, ...data.map((d) => d.count));
    return {
      backgroundColor: "transparent",
      tooltip: {
        backgroundColor: "rgba(10, 16, 31, 0.92)",
        borderColor: "#1a2540",
        textStyle: { color: "#cbd5e1", fontSize: 11 },
        formatter: (params: { data: { value: number[] } }) => {
          const [cat, hour, count] = params.data.value;
          return `<b>${categories[cat] ?? cat}</b><br/>Hour ${String(hour).padStart(2, "0")}:00 · ${count.toLocaleString()} flows`;
        },
      },
      visualMap: {
        max: maxCount,
        calculable: false,
        inRange: { color: ["#0c3a5e", "#0ea5e9", "#a78bfa", "#f87171"] },
        dimension: 2,
        textStyle: { color: "#64748b", fontSize: 10 },
        itemWidth: 10,
        itemHeight: 80,
      },
      grid3D: {
        boxWidth: 190,
        boxDepth: 80,
        boxHeight: 110,
        viewControl: {
          autoRotate: true,
          autoRotateSpeed: 4,
          distance: 260,
          alpha: 24,
          beta: 35,
        },
        light: {
          main: { intensity: 1.3, shadow: true, shadowQuality: "high" },
          ambient: { intensity: 0.4 },
        },
        environment: "transparent",
        axisLine: { lineStyle: { color: "#1a2540" } },
        splitLine: { lineStyle: { color: "#111a30" } },
        axisLabel: { color: "#64748b", fontSize: 9 },
      },
      xAxis3D: {
        type: "category",
        data: categories,
        name: "Attack family",
        nameGap: 16,
        nameTextStyle: { color: "#38bdf8", fontSize: 11 },
      },
      yAxis3D: {
        type: "category",
        data: hours,
        name: "Hour of day",
        nameGap: 14,
        nameTextStyle: { color: "#a78bfa", fontSize: 11 },
      },
      zAxis3D: {
        type: "value",
        name: "Flow count",
        nameTextStyle: { color: "#22d3ee", fontSize: 11 },
      },
      series: [
        {
          type: "bar3D",
          data: data.map((d) => ({
            value: [categories.indexOf(d.category), d.hour, d.count],
            itemStyle: { opacity: 0.92 },
          })),
          shading: "lambert",
          bevelSize: 0.3,
          bevelSmoothness: 4,
          label: { show: false },
        },
      ],
    };
  }, [data]);

  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-[10px] text-slate-500">
        <span>Attack-family rhythm across the 24h day — height = flow volume</span>
        <span className={`flex items-center gap-1.5`}>
          <span className={`h-1.5 w-1.5 animate-pulse rounded-full ${loading ? "bg-cyber-yellow" : "bg-cyber-green"}`} />
          {loading ? "loading…" : `${data.length} cells`}
        </span>
      </div>
      <ReactECharts
        option={option as never}
        notMerge
        lazyUpdate
        style={{ height, width: "100%" }}
        opts={{ renderer: "canvas" }}
      />
      <p className="mt-1 text-[10px] text-slate-600">
        Daily attack rhythm computed from UNSW-NB15 flows — spot the hours each attack family peaks.
      </p>
    </div>
  );
}
