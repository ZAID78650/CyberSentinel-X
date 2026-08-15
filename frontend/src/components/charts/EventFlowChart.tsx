import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api } from "../../services/api";
import { useSocket } from "../../contexts/WebSocketContext";

interface Bucket {
  time: string;
  total: number;
  anomalous: number;
}

function hourKey(d: Date): string {
  const k = new Date(d);
  k.setMinutes(0, 0, 0);
  return k.toISOString();
}

function formatHour(iso: string): string {
  const d = new Date(iso);
  const h = d.getHours();
  const ampm = h >= 12 ? "PM" : "AM";
  return `${((h + 11) % 12) + 1}${ampm}`;
}

function ChartTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-night-700 bg-night-900/95 px-3 py-2 font-mono text-[11px] shadow-panel backdrop-blur">
      <p className="mb-1 text-slate-400">{label ? formatHour(label) : ""}</p>
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2 text-slate-200">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color, boxShadow: `0 0 6px ${p.color}` }} />
          {p.name}: <b>{p.value.toLocaleString()}</b>
        </p>
      ))}
    </div>
  );
}

export default function EventFlowChart({ hours = 48 }: { hours?: number }) {
  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [loading, setLoading] = useState(true);
  const { on, connected } = useSocket();
  const lastLoad = useRef(0);

  const load = useCallback(async () => {
    try {
      const res = await api.get<Bucket[]>("/dashboard/events-timeseries", {
        params: { hours },
      });
      setBuckets(res.data);
      lastLoad.current = Date.now();
    } catch {
      // transient
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 60_000);
    return () => window.clearInterval(timer);
  }, [load]);

  // Live: bump the current hour bucket on every streamed event.
  useEffect(() => {
    const off = on("new_event", () => {
      setBuckets((prev) => {
        if (!prev.length) return prev;
        const key = hourKey(new Date());
        const next = prev.map((b) =>
          b.time === key ? { ...b, total: b.total + 1, anomalous: b.anomalous + 1 } : b,
        );
        // if the bucket doesn't exist yet (new hour started), append it
        return next.some((b) => b.time === key)
          ? next
          : [...next, { time: key, total: 1, anomalous: 1 }].slice(-hours);
      });
    });
    return off;
  }, [on, hours]);

  const data = useMemo(() => {
    if (buckets.length === 0) {
      return Array.from({ length: 12 }, (_, i) => {
        const d = new Date(Date.now() - (11 - i) * 3600_000);
        return { time: hourKey(d), total: 0, anomalous: 0 };
      });
    }
    return buckets;
  }, [buckets]);

  const tick = (v: string) => formatHour(v);

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span className="flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-electric-400 shadow-[0_0_6px_#38bdf8]" /> Total flows
          </span>
          <span className="flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-cyber-red shadow-[0_0_6px_#f87171]" /> Anomalous
          </span>
        </div>
        <span className={`flex items-center gap-1.5 text-[10px] font-semibold ${connected ? "text-cyber-green" : "text-cyber-yellow"}`}>
          <span className={`h-1.5 w-1.5 animate-pulse rounded-full ${connected ? "bg-cyber-green" : "bg-cyber-yellow"}`} />
          {connected ? "LIVE" : "BUFFERING"}
        </span>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="flowTotal" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.45} />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="flowAnomalous" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f87171" stopOpacity={0.6} />
              <stop offset="100%" stopColor="#f87171" stopOpacity={0.04} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" vertical={false} />
          <XAxis
            dataKey="time" tickFormatter={tick} stroke="#475569" fontSize={10} tickLine={false}
            axisLine={{ stroke: "#1a2540" }} interval="preserveStartEnd" minTickGap={32}
          />
          <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#334155", strokeDasharray: "4 4" }} />
          <Area
            type="monotone" dataKey="total" name="Total flows" stroke="#38bdf8" strokeWidth={2}
            fill="url(#flowTotal)" dot={false} activeDot={{ r: 3, strokeWidth: 0 }}
            animationDuration={600}
          />
          <Area
            type="monotone" dataKey="anomalous" name="Anomalous" stroke="#f87171" strokeWidth={2}
            fill="url(#flowAnomalous)" dot={false} activeDot={{ r: 3, strokeWidth: 0 }}
            animationDuration={600}
          />
        </AreaChart>
      </ResponsiveContainer>
      {loading && <p className="mt-1 text-center text-[10px] text-slate-600">loading…</p>}
    </div>
  );
}
