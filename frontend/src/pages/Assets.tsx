import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Server, Database, Monitor, Globe, Cpu } from "lucide-react";
import { api } from "../services/api";
import { Card, Skeleton } from "../components/ui";
import type { AssetItem } from "../types";

const TYPE_ICONS: Record<string, React.ReactNode> = {
  server: <Server className="h-4 w-4" />,
  database: <Database className="h-4 w-4" />,
  workstation: <Monitor className="h-4 w-4" />,
  domain: <Globe className="h-4 w-4" />,
};

function criticalityColor(c: number) {
  if (c >= 9) return "#f87171";
  if (c >= 7) return "#fb923c";
  if (c >= 5) return "#facc15";
  return "#4ade80";
}

export default function Assets() {
  const [type, setType] = useState<string>("");
  const { data, isLoading } = useQuery({
    queryKey: ["assets", type],
    queryFn: async () =>
      (await api.get("/security/assets", { params: { page_size: 200, asset_type: type || undefined } })).data,
  });

  const items: AssetItem[] = data?.items ?? [];
  const types = Array.from(new Set(items.map((a) => a.asset_type)));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-slate-100">Asset Inventory</h2>
          <p className="text-xs text-slate-500">{data?.total ?? 0} monitored assets</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setType("")} className={`btn-ghost ${!type ? "ring-1 ring-electric-500/50" : ""}`}>All</button>
          {types.map((t) => (
            <button key={t} onClick={() => setType(type === t ? "" : t)} className={`btn-ghost ${type === t ? "ring-1 ring-electric-500/50" : ""}`}>
              {t}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-32" />)}
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {items.map((a) => (
            <Card key={a.id} className="glass-hover">
              <div className="flex items-start gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-night-800 text-electric-400">
                  {TYPE_ICONS[a.asset_type] ?? <Cpu className="h-4 w-4" />}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className="truncate text-sm font-semibold text-slate-200">{a.name}</p>
                    <span className="badge border border-night-700 text-[10px] text-slate-400">{a.asset_type}</span>
                  </div>
                  <p className="mt-0.5 truncate font-mono text-xs text-slate-500">{a.hostname || a.ip_address || "—"}</p>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-600">Criticality</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-night-800">
                      <div className="h-full rounded-full" style={{ width: `${a.criticality * 10}%`, background: criticalityColor(a.criticality) }} />
                    </div>
                    <span className="font-mono text-xs font-bold" style={{ color: criticalityColor(a.criticality) }}>
                      {a.criticality}/10
                    </span>
                  </div>
                  {a.owner && <p className="mt-2 text-[11px] text-slate-600">Owner: {a.owner}</p>}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
