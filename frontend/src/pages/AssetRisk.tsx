import { useEffect, useState } from "react";
import { Server, ShieldAlert } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, Skeleton } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { AssetRiskResponse } from "../types";

function riskColor(s: number): string {
  return s >= 65 ? "#f87171" : s >= 35 ? "#fb923c" : "#4ade80";
}

export default function AssetRisk() {
  const [data, setData] = useState<AssetRiskResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get<AssetRiskResponse>("/soc/asset-risk");
        setData(res.data);
      } catch (err) {
        setError(getErrorMessage(err));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <div className="glass glass-hover relative overflow-hidden p-4">
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: "#38bdf8", boxShadow: "0 0 12px #38bdf8" }} />
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Assets Monitored</p>
          <p className="kpi-value mt-1.5 text-2xl" style={{ color: "#38bdf8" }}>{data?.assets.length ?? 0}</p>
        </div>
        <div className="glass glass-hover relative overflow-hidden p-4">
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: "#a78bfa", boxShadow: "0 0 12px #a78bfa" }} />
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Average Risk</p>
          <p className="kpi-value mt-1.5 text-2xl" style={{ color: "#a78bfa" }}>{data?.average_risk.toFixed(0) ?? 0}/100</p>
        </div>
        <div className="glass glass-hover relative overflow-hidden p-4">
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: "#f87171", boxShadow: "0 0 12px #f87171" }} />
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Critical at Risk</p>
          <p className="kpi-value mt-1.5 text-2xl" style={{ color: "#f87171" }}>{data?.critical_assets_at_risk ?? 0}</p>
        </div>
        <div className="glass glass-hover relative overflow-hidden p-4">
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: "#facc15", boxShadow: "0 0 12px #facc15" }} />
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Highest Risk</p>
          <p className="kpi-value mt-1.5 truncate text-2xl" style={{ color: "#facc15" }} title={data?.assets[0]?.name}>{data?.assets[0]?.name ?? "—"}</p>
        </div>
      </div>

      <Card
        title="Asset Risk Intelligence"
        subtitle="Digital-twin style risk: criticality + incident exposure + anomalous activity"
        actions={<ProvenanceBadge source="DATASET" />}
      >
        {error && <div className="mb-3 rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>}
        {!data || data.assets.length === 0 ? (
          <EmptyState icon={<Server className="h-8 w-8" />} title="No assets registered" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-xs">
              <thead>
                <tr className="border-b border-night-700/70 text-[10px] uppercase tracking-wider text-slate-500">
                  <th className="py-2 pr-3">Asset</th>
                  <th className="py-2 pr-3">Type</th>
                  <th className="py-2 pr-3">Criticality</th>
                  <th className="py-2 pr-3">Risk Score</th>
                  <th className="py-2 pr-3">Exposure</th>
                  <th className="py-2 pr-3">Alerts</th>
                  <th className="py-2 pr-3">Incidents</th>
                </tr>
              </thead>
              <tbody>
                {data.assets.map((a) => (
                  <tr key={a.id} className="border-b border-night-800/60 hover:bg-night-850/40">
                    <td className="py-2.5 pr-3">
                      <p className="font-semibold text-slate-200">{a.name}</p>
                      {a.ip_address && <p className="font-mono text-[10px] text-slate-600">{a.ip_address}</p>}
                    </td>
                    <td className="py-2.5 pr-3 text-slate-400">{a.asset_type}</td>
                    <td className="py-2.5 pr-3">
                      <span className={`badge border ${a.criticality >= 8 ? "border-cyber-red/30 bg-cyber-red/10 text-cyber-red" : a.criticality >= 5 ? "border-cyber-yellow/30 bg-cyber-yellow/10 text-cyber-yellow" : "border-cyber-green/30 bg-cyber-green/10 text-cyber-green"}`}>
                        {a.criticality}/10
                      </span>
                    </td>
                    <td className="py-2.5 pr-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-24 overflow-hidden rounded-full bg-night-800">
                          <div className="h-full rounded-full" style={{ width: `${a.risk_score}%`, background: riskColor(a.risk_score), boxShadow: `0 0 8px ${riskColor(a.risk_score)}` }} />
                        </div>
                        <span className="font-mono font-bold" style={{ color: riskColor(a.risk_score) }}>{a.risk_score.toFixed(0)}</span>
                        <span className="text-[10px] text-slate-500">({a.risk_label})</span>
                      </div>
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-300">{a.anomalous_events}</td>
                    <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-300">{a.active_alerts}</td>
                    <td className="py-2.5 font-mono text-[11px] text-slate-300">{a.incident_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && (
          <p className="mt-3 flex items-center gap-1.5 text-[10px] text-slate-600">
            <ShieldAlert className="h-3 w-3" /> {data.method}
          </p>
        )}
      </Card>
    </div>
  );
}
