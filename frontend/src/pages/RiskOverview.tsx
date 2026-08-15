import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Gauge } from "lucide-react";
import { api } from "../services/api";
import { Card, EmptyState, RiskGauge, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import type { Incident, Paginated, Risk } from "../types";

export default function RiskOverview() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);

  const { data: incidents } = useQuery({
    queryKey: ["incidents", "risk", page],
    queryFn: async () => (await api.get<Paginated<Incident>>("/incidents", { params: { page, page_size: 20 } })).data,
  });

  const { data: riskMap } = useQuery({
    queryKey: ["risks", incidents?.items.map((i) => i.id)],
    queryFn: async () => {
      if (!incidents?.items.length) return {} as Record<string, Risk>;
      const entries = await Promise.all(
        incidents.items.map(async (i) => {
          try {
            return [i.id, (await api.get<Risk>(`/risk/${i.id}`)).data] as const;
          } catch {
            return [i.id, null] as const;
          }
        }),
      );
      return Object.fromEntries(entries.filter(([, r]) => r)) as Record<string, Risk>;
    },
    enabled: !!incidents?.items.length,
  });

  const scoreColor = (s: number) => (s > 80 ? "#f87171" : s > 60 ? "#fb923c" : s > 30 ? "#facc15" : "#4ade80");

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Gauge className="h-5 w-5 text-electric-400" />
        <h2 className="text-lg font-bold text-slate-100">Risk Overview</h2>
        <p className="text-xs text-slate-500">Explainable dynamic scoring · 30% anomaly · 20% intel · 20% asset · 15% progression · 15% evidence</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {incidents?.items.map((inc) => {
          const risk = riskMap?.[inc.id];
          return (
            <Card
              key={inc.id}
              className="cursor-pointer glass-hover"
              title={inc.title}
              subtitle={`${inc.incident_id} · ${inc.category}`}
              actions={<SeverityBadge severity={inc.severity} />}
            >
              <div onClick={() => navigate(`/incidents/${inc.id}`)}>
                {risk ? (
                  <div className="flex items-center gap-6">
                    <RiskGauge score={risk.score} label={risk.severity_label} />
                    <div className="flex-1">
                      <div className="mb-2 flex items-center gap-3">
                        <StatusBadge status={inc.status} />
                        <span className="text-xs text-slate-500">Confidence {(risk.confidence * 100).toFixed(0)}%</span>
                      </div>
                      <div className="space-y-1.5">
                        {risk.factors.map((f) => (
                          <div key={f.name} className="flex items-center gap-2 text-[11px]">
                            <span className="w-36 truncate text-slate-500">{f.name}</span>
                            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-night-800">
                              <div className="h-full rounded-full" style={{ width: `${f.contribution * 100}%`, background: scoreColor(risk.score) }} />
                            </div>
                            <span className="w-8 text-right font-mono text-slate-400">{Math.round(f.contribution * 100)}</span>
                          </div>
                        ))}
                      </div>
                      <p className="mt-2 text-[11px] leading-snug text-slate-600">{risk.reason}</p>
                    </div>
                  </div>
                ) : (
                  <Skeleton className="h-32" />
                )}
              </div>
            </Card>
          );
        })}
      </div>

      {incidents && incidents.items.length === 0 && (
        <Card><EmptyState icon={<Gauge className="h-8 w-8" />} title="No incidents to score" /></Card>
      )}

      {incidents && (
        <div className="flex items-center justify-between text-xs text-slate-500">
          <span>Page {incidents.page} of {incidents.pages}</span>
          <div className="flex gap-2">
            <button className="btn-ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
            <button className="btn-ghost" disabled={page >= incidents.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
