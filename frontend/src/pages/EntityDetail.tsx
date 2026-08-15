import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Activity, Fingerprint, Network, ShieldAlert, User } from "lucide-react";
import { api } from "../services/api";
import { Card, EmptyState, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { EntityDetail as EntityDetailType } from "../types";

const TYPE_META: Record<string, { label: string; icon: React.ReactNode }> = {
  user: { label: "User", icon: <User className="h-5 w-5" /> },
  ip: { label: "IP Address", icon: <Network className="h-5 w-5" /> },
  device: { label: "Device", icon: <Activity className="h-5 w-5" /> },
};

function bandColor(band: string) {
  return band === "CRITICAL" ? "#f87171" : band === "HIGH" ? "#fb923c" : band === "MEDIUM" ? "#facc15" : "#4ade80";
}

export default function EntityDetail() {
  const { entityType = "user", value = "" } = useParams();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["entity", entityType, value],
    queryFn: async () =>
      (await api.get<EntityDetailType>(`/ueba/entity/${entityType}/${encodeURIComponent(value)}`)).data,
  });

  const meta = TYPE_META[entityType] ?? { label: "Entity", icon: <Fingerprint className="h-5 w-5" /> };

  if (isLoading) {
    return <div className="grid gap-4 md:grid-cols-2"><Skeleton className="h-32" /><Skeleton className="h-32" /><Skeleton className="h-64 md:col-span-2" /></div>;
  }
  if (isError || !data) {
    return (
      <Card>
        <EmptyState icon={<ShieldAlert className="h-8 w-8" />} title="Entity not found"
          description={`No ${entityType} record for this value, or the entity type is invalid.`} />
      </Card>
    );
  }

  const color = bandColor(data.band);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-electric-500/10 text-electric-400">{meta.icon}</div>
        <div>
          <h2 className="text-lg font-bold text-slate-100">{meta.label} drill-down</h2>
          <p className="font-mono text-xs text-electric-400">{data.entity}</p>
        </div>
        <ProvenanceBadge source="DATASET" />
        <span className="badge border border-night-700 text-slate-500">computed from event corpus · {data.note.split(";")[0]}</span>
        <Link to={`/threat-analyzer?q=${encodeURIComponent(data.entity)}`} className="btn-primary ml-auto">
          <Fingerprint className="h-4 w-4" /> Analyze & predict
        </Link>
      </div>

      {/* Risk summary */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <div className="glass glass-hover p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Risk score</p>
          <div className="mt-1 flex items-end gap-2">
            <p className="font-mono text-3xl font-black" style={{ color }}>{data.risk.toFixed(0)}</p>
            <span className="badge border" style={{ color, borderColor: `${color}44`, background: `${color}11` }}>{data.band}</span>
          </div>
        </div>
        <div className="glass glass-hover p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Events observed</p>
          <p className="mt-1 font-mono text-3xl font-bold text-electric-400">{data.events.toLocaleString()}</p>
        </div>
        <div className="glass glass-hover p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Intel matches</p>
          <p className="mt-1 font-mono text-3xl font-bold text-cyber-red">{data.intel_hits}</p>
        </div>
        <div className="glass glass-hover p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Related incidents</p>
          <p className="mt-1 font-mono text-3xl font-bold text-cyber-yellow">{data.related_incidents.length}</p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Risk components" subtitle="Weighted, explainable — every component has a source">
          <div className="space-y-2.5">
            {Object.entries(data.components).map(([name, score]) => (
              <div key={name} className="text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-300">{name}</span>
                  <span className="font-mono text-slate-400">{Number(score).toFixed(1)}</span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-night-800">
                  <div className="h-full rounded-full bg-electric-500/70" style={{ width: `${Math.min(100, Number(score))}%` }} />
                </div>
              </div>
            ))}
            <p className="pt-1 text-[10px] leading-relaxed text-slate-600">{data.note}</p>
          </div>
        </Card>

        <Card title={`UEBA profile — ${data.ueba.status}`} subtitle={`baseline ${data.ueba.baseline_events} events · current ${data.ueba.current_events} events`}>
          {data.ueba.factors.length === 0 ? (
            <p className="text-xs text-slate-500">{data.ueba.note}</p>
          ) : (
            <div className="space-y-2">
              {data.ueba.factors.map((f) => (
                <div key={f.name} className="flex items-start justify-between gap-3 rounded-lg border border-night-700 bg-night-850/60 p-2.5 text-xs">
                  <div>
                    <p className="font-semibold text-slate-200">{f.name}</p>
                    <p className="mt-0.5 text-[10px] text-slate-500">{f.evidence}</p>
                  </div>
                  <span className="font-mono font-bold" style={{ color: f.score >= 20 ? "#f87171" : "#facc15" }}>+{f.score}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Behavioral features" subtitle="From the entity's event history">
          <div className="grid grid-cols-2 gap-3 text-sm">
            {[
              ["Off-hours ratio", data.features.off_hours_ratio],
              ["Failed-login ratio", data.features.failed_ratio],
              ["Distinct devices", data.features.distinct_devices],
              ["Distinct IPs", data.features.distinct_ips],
              ["Anomaly ratio", data.features.anomaly_ratio],
              ["Rate (events/hr)", data.features.rate_per_hour],
            ].map(([label, val]) => (
              <div key={label as string}>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
                <p className="font-mono text-lg font-bold text-slate-200">{typeof val === "number" && val <= 1 ? `${(val * 100).toFixed(0)}%` : val}</p>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Threat-intel feed" subtitle={`${data.intel.length} match(es) for this entity`}>
          {data.intel.length === 0 ? (
            <p className="text-xs text-slate-500">No feed match — not known, never guessed.</p>
          ) : (
            <div className="space-y-2">
              {data.intel.map((h, i) => (
                <div key={i} className="rounded-lg border border-night-700 bg-night-850/60 p-2.5">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={h.severity} />
                    <span className="font-mono text-xs font-bold text-electric-400">{h.value}</span>
                    <span className="badge border border-night-700 text-slate-500">{h.indicator_type}</span>
                  </div>
                  <p className="mt-1 text-[10px] text-slate-500">confidence {(h.confidence * 100).toFixed(0)}% · {h.match_reason} · {h.source}</p>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Asset record" subtitle="Known asset linked to this entity">
          {data.asset ? (
            <div className="space-y-2 text-xs">
              <div className="flex justify-between"><span className="text-slate-500">Name</span><span className="font-mono font-bold text-electric-400">{data.asset.name}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Type</span><span className="text-slate-300">{data.asset.asset_type}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Hostname</span><span className="font-mono text-slate-300">{data.asset.hostname ?? "—"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">IP</span><span className="font-mono text-slate-300">{data.asset.ip_address ?? "—"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Criticality</span><span className="font-mono text-cyber-yellow">{data.asset.criticality}/5</span></div>
              {data.asset.owner && <div className="flex justify-between"><span className="text-slate-500">Owner</span><span className="text-slate-300">{data.asset.owner}</span></div>}
            </div>
          ) : (
            <p className="text-xs text-slate-500">No asset record mapped to this {entityType}.</p>
          )}
        </Card>
      </div>

      <Card title="Related incidents" subtitle="Incidents whose events involved this entity">
        {data.related_incidents.length === 0 ? (
          <p className="text-xs text-slate-500">No incidents linked to this entity's events.</p>
        ) : (
          <div className="space-y-1.5">
            {data.related_incidents.map((inc) => (
              <Link key={inc.incident_id} to={`/incidents/${inc.id ?? inc.incident_id}`} className="flex items-center justify-between rounded-lg border border-night-700 bg-night-850/50 px-3 py-2 text-xs transition hover:border-electric-500/40">
                <span className="font-mono font-bold text-electric-400">{inc.incident_id}</span>
                <span className="max-w-[320px] truncate text-slate-300">{inc.title}</span>
                <div className="flex items-center gap-1.5">
                  <SeverityBadge severity={inc.severity} />
                  <StatusBadge status={inc.status} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>

      <Card title="Recent events" subtitle={`Last ${data.recent_events.length} events involving this entity`}>
        {data.recent_events.length === 0 ? (
          <p className="text-xs text-slate-500">No events observed for this entity.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr><th>Timestamp</th><th>Event ID</th><th>Type</th><th>Severity</th><th>Anomaly</th><th>Detection reason</th></tr>
              </thead>
              <tbody>
                {data.recent_events.map((e) => (
                  <tr key={e.event_id}>
                    <td className="whitespace-nowrap font-mono text-xs text-slate-400">{e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</td>
                    <td className="font-mono text-[11px] text-electric-400">{e.event_id}</td>
                    <td className="font-mono text-xs text-slate-200">{e.event_type}</td>
                    <td><SeverityBadge severity={e.severity} /></td>
                    <td>{e.is_anomalous ? <span className="badge border border-cyber-red/30 bg-cyber-red/10 text-cyber-red">ANOMALOUS</span> : <span className="badge border border-night-700 text-slate-600">normal</span>}</td>
                    <td className="max-w-[280px] truncate text-xs text-slate-500">{e.detection_reason ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
