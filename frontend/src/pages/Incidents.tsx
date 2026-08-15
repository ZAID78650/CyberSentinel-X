import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Radar, Siren } from "lucide-react";
import { api } from "../services/api";
import IncidentDetail from "../components/incident/IncidentDetail";
import { Card, EmptyState, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import type { Incident, Paginated } from "../types";

export default function Incidents() {
  const [params] = useSearchParams();
  const { id } = useParams();
  const openId = id ?? params.get("open");

  if (openId) return <IncidentDetail incidentId={openId} />;
  return <IncidentList />;
}

function IncidentList() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["incidents", page, status, severity],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, page_size: 20 };
      if (status) params.status = status;
      if (severity) params.severity = severity;
      return (await api.get<Paginated<Incident>>("/incidents", { params })).data;
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-bold text-slate-100">Incidents</h2>
        <select className="input w-auto" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
          <option value="">All statuses</option>
          {["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="input w-auto" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All severities</option>
          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      <Card>
        {isLoading && !data ? (
          <div className="space-y-2">{[...Array(8)].map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
        ) : !data || data.items.length === 0 ? (
          <EmptyState icon={<Siren className="h-8 w-8" />} title="No incidents" description="Correlated attack chains appear here." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Risk</th><th>Category</th><th>Created</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((inc) => (
                  <IncidentRow key={inc.id} incident={inc} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {data && (
          <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
            <span>Page {data.page} of {data.pages} · {data.total} incidents</span>
            <div className="flex gap-2">
              <button className="btn-ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
              <button className="btn-ghost" disabled={page >= data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function IncidentRow({ incident }: { incident: Incident }) {
  const riskColor = (incident.risk_score ?? 0) > 60 ? "#f87171" : (incident.risk_score ?? 0) > 30 ? "#facc15" : "#4ade80";
  return (
    <tr className="cursor-pointer" onClick={() => (window.location.href = `/incidents/${incident.id}`)}>
      <td className="font-mono text-xs text-electric-400">{incident.incident_id}</td>
      <td className="max-w-[280px] truncate font-medium text-slate-200">{incident.title}</td>
      <td><SeverityBadge severity={incident.severity} /></td>
      <td><StatusBadge status={incident.status} /></td>
      <td className="font-mono text-xs" style={{ color: riskColor }}>
        {incident.risk_score != null ? `${Math.round(incident.risk_score)} (${incident.risk_label})` : "—"}
      </td>
      <td className="text-xs text-slate-400">{incident.category}</td>
      <td className="whitespace-nowrap text-xs text-slate-500">{new Date(incident.created_at).toLocaleString()}</td>
      <td>
        <Link to={`/incidents/${incident.id}/war-room`} onClick={(e) => e.stopPropagation()}
          className="flex items-center gap-1 rounded-md border border-cyber-green/30 bg-cyber-green/10 px-2 py-1 text-[10px] font-semibold text-cyber-green hover:bg-cyber-green/20">
          <Radar className="h-3 w-3" /> War Room
        </Link>
      </td>
    </tr>
  );
}
