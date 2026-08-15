import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { api } from "../services/api";
import IncidentDetail from "../components/incident/IncidentDetail";
import { Card, EmptyState, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import type { Incident, Paginated, Recommendation } from "../types";

export default function ResponseCenter() {
  const [selected, setSelected] = useState<string | null>(null);

  const { data: incidents } = useQuery({
    queryKey: ["incidents", "response"],
    queryFn: async () => (await api.get<Paginated<Incident>>("/incidents", { params: { page: 1, page_size: 20 } })).data,
  });

  if (selected) {
    return <IncidentDetail incidentId={selected} backTo="/response-center" />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-electric-400" />
        <h2 className="text-lg font-bold text-slate-100">Response Center</h2>
        <p className="text-xs text-slate-500">Recommended actions with human approval — execution is simulated</p>
      </div>

      {!incidents ? (
        <Skeleton className="h-96" />
      ) : incidents.items.length === 0 ? (
        <Card><EmptyState icon={<ShieldCheck className="h-8 w-8" />} title="No incidents to respond to" /></Card>
      ) : (
        incidents.items.map((inc) => <IncidentResponseCard key={inc.id} incident={inc} onOpen={() => setSelected(inc.id)} />)
      )}
    </div>
  );
}

function IncidentResponseCard({ incident, onOpen }: { incident: Incident; onOpen: () => void }) {
  const { data: recs } = useQuery({
    queryKey: ["recommendations", incident.id],
    queryFn: async () => (await api.get<Recommendation[]>(`/response-recommendations/${incident.id}`)).data,
  });

  return (
    <Card
      title={incident.title}
      subtitle={`${incident.incident_id} · created ${new Date(incident.created_at).toLocaleString()}`}
      actions={
        <div className="flex items-center gap-2">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
        </div>
      }
    >
      {!recs ? (
        <div className="space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
      ) : (
        <div className="space-y-2">
          {recs.map((r) => (
            <div key={r.id} className="flex flex-wrap items-center gap-3 rounded-lg bg-night-850/60 px-4 py-2.5">
              <span className="flex-1 text-sm text-slate-200">{r.action}</span>
              <StatusBadge status={r.status} />
              <button onClick={onOpen} className="btn-ghost px-3 py-1 text-xs">Open incident</button>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
