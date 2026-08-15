import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radar } from "lucide-react";
import { api } from "../services/api";
import IncidentDetail from "../components/incident/IncidentDetail";
import { Card, EmptyState, Skeleton } from "../components/ui";
import type { Paginated, Incident } from "../types";

export default function Investigation() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data: incidents } = useQuery({
    queryKey: ["incidents", "latest"],
    queryFn: async () => (await api.get<Paginated<Incident>>("/incidents", { params: { page: 1, page_size: 10 } })).data,
  });

  useEffect(() => {
    if (!selectedId && incidents && incidents.items.length > 0) {
      setSelectedId(incidents.items[0].id);
    }
  }, [incidents, selectedId]);

  if (!selectedId) {
    return (
      <Card>
        {incidents && incidents.items.length === 0 ? (
          <EmptyState
            icon={<Radar className="h-8 w-8" />}
            title="No investigations yet"
            description="Run an attack simulation to start an AI investigation."
          />
        ) : (
          <Skeleton className="h-96" />
        )}
      </Card>
    );
  }

  return <IncidentDetail incidentId={selectedId} backTo="/incidents" />;
}
