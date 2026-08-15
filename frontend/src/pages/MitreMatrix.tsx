import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Target } from "lucide-react";
import { api } from "../services/api";
import { Card, Skeleton } from "../components/ui";
import type { MitreTechnique } from "../types";

export default function MitreMatrix() {
  const [query, setQuery] = useState("");
  const { data, isLoading } = useQuery({
    queryKey: ["mitre"],
    queryFn: async () => (await api.get<MitreTechnique[]>("/threat-intelligence/mitre")).data,
  });

  const groups = useMemo(() => {
    const rows = (data ?? []).filter((t) => {
      if (!query) return true;
      const q = query.toLowerCase();
      return t.technique_id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.tactic.toLowerCase().includes(q);
    });
    const map: Record<string, MitreTechnique[]> = {};
    for (const t of rows) {
      (map[t.tactic] ??= []).push(t);
    }
    return Object.entries(map).sort((a, b) => a[0].localeCompare(b[0]));
  }, [data, query]);

  const sevColor = (s: string) =>
    s === "CRITICAL" ? "#f87171" : s === "HIGH" ? "#fb923c" : s === "MEDIUM" ? "#facc15" : "#4ade80";

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyber-purple/10 text-cyber-purple">
            <Target className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-100">MITRE ATT&CK Matrix</h2>
            <p className="text-xs text-slate-500">{data?.length ?? 0} techniques mapped to your detection coverage</p>
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            className="input pl-9"
            placeholder="Search technique, tactic…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3"><Skeleton className="h-56" /><Skeleton className="h-56" /></div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {groups.map(([tactic, techniques]) => (
            <Card key={tactic} title={tactic.replace(/-/g, " ").toUpperCase()} subtitle={`${techniques.length} techniques`}>
              <div className="space-y-1.5">
                {techniques.map((t) => (
                  <div key={t.technique_id} className="group flex items-center gap-2 rounded-md bg-night-850/50 px-2.5 py-1.5">
                    <span className="font-mono text-[11px] font-bold text-electric-400">{t.technique_id}</span>
                    <span className="flex-1 truncate text-xs text-slate-300">{t.name}</span>
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: sevColor(t.severity_hint) }} title={t.severity_hint} />
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
