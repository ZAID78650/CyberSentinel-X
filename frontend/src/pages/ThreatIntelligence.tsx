import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Fingerprint, Search, ShieldAlert } from "lucide-react";
import { api } from "../services/api";
import { Card, EmptyState, SeverityBadge, Skeleton } from "../components/ui";
import type { MitreTechnique, Paginated, ThreatIndicator } from "../types";

export default function ThreatIntelligence() {
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [tab, setTab] = useState<"indicators" | "mitre">("indicators");

  const { data: indicators, isLoading } = useQuery({
    queryKey: ["indicators"],
    queryFn: async () => (await api.get<Paginated<ThreatIndicator>>("/threat-intelligence", { params: { page_size: 100 } })).data,
  });

  const { data: mitre } = useQuery({
    queryKey: ["mitre"],
    queryFn: async () => (await api.get<MitreTechnique[]>(`/threat-intelligence/mitre`)).data,
  });

  const { data: searchResult, isFetching: searching } = useQuery({
    queryKey: ["intel-search", submitted],
    queryFn: async () => {
      const res = await api.post<{ hits: Array<Record<string, unknown>>; source_count: number }>("/threat-intelligence/search", {
        query: submitted,
      });
      return res.data;
    },
    enabled: submitted.length > 0,
  });

  const handleSearch = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) setSubmitted(query.trim());
  };

  return (
    <div className="space-y-4">
      <Card>
        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              className="input pl-10"
              placeholder="Search IP, domain, URL, hash, CVE, malware…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-primary" disabled={searching}>
            <Fingerprint className="h-4 w-4" /> Query intel
          </button>
        </form>

        {searchResult && (
          <div className="mt-4">
            <p className="mb-2 text-xs font-semibold text-slate-400">
              {searchResult.hits.length} match(es) across {searchResult.source_count} sources
            </p>
            {searchResult.hits.length === 0 ? (
              <p className="text-xs text-slate-600">No local intelligence matches. Try an IP from the demo (e.g. 45.155.205.233).</p>
            ) : (
              <div className="grid gap-2 md:grid-cols-2">
                {searchResult.hits.map((h, i) => (
                  <div key={i} className="rounded-lg border border-night-700 bg-night-850/60 p-3">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={h.severity as string} />
                      <span className="font-mono text-xs font-bold text-electric-400">{h.value as string}</span>
                      <span className="badge border border-night-700 text-slate-500">{h.indicator_type as string}</span>
                    </div>
                    <p className="mt-1.5 text-xs text-slate-400">{h.description as string}</p>
                    <p className="mt-1 text-[10px] text-slate-600">
                      confidence {(h.confidence as number * 100).toFixed(0)}% · {h.match_reason as string}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Card>

      <div className="flex gap-1 border-b border-night-700/70">
        {(["indicators", "mitre"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`border-b-2 px-4 py-2.5 text-sm font-semibold ${
              tab === t ? "border-electric-500 text-electric-400" : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            {t === "indicators" ? "Indicator Feed" : "MITRE ATT&CK Reference"}
          </button>
        ))}
      </div>

      {tab === "indicators" ? (
        <Card>
          {isLoading && !indicators ? (
            <div className="space-y-2">{[...Array(8)].map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
          ) : !indicators || indicators.items.length === 0 ? (
            <EmptyState icon={<ShieldAlert className="h-8 w-8" />} title="No indicators loaded" />
          ) : (
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th><th>Tags</th><th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {indicators.items.map((ind) => (
                    <tr key={ind.id}>
                      <td><span className="badge border border-night-700 text-slate-400">{ind.indicator_type}</span></td>
                      <td className="max-w-[200px] truncate font-mono text-xs text-electric-400">{ind.value}</td>
                      <td><SeverityBadge severity={ind.severity} /></td>
                      <td className="font-mono text-xs">{(ind.confidence * 100).toFixed(0)}%</td>
                      <td className="max-w-[180px]">
                        <div className="flex flex-wrap gap-1">
                          {ind.tags.slice(0, 3).map((t) => (
                            <span key={t} className="badge border border-night-700 text-slate-500">{t}</span>
                          ))}
                        </div>
                      </td>
                      <td className="max-w-[260px] truncate text-xs text-slate-500">{ind.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : (
        <Card title="MITRE ATT&CK Techniques" subtitle="Embedded knowledge base used for incident mapping">
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {mitre?.map((t) => (
              <a
                key={t.technique_id}
                href={t.url ?? `https://attack.mitre.org/techniques/${t.technique_id}/`}
                target="_blank"
                rel="noreferrer"
                className="rounded-lg border border-night-700 bg-night-850/60 p-3 transition hover:border-electric-500/50"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-electric-400">{t.technique_id}</span>
                  <span className="text-[10px] uppercase tracking-wide text-slate-600">{t.tactic}</span>
                </div>
                <p className="mt-1 text-xs font-semibold text-slate-200">{t.name}</p>
                <p className="mt-1 line-clamp-2 text-[11px] leading-snug text-slate-500">{t.description}</p>
              </a>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
