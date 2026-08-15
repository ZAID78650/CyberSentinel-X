import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BookOpen, FileText, FlaskConical, Loader2, ScrollText, ShieldAlert } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, Skeleton } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { PlaybookDoc, PlaybookSimulation } from "../types";

const DOC_META: Record<string, { icon: React.ReactNode; color: string }> = {
  playbook: { icon: <ScrollText className="h-4 w-4" />, color: "#38bdf8" },
  policy: { icon: <FileText className="h-4 w-4" />, color: "#a78bfa" },
  cve: { icon: <ShieldAlert className="h-4 w-4" />, color: "#f87171" },
  mitre: { icon: <BookOpen className="h-4 w-4" />, color: "#4ade80" },
};

function PlaybookCard({ doc }: { doc: PlaybookDoc }) {
  const [open, setOpen] = useState(false);
  const simulate = useMutation({
    mutationFn: async () => (await api.post<PlaybookSimulation>(`/security/playbooks/${doc.id}/simulate`)).data,
  });
  const meta = DOC_META[doc.doc_type] ?? { icon: <FileText className="h-4 w-4" />, color: "#94a3b8" };
  const r = simulate.data;

  return (
    <Card className="glass-hover">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg" style={{ background: `${meta.color}18`, color: meta.color }}>
          {meta.icon}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <p className="truncate text-sm font-semibold text-slate-200">{doc.title}</p>
            <span className="badge border border-night-700 text-[10px] uppercase text-slate-400">{doc.doc_type}</span>
          </div>
          <p className="mt-1.5 line-clamp-3 text-xs leading-relaxed text-slate-500">{doc.content_preview}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {doc.tags.map((t) => (
              <span key={t} className="rounded bg-night-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">{t}</span>
            ))}
            <span className="ml-auto text-[10px] text-slate-600">{doc.chunk_count} chunks</span>
          </div>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-2 border-t border-night-800 pt-3">
        <button className="btn-ghost" onClick={() => setOpen((o) => !o)}>
          <FlaskConical className="h-3.5 w-3.5" /> What-if simulation
        </button>
        {simulate.isError && (
          <span className="text-[10px] text-cyber-red">{getErrorMessage(simulate.error)}</span>
        )}
      </div>

      {open && (
        <div className="mt-3 rounded-lg border border-cyber-yellow/30 bg-cyber-yellow/5 p-3">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-semibold text-slate-200">Projected risk reduction over affected assets</p>
            <ProvenanceBadge source="SIMULATED" />
          </div>
          <p className="mt-1 text-[10px] text-slate-500">{simulate.data?.provenance.basis ?? "Projection from current per-asset exposure — not measured impact."}</p>

          {simulate.isPending && (
            <div className="mt-3 space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-8" />)}</div>
          )}

          {r && (
            <div className="mt-3 space-y-3">
              <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Affected assets</p>
                  <p className="font-mono text-xl font-bold text-electric-400">{r.asset_count}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Exposure before</p>
                  <p className="font-mono text-xl font-bold text-cyber-red">{r.exposure_before.toFixed(1)}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Exposure after</p>
                  <p className="font-mono text-xl font-bold text-cyber-green">{r.exposure_after.toFixed(1)}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Projected reduction</p>
                  <p className="font-mono text-xl font-bold text-cyber-green">−{r.projected_reduction_pct.toFixed(0)}%</p>
                </div>
              </div>

              <div className="space-y-1.5">
                {r.affected_assets.slice(0, 8).map((a) => (
                  <div key={a.name} className="flex items-center gap-2 text-[11px]">
                    <span className="w-40 truncate font-mono text-slate-300">{a.name}</span>
                    <span className="badge border border-night-700 text-[9px] text-slate-500">crit {a.criticality}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-night-800">
                      <div className="h-full rounded-full bg-cyber-red/70" style={{ width: `${a.exposure}%` }} />
                    </div>
                    <span className="w-8 text-right font-mono text-cyber-red">{a.exposure.toFixed(0)}</span>
                    <FlaskConical className="h-3 w-3 text-cyber-yellow" />
                    <div className="h-1.5 w-16 overflow-hidden rounded-full bg-night-800">
                      <div className="h-full rounded-full bg-cyber-green/70" style={{ width: `${a.exposure_after}%` }} />
                    </div>
                    <span className="w-8 text-right font-mono text-cyber-green">{a.exposure_after.toFixed(0)}</span>
                  </div>
                ))}
              </div>

              <p className="text-[10px] text-slate-600">
                {r.note} Control signals: {r.control_signals.length > 0 ? r.control_signals.join(", ") : "none detected"} · ratio {r.reduction_ratio}
              </p>
            </div>
          )}

          {!simulate.isPending && !r && (
            <button className="btn-primary mt-3" onClick={() => simulate.mutate()} disabled={simulate.isPending}>
              {simulate.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />}
              Run simulation
            </button>
          )}
        </div>
      )}
    </Card>
  );
}

export default function Playbooks() {
  const [filter, setFilter] = useState<string>("");
  const { data, isLoading } = useQuery({
    queryKey: ["playbooks"],
    queryFn: async () => (await api.get("/security/playbooks", { params: { page_size: 200 } })).data,
  });

  const items: PlaybookDoc[] = (data?.items ?? []).filter((d: PlaybookDoc) => !filter || d.doc_type === filter);
  const docTypes: string[] = Array.from(new Set((data?.items ?? []).map((d: PlaybookDoc) => d.doc_type)));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-slate-100">Playbooks & Knowledge Base</h2>
          <p className="text-xs text-slate-500">{data?.total ?? 0} documents · RAG-indexed response procedures · what-if simulation on every card</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setFilter("")} className={`btn-ghost ${!filter ? "ring-1 ring-electric-500/50" : ""}`}>All</button>
          {docTypes.map((t) => (
            <button key={t} onClick={() => setFilter(filter === t ? "" : t)} className={`btn-ghost ${filter === t ? "ring-1 ring-electric-500/50" : ""}`}>
              {t}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2"><Skeleton className="h-36" /><Skeleton className="h-36" /><Skeleton className="h-36" /></div>
      ) : items.length === 0 ? (
        <Card><p className="py-10 text-center text-sm text-slate-500">No documents match this filter.</p></Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {items.map((d) => <PlaybookCard key={d.id} doc={d} />)}
        </div>
      )}
    </div>
  );
}
