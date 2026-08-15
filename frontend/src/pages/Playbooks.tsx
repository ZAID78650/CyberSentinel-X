import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { BookOpen, FileText, ScrollText, ShieldAlert } from "lucide-react";
import { api } from "../services/api";
import { Card, Skeleton } from "../components/ui";
import type { PlaybookDoc } from "../types";

const DOC_META: Record<string, { icon: React.ReactNode; color: string }> = {
  playbook: { icon: <ScrollText className="h-4 w-4" />, color: "#38bdf8" },
  policy: { icon: <FileText className="h-4 w-4" />, color: "#a78bfa" },
  cve: { icon: <ShieldAlert className="h-4 w-4" />, color: "#f87171" },
  mitre: { icon: <BookOpen className="h-4 w-4" />, color: "#4ade80" },
};

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
          <p className="text-xs text-slate-500">{data?.total ?? 0} documents · RAG-indexed response procedures</p>
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
          {items.map((d) => {
            const meta = DOC_META[d.doc_type] ?? { icon: <FileText className="h-4 w-4" />, color: "#94a3b8" };
            return (
              <Card key={d.id} className="glass-hover">
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg" style={{ background: `${meta.color}18`, color: meta.color }}>
                    {meta.icon}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <p className="truncate text-sm font-semibold text-slate-200">{d.title}</p>
                      <span className="badge border border-night-700 text-[10px] uppercase text-slate-400">{d.doc_type}</span>
                    </div>
                    <p className="mt-1.5 line-clamp-3 text-xs leading-relaxed text-slate-500">{d.content_preview}</p>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      {d.tags.map((t) => (
                        <span key={t} className="rounded bg-night-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">{t}</span>
                      ))}
                      <span className="ml-auto text-[10px] text-slate-600">{d.chunk_count} chunks</span>
                    </div>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
