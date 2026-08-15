import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Boxes, Dna, FileText, Fingerprint, Loader2, Search, Target } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import type { GlobalSearchResult } from "../types";

function short(s?: string | null, n = 14): string {
  if (!s) return "—";
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

export default function GlobalSearch() {
  const [params, setParams] = useSearchParams();
  const initial = params.get("q") ?? "";
  const [query, setQuery] = useState(initial);
  const [result, setResult] = useState<GlobalSearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const search = async (q: string) => {
    const text = q.trim();
    if (!text) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<GlobalSearchResult>("/soc/search", { params: { q: text, limit: 20 } });
      setResult(res.data);
      setParams({ q: text }, { replace: true });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initial) void search(initial);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sections: Array<{ key: keyof GlobalSearchResult["results"]; label: string; icon: React.ReactNode; count: number }> = [
    { key: "incidents", label: "Incidents", icon: <FileText className="h-3.5 w-3.5" />, count: result?.results.incidents.length ?? 0 },
    { key: "alerts", label: "Alerts", icon: <Target className="h-3.5 w-3.5" />, count: result?.results.alerts.length ?? 0 },
    { key: "events", label: "Events", icon: <Search className="h-3.5 w-3.5" />, count: result?.results.events.length ?? 0 },
    { key: "dna", label: "Attack DNA", icon: <Dna className="h-3.5 w-3.5" />, count: result?.results.dna.length ?? 0 },
    { key: "techniques", label: "MITRE", icon: <Target className="h-3.5 w-3.5" />, count: result?.results.techniques.length ?? 0 },
    { key: "evidence", label: "Evidence", icon: <Boxes className="h-3.5 w-3.5" />, count: result?.results.evidence.length ?? 0 },
  ];

  return (
    <div className="space-y-5">
      <Card title="Global Search 2.0" subtitle="One box across incidents, alerts, events, Attack DNA, MITRE techniques and evidence">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              ref={inputRef}
              className="w-full rounded-lg border border-night-700 bg-night-850 py-2.5 pl-10 pr-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-electric-500/50 focus:outline-none"
              placeholder="Search an IP, incident ID, alert, DNA hash, MITRE technique or CVE…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void search(query)}
            />
          </div>
          <button className="btn-primary" onClick={() => void search(query)} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Search
          </button>
          <Link to={`/threat-analyzer?q=${encodeURIComponent(query.trim())}`}
            className={`btn-ghost ${!query.trim() ? "pointer-events-none opacity-40" : ""}`}>
            <Fingerprint className="h-4 w-4" /> Analyze
          </Link>
        </div>
      </Card>

      {error && <div className="rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>}

      {loading && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-40" />)}
        </div>
      )}

      {!loading && result && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {sections.map((s) => {
            const items = result.results[s.key];
            if (items.length === 0) return null;
            return (
              <Card key={s.key} title={`${s.label} (${s.count})`}>
                <div className="space-y-2">
                  {items.map((it, i) => <Row key={i} section={s.key} item={it as never} />)}
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {!loading && !result && (
        <Card>
          <EmptyState icon={<Search className="h-8 w-8" />} title="Search the SOC"
            description="Find incidents, alerts, events, Attack DNA fingerprints, MITRE techniques and evidence records in one place." />
        </Card>
      )}
    </div>
  );
}

function Row({ section, item }: { section: keyof GlobalSearchResult["results"]; item: never }) {
  switch (section) {
    case "incidents": {
      const i = item as GlobalSearchResult["results"]["incidents"][number];
      return (
        <Link to={`/incidents/${i.id}`} className="block rounded-lg border border-night-700 bg-night-850/60 p-2.5 transition hover:border-electric-500/40">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] font-bold text-electric-400">{i.incident_id}</span>
            <div className="flex gap-1.5"><SeverityBadge severity={i.severity} /><StatusBadge status={i.status} /></div>
          </div>
          <p className="mt-1 truncate text-xs font-semibold text-slate-200">{i.title}</p>
          <p className="text-[10px] text-slate-500">risk {i.risk_score?.toFixed(0) ?? "—"}</p>
        </Link>
      );
    }
    case "alerts": {
      const a = item as GlobalSearchResult["results"]["alerts"][number];
      return (
        <Link to={`/alerts`} className="block rounded-lg border border-night-700 bg-night-850/60 p-2.5 transition hover:border-electric-500/40">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] font-bold text-cyber-yellow">{a.alert_id}</span>
            <div className="flex gap-1.5"><SeverityBadge severity={a.severity} /><StatusBadge status={a.status} /></div>
          </div>
          <p className="mt-1 truncate text-xs font-semibold text-slate-200">{a.title}</p>
        </Link>
      );
    }
    case "events": {
      const e = item as GlobalSearchResult["results"]["events"][number];
      return (
        <div className="rounded-lg border border-night-700 bg-night-850/60 p-2.5">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] font-bold text-slate-200">{e.event_type}</span>
            <div className="flex items-center gap-1.5"><SeverityBadge severity={e.severity} /></div>
          </div>
          <p className="mt-1 font-mono text-[10px] text-slate-400">
            {e.source_ip ? <Link to={`/entity/ip/${encodeURIComponent(e.source_ip)}`} className="text-electric-400 hover:underline">{short(e.source_ip)}</Link> : "—"} →{" "}
            {e.destination_ip ? <Link to={`/entity/ip/${encodeURIComponent(e.destination_ip)}`} className="text-electric-400 hover:underline">{short(e.destination_ip)}</Link> : "—"}
          </p>
          <p className="text-[9px] text-slate-600">{new Date(e.timestamp).toLocaleString()}</p>
          <Link to={`/threat-analyzer?q=${encodeURIComponent(e.event_id)}`} className="mt-1.5 inline-flex items-center gap-1 rounded-md border border-night-700 px-1.5 py-0.5 text-[9px] font-semibold text-slate-400 transition hover:border-electric-500/50 hover:text-electric-400">
            <Fingerprint className="h-2.5 w-2.5" /> Analyze
          </Link>
        </div>
      );
    }
    case "dna": {
      const d = item as GlobalSearchResult["results"]["dna"][number];
      return (
        <Link to={`/attack-dna`} className="block rounded-lg border border-night-700 bg-night-850/60 p-2.5 transition hover:border-electric-500/40">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] font-bold text-cyber-purple">{d.dna_id}</span>
            <span className="badge border border-cyber-purple/30 bg-cyber-purple/10 text-cyber-purple">{d.family}</span>
          </div>
          <p className="mt-1 font-mono text-[9px] text-slate-500">0x{short(d.fingerprint, 18)}</p>
        </Link>
      );
    }
    case "techniques": {
      const t = item as GlobalSearchResult["results"]["techniques"][number];
      return (
        <a href={`https://attack.mitre.org/techniques/${t.technique_id}/`} target="_blank" rel="noreferrer"
          className="block rounded-lg border border-night-700 bg-night-850/60 p-2.5 transition hover:border-electric-500/40">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] font-bold text-electric-400">{t.technique_id}</span>
            <span className="text-[9px] uppercase text-slate-500">{t.tactic}</span>
          </div>
          <p className="mt-1 truncate text-xs font-semibold text-slate-200">{t.name}</p>
        </a>
      );
    }
    case "evidence": {
      const ev = item as GlobalSearchResult["results"]["evidence"][number];
      return (
        <Link to={`/evidence-ledger`} className="block rounded-lg border border-night-700 bg-night-850/60 p-2.5 transition hover:border-electric-500/40">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] font-bold text-electric-400">{ev.evidence_id}</span>
            <StatusBadge status={ev.status} />
          </div>
          <p className="mt-1 truncate text-xs font-semibold text-slate-200">{ev.title}</p>
        </Link>
      );
    }
    default:
      return null;
  }
}
