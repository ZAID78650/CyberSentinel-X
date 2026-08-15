import { useState } from "react";
import { Bookmark, Loader2, Radar, Search, ShieldCheck } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, SeverityBadge, StatusBadge } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import type { HuntResult } from "../types";

const EXAMPLES = [
  "Find all critical incidents in the last 6 hours",
  "Show endpoints with abnormal outbound traffic",
  "Find repeated authentication failures from 45.155.205.233",
  "Find assets associated with privilege escalation",
  "Find IP addresses appearing in multiple incidents",
  "Show malware detected in the last 24 hours with anomaly score above 0.8",
];

export default function ThreatHunting() {
  const { hasRole } = useAuth();
  const { success, error: toastError } = useToast();
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<"all" | "events" | "alerts" | "incidents">("all");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<HuntResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"events" | "alerts" | "incidents">("incidents");

  const run = async (q?: string) => {
    const text = (q ?? query).trim();
    if (!text) return;
    setRunning(true);
    setError(null);
    try {
      const res = await api.post<HuntResult>("/soc/threat-hunting", { query: text, scope });
      setResult(res.data);
      const first = (["incidents", "alerts", "events"] as const).find((k) => res.data.counts[k] > 0);
      if (first) setActiveTab(first);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setRunning(false);
    }
  };

  const save = async () => {
    try {
      await api.post("/soc/threat-hunting/save", { query, name: query.slice(0, 60), scope });
      success("Hunt saved", "Stored in the audit log for reuse.");
    } catch (err) {
      toastError("Save failed", getErrorMessage(err));
    }
  };

  const canSave = hasRole("ADMIN") || hasRole("SECURITY_ANALYST");

  return (
    <div className="space-y-5">
      {/* Query input */}
      <Card
        title="Threat Hunting Console"
        subtitle="Natural-language queries are translated into safe structured filters — never arbitrary SQL"
        actions={<ProvenanceBadge source="LOCAL" />}
      >
        <div className="relative">
          <Search className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
          <textarea
            className="w-full rounded-lg border border-night-700 bg-night-850 py-3 pl-10 pr-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-electric-500/50 focus:outline-none"
            rows={2}
            placeholder="Ask in plain English, e.g. “find login failures from 45.155.205.233 in the last 24 hours”"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) void run();
            }}
          />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-[11px] uppercase tracking-wider text-slate-600">Scope</span>
          {(["all", "events", "alerts", "incidents"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setScope(s)}
              className={`badge border capitalize transition-colors ${scope === s ? "border-electric-500/50 bg-electric-500/15 text-electric-400" : "border-night-700 bg-night-850 text-slate-500 hover:text-slate-300"}`}
            >
              {s}
            </button>
          ))}
          <button className="btn-primary ml-auto" onClick={() => void run()} disabled={running || !query.trim()}>
            {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
            Run hunt
          </button>
          {canSave && (
            <button className="btn-ghost" onClick={save} disabled={!query.trim()}>
              <Bookmark className="h-4 w-4" /> Save hunt
            </button>
          )}
        </div>

        <div className="mt-4 flex flex-wrap gap-1.5">
          {EXAMPLES.map((ex) => (
            <button key={ex} onClick={() => { setQuery(ex); void run(ex); }}
              className="rounded-md border border-night-700 bg-night-850/60 px-2.5 py-1.5 text-left text-[10px] text-slate-400 transition hover:border-electric-500/40 hover:text-slate-200">
              {ex}
            </button>
          ))}
        </div>
      </Card>

      {error && <div className="rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>}

      {/* Generated query */}
      {result && (
        <Card title="Generated Query" subtitle={`Confidence ${Math.round(result.confidence * 100)}% · safe whitelisted filters only`}
          actions={<span className="flex items-center gap-1 text-[11px] text-cyber-green"><ShieldCheck className="h-3.5 w-3.5" /> NO RAW SQL</span>}>
          <div className="flex flex-wrap gap-2">
            {result.generated_filters.map((f) => (
              <code key={f} className="rounded-md border border-electric-500/30 bg-electric-500/10 px-2.5 py-1.5 font-mono text-[11px] text-electric-400">{f}</code>
            ))}
          </div>
          <div className="mt-3 grid grid-cols-3 gap-2 text-center">
            <div className="rounded-md bg-night-850/60 p-2">
              <p className="font-mono text-xl font-bold text-cyber-red">{result.counts.events.toLocaleString()}</p>
              <p className="text-[9px] uppercase tracking-wider text-slate-500">events</p>
            </div>
            <div className="rounded-md bg-night-850/60 p-2">
              <p className="font-mono text-xl font-bold text-cyber-yellow">{result.counts.alerts.toLocaleString()}</p>
              <p className="text-[9px] uppercase tracking-wider text-slate-500">alerts</p>
            </div>
            <div className="rounded-md bg-night-850/60 p-2">
              <p className="font-mono text-xl font-bold text-electric-400">{result.counts.incidents.toLocaleString()}</p>
              <p className="text-[9px] uppercase tracking-wider text-slate-500">incidents</p>
            </div>
          </div>
        </Card>
      )}

      {/* Results */}
      {result && (
        <Card title="Results" subtitle={`Query: “${result.query}”`}>
          <div className="mb-3 flex gap-1 border-b border-night-700/70">
            {(["events", "alerts", "incidents"] as const).map((k) => (
              <button key={k}
                onClick={() => setActiveTab(k)}
                className={`border-b-2 px-4 py-2 text-sm font-semibold capitalize transition-colors ${activeTab === k ? "border-electric-500 text-electric-400" : "border-transparent text-slate-500 hover:text-slate-300"}`}>
                {k} <span className="font-mono text-[10px]">{result.counts[k]}</span>
              </button>
            ))}
          </div>

          {activeTab === "events" && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-xs">
                <thead><tr className="border-b border-night-700/70 text-[10px] uppercase tracking-wider text-slate-500">
                  <th className="py-2 pr-3">Time</th><th className="py-2 pr-3">Type</th><th className="py-2 pr-3">Severity</th>
                  <th className="py-2 pr-3">Source</th><th className="py-2 pr-3">Dest</th><th className="py-2 pr-3">Anomaly</th>
                </tr></thead>
                <tbody>
                  {result.results.events.map((e) => (
                    <tr key={e.event_id} className="border-b border-night-800/60 hover:bg-night-850/40">
                      <td className="py-2 pr-3 font-mono text-[10px] text-slate-500">{new Date(e.timestamp).toLocaleString()}</td>
                      <td className="py-2 pr-3 font-mono text-slate-200">{e.event_type}</td>
                      <td className="py-2 pr-3"><SeverityBadge severity={e.severity} /></td>
                      <td className="py-2 pr-3 font-mono text-[11px] text-slate-300">{e.source_ip ?? "—"}</td>
                      <td className="py-2 pr-3 font-mono text-[11px] text-slate-300">{e.destination_ip ?? "—"}</td>
                      <td className="py-2 pr-3">{e.anomaly_score != null ? <span className={`font-mono ${e.anomaly_score > 0.7 ? "text-cyber-red" : "text-slate-300"}`}>{e.anomaly_score.toFixed(2)}</span> : "—"}</td>
                    </tr>
                  ))}
                  {result.results.events.length === 0 && <tr><td colSpan={6} className="py-6 text-center text-slate-600">No matching events</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === "alerts" && (
            <div className="space-y-2">
              {result.results.alerts.map((a) => (
                <div key={a.id} className="flex items-center justify-between rounded-lg border border-night-700 bg-night-850/60 px-3 py-2.5">
                  <div>
                    <p className="text-xs font-semibold text-slate-200">{a.title}</p>
                    <p className="font-mono text-[10px] text-slate-600">{a.alert_id} · {a.category}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    <StatusBadge status={a.status} />
                  </div>
                </div>
              ))}
              {result.results.alerts.length === 0 && <p className="py-6 text-center text-xs text-slate-600">No matching alerts</p>}
            </div>
          )}

          {activeTab === "incidents" && (
            <div className="space-y-2">
              {result.results.incidents.map((i) => (
                <div key={i.id} className="flex items-center justify-between rounded-lg border border-night-700 bg-night-850/60 px-3 py-2.5">
                  <div className="min-w-0">
                    <p className="truncate text-xs font-semibold text-slate-200">{i.title}</p>
                    <p className="font-mono text-[10px] text-slate-600">{i.incident_id} · {i.category} · risk {i.risk_score?.toFixed(0) ?? "—"}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <SeverityBadge severity={i.severity} />
                    <StatusBadge status={i.status} />
                    <a href={`#/incidents/${i.id}`} className="text-electric-400 hover:underline">open</a>
                  </div>
                </div>
              ))}
              {result.results.incidents.length === 0 && <p className="py-6 text-center text-xs text-slate-600">No matching incidents</p>}
            </div>
          )}
        </Card>
      )}

      {!result && (
        <Card>
          <EmptyState icon={<Radar className="h-8 w-8" />} title="Run a hunt to see results"
            description="Try one of the example queries above — the console translates it into structured filters and searches real events, alerts and incidents." />
        </Card>
      )}
    </div>
  );
}
