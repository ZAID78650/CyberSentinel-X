import { useEffect, useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { Fingerprint, Radar, Search, ShieldAlert, ShieldCheck, TrendingUp } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import { Card, SeverityBadge, Skeleton } from "../components/ui";

interface IntelHit {
  indicator_type: string;
  value: string;
  confidence: number;
  severity: string;
  source: string;
  tags: string[];
  description: string | null;
  match_reason: string;
}

interface AnalyzeResult {
  query: string;
  intel: IntelHit[];
  history: {
    seen: boolean;
    count: number;
    first_seen: string | null;
    last_seen: string | null;
    anomaly_ratio: number | null;
    related_incidents: Array<{ incident_id: string; title: string; severity: string; status: string }>;
  };
  risk: {
    score: number;
    band: string;
    components: Array<{ component: string; contribution: number; evidence: string }>;
  };
  prediction: {
    current_stage: string;
    predicted_stage: string;
    probability: number;
    confidence: number;
    incident_id: string;
  } | null;
  firewall: {
    malware_guard: boolean;
    malware_guard_note: string;
    ip_watch: boolean;
    ip_watch_note: string;
    blocked_indicators: string[];
  };
  provenance: { mode: string; basis: string };
}

function bandColor(band: string) {
  return band === "CRITICAL" ? "#f87171" : band === "HIGH" ? "#fb923c" : band === "MEDIUM" ? "#facc15" : "#4ade80";
}

export default function ThreatAnalyzer() {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") ?? "");
  const analyze = useMutation({
    mutationFn: async (q: string) => (await api.post<AnalyzeResult>("/security/analyze", { query: q })).data,
  });

  // Deep-link support: ?q=… auto-runs the analysis (from Live Events, Global
  // Search, entity drill-downs…), and re-runs when the query changes.
  const qParam = params.get("q");
  useEffect(() => {
    if (qParam && qParam !== query) {
      setQuery(qParam);
      analyze.mutate(qParam);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qParam]);
  useEffect(() => {
    if (query.trim() && !analyze.isSuccess) analyze.mutate(query.trim());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      analyze.mutate(query.trim());
      setParams({ q: query.trim() }, { replace: true });
    }
  };

  const r = analyze.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-bold text-slate-100">Threat Analyzer</h2>
        <span className="badge border border-night-700 text-slate-500">click an indicator → analyze & predict</span>
      </div>

      <Card title="Analyze & predict" subtitle="One click runs intel lookup, event-store history, explainable risk, next-stage prediction and a firewall verdict — all from real data.">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              className="input pl-10"
              placeholder="IP, hash, domain, user, asset, event ID… e.g. 45.155.205.233 or 44d88612fea8a8f36de82e1278abb02f"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-primary" disabled={analyze.isPending || !query.trim()}>
            {analyze.isPending ? <Skeleton className="h-4 w-16" /> : <Fingerprint className="h-4 w-4" />}
            Analyze & predict
          </button>
        </form>

        {analyze.isError && (
          <div className="mt-3 rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">
            {getErrorMessage(analyze.error)}
          </div>
        )}

        {analyze.isPending && <div className="mt-4 space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-20" />)}</div>}

        {r && (
          <div className="mt-5 space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-bold text-electric-400">{r.query}</span>
              <ProvenanceBadge source={r.provenance.mode} />
              <span className="badge border border-night-700 text-slate-500">{r.provenance.basis}</span>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <Card title="Threat intelligence" subtitle={`${r.intel.length} match(es) in the local feed`}>
                {r.intel.length === 0 ? (
                  <p className="text-xs text-slate-500">No local feed match — reported as not known, never guessed.</p>
                ) : (
                  <div className="space-y-2">
                    {r.intel.map((h, i) => (
                      <div key={i} className="rounded-lg border border-night-700 bg-night-850/60 p-3">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={h.severity} />
                          <span className="font-mono text-xs font-bold text-electric-400">{h.value}</span>
                          <span className="badge border border-night-700 text-slate-500">{h.indicator_type}</span>
                        </div>
                        <p className="mt-1.5 text-xs text-slate-400">{h.description}</p>
                        <p className="mt-1 text-[10px] text-slate-600">
                          confidence {(h.confidence * 100).toFixed(0)}% · {h.match_reason} · source {h.source}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card title="Event history" subtitle="What the platform has observed about this indicator">
                {!r.history.seen ? (
                  <p className="text-xs text-slate-500">Not observed in the event corpus.</p>
                ) : (
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div><p className="text-[10px] uppercase tracking-wider text-slate-500">events</p><p className="font-mono text-xl font-bold text-electric-400">{r.history.count.toLocaleString()}</p></div>
                    <div><p className="text-[10px] uppercase tracking-wider text-slate-500">anomaly ratio</p><p className="font-mono text-xl font-bold text-slate-200">{((r.history.anomaly_ratio ?? 0) * 100).toFixed(0)}%</p></div>
                    <div><p className="text-[10px] uppercase tracking-wider text-slate-500">first seen</p><p className="font-mono text-xs text-slate-300">{r.history.first_seen ? new Date(r.history.first_seen).toLocaleString() : "—"}</p></div>
                    <div><p className="text-[10px] uppercase tracking-wider text-slate-500">last seen</p><p className="font-mono text-xs text-slate-300">{r.history.last_seen ? new Date(r.history.last_seen).toLocaleString() : "—"}</p></div>
                  </div>
                )}
                {r.history.related_incidents.length > 0 && (
                  <div className="mt-3 space-y-1.5">
                    <p className="text-[10px] uppercase tracking-wider text-slate-500">related incidents</p>
                    {r.history.related_incidents.map((inc) => (
                      <div key={inc.incident_id} className="flex items-center justify-between rounded border border-night-700 bg-night-850/50 px-2.5 py-1.5 text-xs">
                        <span className="font-mono text-electric-400">{inc.incident_id}</span>
                        <span className="max-w-[180px] truncate text-slate-300">{inc.title}</span>
                        <SeverityBadge severity={inc.severity} />
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Card title="Risk score" subtitle="Explainable — every component cites evidence">
                <div className="flex items-end gap-3">
                  <p className="font-mono text-4xl font-black" style={{ color: bandColor(r.risk.band) }}>{r.risk.score.toFixed(0)}</p>
                  <span className="badge border" style={{ color: bandColor(r.risk.band), borderColor: `${bandColor(r.risk.band)}44`, background: `${bandColor(r.risk.band)}11` }}>{r.risk.band}</span>
                </div>
                <div className="mt-3 space-y-2">
                  {r.risk.components.map((c) => (
                    <div key={c.component} className="text-xs">
                      <div className="flex justify-between"><span className="text-slate-300">{c.component}</span><span className="font-mono text-slate-400">+{c.contribution.toFixed(1)}</span></div>
                      <p className="text-[10px] text-slate-600">{c.evidence}</p>
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Next-stage prediction" subtitle="Markov model — MODEL PREDICTION, not verified accuracy">
                {r.prediction ? (
                  <div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-slate-300">{r.prediction.current_stage}</span>
                      <TrendingUp className="h-4 w-4 text-cyber-purple" />
                      <span className="font-bold text-cyber-purple">{r.prediction.predicted_stage}</span>
                    </div>
                    <p className="mt-3 font-mono text-3xl font-black text-cyber-purple">{(r.prediction.probability * 100).toFixed(0)}%</p>
                    <p className="text-[10px] text-slate-500">confidence {(r.prediction.confidence * 100).toFixed(0)}% · incident {r.prediction.incident_id}</p>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">No incident association to predict from.</p>
                )}
              </Card>

              <Card title="Firewall verdict" subtitle="Would this indicator be blocked?">
                <div className="space-y-2 text-xs">
                  <div className={`flex items-center gap-2 rounded-lg border p-2.5 ${r.firewall.malware_guard ? "border-cyber-red/40 bg-cyber-red/10" : "border-cyber-green/40 bg-cyber-green/5"}`}>
                    {r.firewall.malware_guard ? <ShieldAlert className="h-4 w-4 text-cyber-red" /> : <ShieldCheck className="h-4 w-4 text-cyber-green" />}
                    <div>
                      <p className="font-semibold text-slate-200">MALWARE_GUARD {r.firewall.malware_guard ? "would block" : "passes"}</p>
                      <p className="text-[10px] text-slate-500">{r.firewall.malware_guard_note}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 rounded-lg border border-night-700 bg-night-850/60 p-2.5">
                    <Radar className="h-4 w-4 text-slate-400" />
                    <div>
                      <p className="font-semibold text-slate-300">IP_WATCH</p>
                      <p className="text-[10px] text-slate-500">{r.firewall.ip_watch_note}</p>
                    </div>
                  </div>
                  {r.firewall.blocked_indicators.length > 0 && (
                    <p className="text-[10px] text-slate-500">blocked indicators: {r.firewall.blocked_indicators.join(", ")}</p>
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
