import { useCallback, useEffect, useState } from "react";
import { ArrowRight, Dna, Fingerprint, GitCompare, Loader2, Radar, RefreshCw, Search } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, RiskGauge, Skeleton } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { AttackDnaItem, AttackPredictionItem } from "../types";

function short(s?: string | null, n = 12): string {
  if (!s) return "—";
  return `${s.slice(0, n)}…`;
}

function FamilyColor(family: string): string {
  const map: Record<string, string> = {
    "Credential Attack": "#f87171",
    "Privilege Escalation": "#fb923c",
    Malware: "#a78bfa",
    "Data Exfiltration": "#facc15",
    Reconnaissance: "#38bdf8",
    Fuzzing: "#22d3ee",
    Exploit: "#f472b6",
    "Backdoor": "#4ade80",
    "Generic_Attack": "#94a3b8",
    "Denial_Of_Service": "#e879f9",
  };
  return map[family] ?? "#38bdf8";
}

export default function AttackDna() {
  const [items, setItems] = useState<AttackDnaItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AttackDnaItem | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [similar, setSimilar] = useState<NonNullable<AttackDnaItem["similar_attacks"]>>([]);
  const [predictions, setPredictions] = useState<Record<string, AttackPredictionItem>>({});

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ items: AttackDnaItem[] }>("/attack-dna");
      setItems(res.data.items);
      setError(null);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const select = useCallback(async (dna: AttackDnaItem) => {
    setSelected(dna);
    setSearching(true);
    try {
      const [simRes, predRes] = await Promise.all([
        api.get<{ items: AttackDnaItem["similar_attacks"] }>(`/attack-dna/similar?incident_id=${dna.incident_id}&top_k=5`),
        api.get<AttackPredictionItem>(`/predictions/${dna.incident_id}`).catch(() => null),
      ]);
      setSimilar(simRes.data.items ?? []);
      if (predRes?.data) setPredictions((p) => ({ ...p, [dna.incident_id]: predRes.data }));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setSearching(false);
    }
  }, []);

  const searchSimilar = async () => {
    if (!searchQuery.trim()) return;
    setSearching(true);
    try {
      const res = await api.get<{ items: AttackDnaItem["similar_attacks"] }>(
        `/attack-dna/similar?top_k=8${searchQuery.trim() ? "" : ""}`,
      );
      setSimilar(res.data.items ?? []);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setSearching(false);
    }
  };

  const prediction = selected ? predictions[selected.incident_id] : null;

  if (loading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  const families = new Map<string, number>();
  items.forEach((d) => families.set(d.family, (families.get(d.family) ?? 0) + 1));

  return (
    <div className="space-y-5">
      {/* Header + search */}
      <div className="glass flex flex-col gap-4 p-5 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Dna className="h-5 w-5 text-electric-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">Attack DNA Engine</h2>
            <ProvenanceBadge source="MODEL" />
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Behavioral fingerprints of every significant incident — event mix, severity, anomaly signal, MITRE techniques and flow statistics hashed into a stable 64-char identity. Find “attacks that look like this one”.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              className="w-56 rounded-lg border border-night-700 bg-night-850 py-2 pl-9 pr-3 text-xs text-slate-200 placeholder:text-slate-600 focus:border-electric-500/50 focus:outline-none"
              placeholder="Search similar fingerprints…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void searchSimilar()}
            />
          </div>
          <button className="btn-ghost" onClick={searchSimilar} disabled={searching}>
            {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitCompare className="h-4 w-4" />} Find similar
          </button>
          <button className="btn-ghost" onClick={() => void load()} title="Refresh">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Family distribution */}
      <div className="glass p-5">
        <p className="label mb-3">Family distribution (fingerprinted incidents)</p>
        <div className="flex flex-wrap gap-2">
          {[...families.entries()].sort((a, b) => b[1] - a[1]).map(([family, count]) => (
            <span key={family} className="flex items-center gap-1.5 rounded-md border border-night-700 bg-night-850/70 px-2.5 py-1.5 text-[11px]">
              <span className="h-2 w-2 rounded-full" style={{ background: FamilyColor(family), boxShadow: `0 0 6px ${FamilyColor(family)}` }} />
              <span className="text-slate-300">{family}</span>
              <span className="font-mono font-bold text-slate-200">{count}</span>
            </span>
          ))}
          {families.size === 0 && <p className="text-xs text-slate-500">No fingerprints generated yet.</p>}
        </div>
      </div>

      {error && <div className="rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>}

      {/* Detail panel */}
      {selected && (
        <div className="grid gap-5 xl:grid-cols-3">
          {/* DNA card */}
          <Card
            title={`${selected.dna_id} — ${selected.family}`}
            subtitle={`Incident ${selected.incident_id}`}
            className="xl:col-span-1"
            actions={<span className="font-mono text-[10px] text-slate-500">0x{short(selected.fingerprint)}</span>}
          >
            <div className="flex items-center gap-5">
              <RiskGauge score={selected.risk_score ?? 50} label="risk" />
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] uppercase tracking-wider text-slate-500">Confidence</span>
                  <span className="font-mono text-lg font-bold text-cyber-green">{Math.round(selected.confidence * 100)}%</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] uppercase tracking-wider text-slate-500">Similar to</span>
                  <span className="font-mono text-xs text-electric-400">
                    {selected.similar_to ?? "—"}{selected.historical_similarity ? ` (${Math.round(selected.historical_similarity * 100)}%)` : ""}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] uppercase tracking-wider text-slate-500">Events</span>
                  <span className="font-mono text-xs text-slate-300">{selected.features.event_count ?? 0}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] uppercase tracking-wider text-slate-500">Anomaly μ</span>
                  <span className="font-mono text-xs text-slate-300">{(selected.features.anomaly_mean ?? 0).toFixed(3)}</span>
                </div>
              </div>
            </div>

            <p className="label mb-2 mt-4">Behavior</p>
            <div className="flex flex-wrap gap-1.5">
              {selected.behaviors.map((b) => (
                <span key={b} className="rounded-md border border-electric-500/30 bg-electric-500/10 px-2 py-1 text-[10px] text-electric-400">{b}</span>
              ))}
              {selected.behaviors.length === 0 && <span className="text-[10px] text-slate-600">No distinct behaviors — low event volume</span>}
            </div>

            <p className="label mb-2 mt-4">MITRE techniques</p>
            <div className="flex flex-wrap gap-1.5">
              {(selected.techniques ?? []).map((t) => (
                <span key={t.id} className="rounded-md border border-cyber-purple/30 bg-cyber-purple/10 px-2 py-1 font-mono text-[10px] text-cyber-purple">{t.id}</span>
              ))}
              {(selected.techniques ?? []).length === 0 && <span className="text-[10px] text-slate-600">No MITRE mapping recorded</span>}
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2 text-[10px] text-slate-500">
              <div className="rounded-md bg-night-850/60 p-2">
                <p className="uppercase tracking-wider">Source IPs</p>
                <p className="mt-0.5 font-mono text-slate-300">{(selected.features.source_ips ?? []).length}</p>
              </div>
              <div className="rounded-md bg-night-850/60 p-2">
                <p className="uppercase tracking-wider">Dest IPs</p>
                <p className="mt-0.5 font-mono text-slate-300">{(selected.features.dest_ips ?? []).length}</p>
              </div>
            </div>
          </Card>

          {/* Similar attacks */}
          <Card
            title="Similar Attack DNA"
            subtitle="Cosine similarity over the behavioral feature vector"
            className="xl:col-span-1"
            actions={<ProvenanceBadge source="MODEL" />}
          >
            {searching ? (
              <div className="flex items-center gap-2 py-10 text-xs text-slate-500"><Loader2 className="h-4 w-4 animate-spin" /> Computing similarities…</div>
            ) : similar.length === 0 ? (
              <EmptyState icon={<GitCompare className="h-8 w-8" />} title="No similar fingerprints"
                description="Select an incident card to compute historical similarity, or search by fingerprint hash." />
            ) : (
              <div className="space-y-2">
                {similar.map((s) => (
                  <div key={s.dna_id} className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-electric-400">{s.dna_id}</span>
                        <span className="badge border border-cyber-purple/30 bg-cyber-purple/10 text-cyber-purple">{s.family}</span>
                      </div>
                      <span className="font-mono text-sm font-bold" style={{ color: s.similarity > 0.85 ? "#4ade80" : s.similarity > 0.6 ? "#facc15" : "#94a3b8" }}>
                        {Math.round(s.similarity * 100)}%
                      </span>
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500">
                      <span className="font-mono">{s.incident_id}</span>
                      <span>risk {s.risk_score?.toFixed(0) ?? "—"}/100</span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {(s.behaviors ?? []).slice(0, 3).map((b) => (
                        <span key={b} className="rounded bg-night-900/70 px-1.5 py-0.5 text-[9px] text-slate-400">{b}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Prediction panel */}
          <Card
            title="Predicted Attack Path"
            subtitle="Next-stage prediction — clearly labeled, never a confirmed event"
            className="xl:col-span-1"
            actions={<span className="badge border border-cyber-yellow/40 bg-cyber-yellow/10 text-cyber-yellow">PREDICTION</span>}
          >
            {prediction ? (
              <div>
                <div className="flex items-center justify-center gap-3 py-3">
                  <div className="flex flex-col items-center gap-1 rounded-lg border border-night-700/70 bg-night-850/60 px-4 py-3">
                    <Radar className="h-4 w-4 text-electric-400" />
                    <span className="text-[10px] uppercase tracking-wider text-slate-500">Current stage</span>
                    <span className="text-sm font-bold text-slate-100">{prediction.current_stage}</span>
                  </div>
                  <ArrowRight className="h-5 w-5 text-slate-600" />
                  <div className="flex flex-col items-center gap-1 rounded-lg border border-cyber-yellow/40 bg-cyber-yellow/10 px-4 py-3">
                    <Fingerprint className="h-4 w-4 text-cyber-yellow" />
                    <span className="text-[10px] uppercase tracking-wider text-cyber-yellow">Predicted next</span>
                    <span className="text-sm font-bold text-cyber-yellow">{prediction.predicted_stage}</span>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-center">
                  <div className="rounded-md bg-night-850/60 p-2">
                    <p className="font-mono text-xl font-bold text-cyber-yellow">{Math.round(prediction.probability * 100)}%</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">probability</p>
                  </div>
                  <div className="rounded-md bg-night-850/60 p-2">
                    <p className="font-mono text-xl font-bold text-cyber-purple">{Math.round(prediction.confidence * 100)}%</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">model confidence</p>
                  </div>
                </div>
                <p className="mt-3 rounded-lg border border-night-700/70 bg-night-850/40 p-3 text-[11px] leading-snug text-slate-400">
                  {prediction.rationale}
                </p>
                <div className="mt-3">
                  <p className="label mb-1.5">Recommended prevention</p>
                  <p className="rounded-md border border-cyber-green/30 bg-cyber-green/10 px-3 py-2 text-[11px] text-cyber-green">
                    {prediction.recommended_control}
                  </p>
                </div>
                <p className="mt-3 text-[9px] text-slate-600">Model {prediction.model_version} · {new Date(prediction.created_at).toLocaleString()}</p>
              </div>
            ) : (
              <EmptyState icon={<Radar className="h-8 w-8" />} title="No prediction for this incident"
                description="Predictions are generated by the attack-path model when an incident is processed by the orchestrator." />
            )}
          </Card>
        </div>
      )}

      {/* Fingerprint list */}
      <Card title="Incident fingerprints" subtitle={`${items.length} fingerprints · click to inspect`}>
        {items.length === 0 ? (
          <EmptyState icon={<Dna className="h-8 w-8" />} title="No attack DNA generated"
            description="DNA fingerprints are created automatically for every significant incident during the investigation pipeline." />
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {items.map((d) => (
              <button
                key={d.id}
                onClick={() => void select(d)}
                className={`glass glass-hover p-4 text-left ${selected?.id === d.id ? "ring-1 ring-electric-500/50" : ""}`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold" style={{ color: FamilyColor(d.family) }}>{d.dna_id}</span>
                    <span className="badge border border-night-600 bg-night-850 text-slate-400">{d.severity}</span>
                  </div>
                  <ProvenanceBadge source="MODEL" compact />
                </div>
                <p className="mt-2 text-[11px] font-semibold text-slate-200">{d.family}</p>
                <p className="font-mono text-[9px] text-slate-600">{d.incident_id}</p>
                <div className="mt-2 flex items-center gap-3 text-[10px] text-slate-500">
                  <span>conf <b className="text-cyber-green">{Math.round(d.confidence * 100)}%</b></span>
                  <span>risk <b className="text-slate-300">{d.risk_score?.toFixed(0) ?? "—"}</b></span>
                  <span>sim <b className="text-electric-400">{d.historical_similarity ? `${Math.round(d.historical_similarity * 100)}%` : "—"}</b></span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {(d.behaviors ?? []).slice(0, 3).map((b) => (
                    <span key={b} className="rounded bg-night-900/70 px-1.5 py-0.5 text-[9px] text-slate-400">{b}</span>
                  ))}
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {(d.techniques ?? []).slice(0, 4).map((t) => (
                    <span key={t.id} className="rounded bg-cyber-purple/10 px-1.5 py-0.5 font-mono text-[9px] text-cyber-purple">{t.id}</span>
                  ))}
                </div>
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
