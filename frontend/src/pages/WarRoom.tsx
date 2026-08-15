import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowRight, Boxes, ChevronLeft, Dna, FileText, GitBranch, Gauge, Loader2,
  Radar, ShieldAlert, Target,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, RiskGauge, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type {
  AttackDnaItem, AttackPredictionItem, BlastRadius, EvidenceRecordItem,
  Incident, InvestigationDetail, Recommendation, Risk,
} from "../types";

function short(s?: string | null, n = 12): string {
  if (!s) return "—";
  return `${s.slice(0, n)}…${s.slice(-6)}`;
}

export default function WarRoom() {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [inv, setInv] = useState<InvestigationDetail | null>(null);
  const [dna, setDna] = useState<AttackDnaItem | null>(null);
  const [prediction, setPrediction] = useState<AttackPredictionItem | null>(null);
  const [blast, setBlast] = useState<BlastRadius | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecordItem[]>([]);
  const [risk, setRisk] = useState<Risk | null>(null);
  const [recs, setRecs] = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const [inc, invR, dnaR, predR, blastR, evR, riskR, recR] = await Promise.all([
          api.get<Incident>(`/incidents/${id}`),
          api.get<InvestigationDetail>(`/investigations/${id}`).catch(() => null),
          api.get<AttackDnaItem>(`/attack-dna/${id}`).catch(() => null),
          api.get<AttackPredictionItem>(`/predictions/${id}`).catch(() => null),
          api.get<BlastRadius>(`/soc/blast-radius/${id}`).catch(() => null),
          api.get<{ items: EvidenceRecordItem[] }>(`/evidence?incident_id=${id}`).catch(() => null),
          api.get<Risk>(`/risk/${id}`).catch(() => null),
          api.get<Recommendation[]>(`/response-recommendations/${id}`).catch(() => null),
        ]);
        if (cancelled) return;
        setIncident(inc.data);
        setInv(invR?.data ?? null);
        setDna(dnaR?.data ?? null);
        setPrediction(predR?.data ?? null);
        setBlast(blastR?.data ?? null);
        setEvidence(evR?.data.items ?? []);
        setRisk(riskR?.data ?? null);
        setRecs(recR?.data ?? []);
      } catch (err) {
        if (!cancelled) setError(getErrorMessage(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [id]);

  if (loading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-28" />
        <div className="grid gap-5 lg:grid-cols-3">
          <Skeleton className="h-80 lg:col-span-2" />
          <Skeleton className="h-80" />
        </div>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="glass p-10 text-center">
        <ShieldAlert className="mx-auto h-10 w-10 text-cyber-red" />
        <p className="mt-3 text-sm text-slate-300">{error ?? "Incident not found"}</p>
        <Link to="/incidents" className="btn-ghost mt-4"><ChevronLeft className="h-4 w-4" /> Back to incidents</Link>
      </div>
    );
  }

  const timeline = ((inv?.investigation.timeline ?? []) as Array<{ timestamp: string; event: string; detail?: Record<string, unknown> }>);
  const blastColor = blast?.blast_radius === "HIGH" ? "#f87171" : blast?.blast_radius === "MEDIUM" ? "#fb923c" : "#4ade80";

  return (
    <div className="space-y-5">
      <Link to="/incidents" className="flex items-center gap-1 text-xs font-semibold text-slate-500 hover:text-electric-400">
        <ChevronLeft className="h-4 w-4" /> Back to incidents
      </Link>

      {/* Header */}
      <div className="glass flex flex-wrap items-center gap-5 p-5">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-bold text-electric-400">{incident.incident_id}</span>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            <ProvenanceBadge source={incident.title.includes("UNSW") ? "DATASET" : "SIMULATED"} />
          </div>
          <h2 className="mt-1.5 text-lg font-bold text-slate-100">{incident.title}</h2>
          <p className="mt-1 text-xs text-slate-500">created {new Date(incident.created_at).toLocaleString()} · {incident.category}</p>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-center">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Risk</p>
            <p className="font-mono text-2xl font-bold" style={{ color: (incident.risk_score ?? 0) > 60 ? "#f87171" : "#38bdf8" }}>
              {incident.risk_score != null ? Math.round(incident.risk_score) : "—"}
            </p>
            <p className="text-[10px] text-slate-500">{incident.risk_label ?? ""}</p>
          </div>
          <div className="text-center">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Confidence</p>
            <p className="font-mono text-2xl font-bold text-electric-400">{(incident.confidence * 100).toFixed(0)}%</p>
          </div>
        </div>
      </div>

      {/* Top summary row: DNA, prediction, blast radius */}
      <div className="grid gap-5 md:grid-cols-3">
        {/* Attack DNA */}
        <Card title="Attack DNA" subtitle="Behavioral fingerprint" actions={dna ? <span className="font-mono text-[10px] text-slate-500">0x{short(dna.fingerprint)}</span> : undefined}>
          {dna ? (
            <div>
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-bold text-electric-400">{dna.dna_id}</span>
                <span className="badge border border-cyber-purple/30 bg-cyber-purple/10 text-cyber-purple">{dna.family}</span>
              </div>
              <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-500">
                <span>conf <b className="text-cyber-green">{Math.round(dna.confidence * 100)}%</b></span>
                <span>risk <b className="text-slate-300">{dna.risk_score?.toFixed(0) ?? "—"}</b></span>
                <span>sim <b className="text-electric-400">{dna.historical_similarity ? `${Math.round(dna.historical_similarity * 100)}%` : "—"}</b></span>
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {(dna.behaviors ?? []).slice(0, 3).map((b) => (
                  <span key={b} className="rounded bg-night-900/70 px-1.5 py-0.5 text-[9px] text-slate-400">{b}</span>
                ))}
              </div>
              <Link to="/attack-dna" className="mt-3 flex items-center gap-1 text-[11px] font-semibold text-electric-400 hover:underline">
                <Dna className="h-3.5 w-3.5" /> Open DNA engine
              </Link>
            </div>
          ) : <EmptyState icon={<Dna className="h-6 w-6" />} title="DNA pending" />}
        </Card>

        {/* Prediction */}
        <Card title="Predicted Next Stage" subtitle="Clearly labeled prediction — never confirmed" actions={<span className="badge border border-cyber-yellow/40 bg-cyber-yellow/10 text-cyber-yellow">PREDICTION</span>}>
          {prediction ? (
            <div>
              <div className="flex items-center justify-center gap-2 py-2">
                <div className="flex flex-col items-center rounded-lg border border-night-700/70 bg-night-850/60 px-3 py-2">
                  <span className="text-[9px] uppercase tracking-wider text-slate-500">Current</span>
                  <span className="text-xs font-bold text-slate-100">{prediction.current_stage}</span>
                </div>
                <ArrowRight className="h-4 w-4 text-slate-600" />
                <div className="flex flex-col items-center rounded-lg border border-cyber-yellow/40 bg-cyber-yellow/10 px-3 py-2">
                  <span className="text-[9px] uppercase tracking-wider text-cyber-yellow">Next</span>
                  <span className="text-xs font-bold text-cyber-yellow">{prediction.predicted_stage}</span>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 text-center">
                <div className="rounded-md bg-night-850/60 p-2">
                  <p className="font-mono text-lg font-bold text-cyber-yellow">{Math.round(prediction.probability * 100)}%</p>
                  <p className="text-[9px] uppercase tracking-wider text-slate-500">probability</p>
                </div>
                <div className="rounded-md bg-night-850/60 p-2">
                  <p className="font-mono text-lg font-bold text-cyber-purple">{Math.round(prediction.confidence * 100)}%</p>
                  <p className="text-[9px] uppercase tracking-wider text-slate-500">confidence</p>
                </div>
              </div>
              <p className="mt-2 rounded-md border border-cyber-green/30 bg-cyber-green/10 px-3 py-1.5 text-[10px] text-cyber-green">{prediction.recommended_control}</p>
            </div>
          ) : <EmptyState icon={<Radar className="h-6 w-6" />} title="Prediction pending" />}
        </Card>

        {/* Blast radius */}
        <Card title="Blast Radius" subtitle="Attack-graph reachability estimate" actions={blast ? <ProvenanceBadge source="MODEL" /> : undefined}>
          {blast ? (
            <div>
              <div className="flex items-center gap-4">
                <RiskGauge score={blast.blast_radius === "HIGH" ? 85 : blast.blast_radius === "MEDIUM" ? 55 : 20} label="exposure" />
                <div className="grid flex-1 grid-cols-2 gap-2 text-center">
                  <div className="rounded-md bg-night-850/60 p-2">
                    <p className="font-mono text-xl font-bold" style={{ color: blastColor }}>{blast.affected_assets}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">assets</p>
                  </div>
                  <div className="rounded-md bg-night-850/60 p-2">
                    <p className="font-mono text-xl font-bold text-cyber-purple">{blast.affected_databases}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">databases</p>
                  </div>
                  <div className="rounded-md bg-night-850/60 p-2">
                    <p className="font-mono text-xl font-bold text-electric-400">{blast.affected_users}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">users</p>
                  </div>
                  <div className="rounded-md bg-night-850/60 p-2">
                    <p className="font-mono text-xl font-bold text-cyber-orange">{blast.critical_services}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">services</p>
                  </div>
                </div>
              </div>
              {blast.path.length > 0 && (
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  {blast.path.map((p, i) => (
                    <span key={i} className="flex items-center gap-1.5 text-[10px]">
                      <span className="rounded bg-night-900/80 px-1.5 py-0.5 font-mono text-slate-300">{p.node}</span>
                      {i < blast.path.length - 1 && <ArrowRight className="h-3 w-3 text-slate-600" />}
                    </span>
                  ))}
                </div>
              )}
              <p className="mt-2 text-[9px] text-slate-600">{blast.estimate ? "ESTIMATE — observed correlation, not confirmed spread." : ""}</p>
            </div>
          ) : <EmptyState icon={<Gauge className="h-6 w-6" />} title="Blast radius pending" />}
        </Card>
      </div>

      {/* Main grid */}
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          {/* AI investigation */}
          <Card title="AI Investigation" subtitle="Investigation Agent conclusion" actions={<ProvenanceBadge source="MODEL" />}>
            {inv ? (
              <div>
                <div className="flex items-start gap-2">
                  <Radar className="mt-0.5 h-5 w-5 shrink-0 text-electric-400" />
                  <p className="text-sm leading-relaxed text-slate-300">{inv.investigation.summary}</p>
                </div>
                <div className="mt-3 flex items-center gap-3">
                  <span className={`badge border ${inv.investigation.verdict?.startsWith("HIGH") ? "border-cyber-red/40 bg-cyber-red/10 text-cyber-red" : "border-cyber-green/40 bg-cyber-green/10 text-cyber-green"}`}>
                    {inv.investigation.verdict ?? "PENDING"}
                  </span>
                  <span className="text-[11px] text-slate-500">confidence <b className="text-electric-400">{inv.investigation.confidence}%</b></span>
                </div>
              </div>
            ) : <div className="flex items-center gap-2 text-xs text-slate-500"><Loader2 className="h-4 w-4 animate-spin" /> Investigation running…</div>}
          </Card>

          {/* Timeline */}
          <Card title="Attack Timeline" subtitle="Correlated event sequence">
            {timeline.length === 0 ? (
              <EmptyState icon={<FileText className="h-6 w-6" />} title="No timeline yet" />
            ) : (
              <div className="relative space-y-0 pl-5">
                <div className="absolute bottom-2 left-[7px] top-2 w-px bg-night-700" />
                {timeline.map((t, i) => (
                  <div key={i} className="relative pb-4">
                    <span className="absolute -left-5 top-1 h-3 w-3 rounded-full border-2 border-electric-500 bg-night-900" />
                    <p className="font-mono text-[11px] text-slate-500">{new Date(t.timestamp).toLocaleTimeString()}</p>
                    <p className="text-sm font-medium text-slate-200">{t.event}</p>
                    {typeof t.detail?.source_ip === "string" && <p className="text-[11px] text-slate-600">from {t.detail.source_ip}</p>}
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* MITRE */}
          <Card title="MITRE ATT&CK Mapping" subtitle="Techniques observed in this incident">
            {inv && inv.mitre_mappings.length > 0 ? (
              <div className="grid gap-2 sm:grid-cols-2">
                {inv.mitre_mappings.map((m) => (
                  <a key={m.technique_id} href={`https://attack.mitre.org/techniques/${m.technique_id}/`} target="_blank" rel="noreferrer"
                    className="rounded-lg border border-night-700 bg-night-850/60 p-3 transition hover:border-electric-500/50">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-electric-400">{m.technique_id}</span>
                      <span className="font-mono text-[10px] text-slate-500">{(m.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <p className="mt-1 text-xs font-semibold text-slate-200">{m.name}</p>
                    <p className="text-[10px] uppercase tracking-wide text-slate-600">{m.tactic}</p>
                  </a>
                ))}
              </div>
            ) : <EmptyState icon={<Target className="h-6 w-6" />} title="No MITRE mapping recorded" />}
          </Card>

          {/* Recommendations */}
          <Card title="Recommended Response" subtitle="Response Agent · human approval required for execution">
            {recs.length === 0 ? (
              <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title="No recommendations yet" />
            ) : (
              <div className="space-y-2">
                {recs.slice(0, 5).map((r) => (
                  <div key={r.id} className="flex items-center justify-between rounded-lg border border-night-700 bg-night-850/60 px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-slate-200">{r.action}</span>
                      <span className="badge border border-night-600 bg-night-850 text-[9px] text-slate-500">IMPACT {r.impact}</span>
                    </div>
                    <StatusBadge status={r.status} />
                  </div>
                ))}
              </div>
            )}
            <Link to="/human-approvals" className="btn-ghost mt-3">Review approvals <ArrowRight className="h-3.5 w-3.5" /></Link>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-5">
          {risk && (
            <Card title="Explainable Risk" subtitle="Why this score">
              <RiskGauge score={risk.score} label={risk.severity_label} />
              <div className="mt-3 space-y-2">
                {risk.factors.map((f) => (
                  <div key={f.name}>
                    <div className="mb-0.5 flex justify-between text-[11px]">
                      <span className="text-slate-400">{f.name}</span>
                      <span className="font-mono text-slate-300">{Math.round(f.contribution * 100)}%</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-night-800">
                      <div className="h-full rounded-full" style={{ width: `${Math.min(100, f.contribution * 100)}%`, background: "#a78bfa", boxShadow: "0 0 8px #a78bfa" }} />
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <Card title="Evidence Ledger" subtitle="Chain-of-custody records" actions={<ProvenanceBadge source="LOCAL" />}>
            {evidence.length === 0 ? (
              <EmptyState icon={<Boxes className="h-6 w-6" />} title="No evidence recorded" />
            ) : (
              <div className="space-y-2">
                {evidence.map((e) => (
                  <div key={e.id} className="rounded-lg border border-night-700 bg-night-850/50 p-2.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] font-bold text-electric-400">{e.evidence_id}</span>
                      <StatusBadge status={e.status} />
                    </div>
                    <p className="mt-1 truncate text-[11px] text-slate-300" title={e.title}>{e.title}</p>
                    <p className="font-mono text-[9px] text-slate-600">0x{short(e.record_hash)} · #{e.chain_index}</p>
                  </div>
                ))}
              </div>
            )}
            <Link to="/evidence-ledger" className="mt-3 flex items-center gap-1 text-[11px] font-semibold text-electric-400 hover:underline">
              <Boxes className="h-3.5 w-3.5" /> Open ledger
            </Link>
          </Card>

          <Link to={`/attack-graph?incident=${incident.id}`} className="glass glass-hover flex items-center justify-between p-4">
            <span className="flex items-center gap-2 text-sm font-semibold text-slate-200"><GitBranch className="h-4 w-4 text-electric-400" /> Attack Graph</span>
            <ArrowRight className="h-4 w-4 text-slate-500" />
          </Link>
        </div>
      </div>
    </div>
  );
}
