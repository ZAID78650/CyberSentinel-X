import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Boxes, CheckCircle2, Dna, GitBranch, Radar, ShieldCheck, Siren, Zap } from "lucide-react";
import { api } from "../services/api";
import ProvenanceBadge, { provenanceKey } from "../components/ui/ProvenanceBadge";
import { Card, Skeleton, StatCard } from "../components/ui";

interface PipelineStage {
  stage: string;
  label: string;
  count: number;
  provenance: string;
  detail: string;
}

interface JudgeModeData {
  pipeline: PipelineStage[];
  metrics: {
    events_processed: number;
    campaigns_detected: number;
    alerts_correlated: number;
    incidents: number;
    incidents_contained: number;
    prediction_avg_confidence: number;
    false_positive_rate: number | null;
    precision: number | null;
    labeled_alerts: number;
    mttd_hours: number | null;
    mttr_hours: number | null;
    evidence_verified: number;
    evidence_tampered: number;
    merkle_roots: number;
    agent_runs: { completed: number; failed: number };
  };
  provenance_note: string;
}

const STAGE_ICONS: Record<string, React.ReactNode> = {
  EVENTS: <Activity className="h-4 w-4" />,
  ALERTS: <AlertTriangle className="h-4 w-4" />,
  CAMPAIGNS: <Siren className="h-4 w-4" />,
  "ATTACK DNA": <Dna className="h-4 w-4" />,
  PREDICTION: <Radar className="h-4 w-4" />,
  "BLAST RADIUS": <GitBranch className="h-4 w-4" />,
  RESPONSE: <Zap className="h-4 w-4" />,
  "BLOCKCHAIN PROOF": <Boxes className="h-4 w-4" />,
};

export default function JudgeMode() {
  const { data, isLoading } = useQuery({
    queryKey: ["judge-mode"],
    queryFn: async () => (await api.get<JudgeModeData>("/analytics/judge-mode")).data,
  });

  if (isLoading && !data) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-slate-100">Judge Mode</h2>
        {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24" />)}
      </div>
    );
  }
  if (!data) return null;

  const m = data.metrics;
  const pct = (v: number | null | undefined) => (v === null || v === undefined ? "—" : `${(v * 100).toFixed(1)}%`);
  const hours = (v: number | null | undefined) => (v === null || v === undefined ? "—" : `${v.toFixed(2)}h`);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-bold text-slate-100">SIH Judge Mode</h2>
        <span className="badge border border-cyber-purple/40 bg-cyber-purple/10 text-cyber-purple">END-TO-END PIPELINE</span>
      </div>

      <Card title="Pipeline" subtitle="Every stage computed from platform stores — nothing fabricated.">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {data.pipeline.map((s) => (
            <div key={s.stage} className="rounded-lg border border-night-700 bg-night-850/60 p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {STAGE_ICONS[s.stage] ?? <Activity className="h-4 w-4 text-slate-500" />}
                  <span className="text-xs font-bold tracking-wide text-slate-300">{s.stage}</span>
                </div>
                <ProvenanceBadge source={provenanceKey(s.provenance)} compact />
              </div>
              <p className="mt-3 text-2xl font-black text-slate-100">{s.count.toLocaleString()}</p>
              <p className="text-[11px] text-slate-500">{s.label}</p>
              <p className="mt-2 text-[11px] leading-snug text-slate-600">{s.detail}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Metrics" subtitle="Only values that are actually calculated are shown.">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard label="Events processed" value={m.events_processed.toLocaleString()} color="#38bdf8" hint="security_events store" />
          <StatCard label="Campaigns detected" value={m.campaigns_detected.toLocaleString()} color="#f472b6" hint="correlation engine grouping" />
          <StatCard label="Alerts correlated" value={m.alerts_correlated.toLocaleString()} color="#a78bfa" hint="after deduplication" />
          <StatCard label="Prediction avg confidence" value={`${m.prediction_avg_confidence.toFixed(1)}%`} color="#c084fc" hint="MODEL PREDICTION — not verified accuracy" />
          <StatCard label="False-positive rate" value={pct(m.false_positive_rate)} color={m.false_positive_rate !== null && m.false_positive_rate > 0.3 ? "#f87171" : "#34d399"} hint={`analyst feedback · ${m.labeled_alerts} labeled`} />
          <StatCard label="Precision" value={pct(m.precision)} color="#34d399" hint="TP / (TP + FP) on labeled alerts" />
          <StatCard label="MTTD" value={hours(m.mttd_hours)} color="#fbbf24" hint="mean time to detect" />
          <StatCard label="MTTR" value={hours(m.mttr_hours)} color="#fbbf24" hint="mean time to respond (resolved incidents)" />
          <StatCard label="Evidence verified" value={m.evidence_verified.toLocaleString()} color="#34d399" hint={`${m.evidence_tampered} tampered detected`} />
          <StatCard label="Merkle roots" value={m.merkle_roots.toLocaleString()} color="#38bdf8" hint="mined ledger blocks with merkle root" />
          <StatCard label="Incidents contained" value={m.incidents_contained.toLocaleString()} color="#34d399" hint={`of ${m.incidents} incidents`} />
          <StatCard label="Agent runs" value={`${m.agent_runs.completed} ✓ / ${m.agent_runs.failed} ✗`} color="#38bdf8" hint="multi-agent orchestrator" />
        </div>
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-night-700 bg-night-850/60 p-3 text-[11px] text-slate-500">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-cyber-green" />
          <span>{data.provenance_note}</span>
        </div>
      </Card>

      <div className="grid gap-3 md:grid-cols-2">
        <Card title="Verification chain" subtitle="Evidence → hash → merkle root → ledger → verify">
          <div className="space-y-2 text-xs text-slate-400">
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-cyber-green" /> {m.evidence_verified} evidence records verified valid</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-cyber-green" /> {m.merkle_roots} blocks committed with a Merkle root</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-cyber-green" /> Chain of custody recorded per evidence item</div>
          </div>
        </Card>
        <Card title="Human-in-the-loop" subtitle="No high-impact response executes without approval">
          <div className="space-y-2 text-xs text-slate-400">
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-cyber-green" /> Response recommendations require approval</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-cyber-green" /> Every action writes an audit record (action_logs)</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-cyber-green" /> Analyst feedback stored, never silently applied to models</div>
          </div>
        </Card>
      </div>
    </div>
  );
}
