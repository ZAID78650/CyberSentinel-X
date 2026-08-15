import { useEffect, useState } from "react";
import { BrainCircuit, Cpu, GitCommitHorizontal, Layers } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { AccuracyGauge, Card, EmptyState, Skeleton, StatCard } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";

interface ModelCenterData {
  model: {
    name: string;
    version: string;
    architecture: string;
    hyperparameters: Record<string, number>;
    fit_count: number;
    status: string;
  };
  evaluation: {
    accuracy: number; precision: number; recall: number; f1: number;
    true_positives: number; false_positives: number; true_negatives: number; false_negatives: number;
    total_events: number; attack_events: number; benign_events: number;
    method: string; evaluated_at: string;
  };
  note: string;
}

export default function ModelCenter() {
  const [data, setData] = useState<ModelCenterData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get<ModelCenterData>("/soc/model-center");
        setData(res.data);
      } catch (err) {
        setError(getErrorMessage(err));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-40" />
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (!data) {
    return (
      <Card>
        <EmptyState icon={<BrainCircuit className="h-8 w-8" />} title="Model center unavailable" description={error ?? "Could not load model metrics."} />
      </Card>
    );
  }

  const m = data.model;
  const e = data.evaluation;

  return (
    <div className="space-y-5">
      {/* Model card */}
      <Card
        title="Production Detection Model"
        subtitle={`${m.name} · ${m.version}`}
        actions={<ProvenanceBadge source="MODEL" />}
      >
        <div className="grid gap-4 md:grid-cols-[auto_1fr]">
          <div className="flex items-center gap-3 rounded-lg border border-night-700 bg-night-850/60 p-4">
            <BrainCircuit className="h-10 w-10 text-electric-400" />
            <div>
              <p className="font-mono text-sm font-bold text-slate-100">{m.name}</p>
              <p className="text-[11px] text-slate-500">{m.architecture}</p>
              <span className="badge border border-cyber-green/30 bg-cyber-green/10 text-cyber-green">{m.status}</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <div className="rounded-lg border border-night-700 bg-night-850/60 p-3">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500"><Cpu className="h-3 w-3" /> Contamination</div>
              <p className="mt-1 font-mono text-lg font-bold text-slate-200">{m.hyperparameters.contamination}</p>
            </div>
            <div className="rounded-lg border border-night-700 bg-night-850/60 p-3">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500"><Layers className="h-3 w-3" /> Estimators</div>
              <p className="mt-1 font-mono text-lg font-bold text-slate-200">{m.hyperparameters.n_estimators}</p>
            </div>
            <div className="rounded-lg border border-night-700 bg-night-850/60 p-3">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500"><GitCommitHorizontal className="h-3 w-3" /> Fit count</div>
              <p className="mt-1 font-mono text-lg font-bold text-slate-200">{m.fit_count.toLocaleString()}</p>
            </div>
            <div className="rounded-lg border border-night-700 bg-night-850/60 p-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Seed</div>
              <p className="mt-1 font-mono text-lg font-bold text-slate-200">{m.hyperparameters.random_state}</p>
            </div>
          </div>
        </div>
      </Card>

      {/* Measured metrics */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="True Positives" value={e.true_positives} color="#4ade80" hint="attacks correctly flagged" />
        <StatCard label="False Positives" value={e.false_positives} color="#f87171" hint="benign flagged as attack" />
        <StatCard label="True Negatives" value={e.true_negatives} color="#38bdf8" hint="benign correctly passed" />
        <StatCard label="False Negatives" value={e.false_negatives} color="#fb923c" hint="attacks missed" />
      </div>

      <Card title="Evaluation on Labeled Corpus" subtitle={`${e.total_events} events (${e.attack_events} attack · ${e.benign_events} benign) · ${e.method} · evaluated ${new Date(e.evaluated_at).toLocaleString()}`}>
        <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <AccuracyGauge accuracy={e.accuracy} precision={e.precision} recall={e.recall} f1={e.f1} />
          <div className="grid flex-1 grid-cols-2 gap-3 md:max-w-md">
            {[
              { label: "Attack precision", value: e.precision, color: "#a78bfa" },
              { label: "Attack recall", value: e.recall, color: "#4ade80" },
              { label: "F1 score", value: e.f1, color: "#38bdf8" },
              { label: "Benign false-positive rate", value: e.false_positives / Math.max(e.benign_events, 1) * 100, color: "#f87171" },
            ].map((x) => (
              <div key={x.label} className="rounded-lg border border-night-700 bg-night-850/60 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{x.label}</p>
                <p className="mt-1 font-mono text-xl font-bold" style={{ color: x.color }}>{x.value.toFixed(2)}%</p>
              </div>
            ))}
          </div>
        </div>
        <p className="mt-5 rounded-lg border border-night-700 bg-night-850/60 p-3 text-[11px] leading-relaxed text-slate-400">{data.note}</p>
      </Card>
    </div>
  );
}
