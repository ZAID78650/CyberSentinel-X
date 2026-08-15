import { useEffect, useState } from "react";
import { BadgeCheck, FileWarning, ShieldHalf } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, ProgressBar, Skeleton } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { CompliancePosture } from "../types";

export default function ComplianceCenter() {
  const [data, setData] = useState<CompliancePosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get<CompliancePosture>("/soc/compliance");
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
        <Skeleton className="h-36" />
        <div className="grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-72" />)}
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <Card>
        <EmptyState icon={<ShieldHalf className="h-8 w-8" />} title="Compliance posture unavailable" description={error ?? "Could not load compliance data."} />
      </Card>
    );
  }

  const overallColor = data.overall_posture >= 75 ? "#4ade80" : data.overall_posture >= 50 ? "#facc15" : "#f87171";

  return (
    <div className="space-y-5">
      {/* Overall posture */}
      <Card
        title="Compliance Center"
        subtitle="Observed MITRE techniques mapped to control frameworks — posture from real incident data"
        actions={<ProvenanceBadge source="DATASET" />}
      >
        <div className="flex flex-col items-center gap-5 md:flex-row">
          <div className="relative h-32 w-32 shrink-0">
            <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
              <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="10" />
              <circle cx="50" cy="50" r="42" fill="none" stroke={overallColor} strokeWidth="10" strokeLinecap="round"
                strokeDasharray={`${(data.overall_posture / 100) * 264} 264`} style={{ filter: `drop-shadow(0 0 6px ${overallColor})` }} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-mono text-3xl font-bold" style={{ color: overallColor }}>{data.overall_posture.toFixed(1)}%</span>
              <span className="text-[9px] uppercase tracking-wider text-slate-500">overall posture</span>
            </div>
          </div>
          <div className="flex-1 space-y-2">
            <p className="text-sm text-slate-300">{data.method}</p>
            <p className="text-[11px] text-slate-500">
              {data.observed_techniques.length} MITRE techniques observed in incident mappings:{" "}
              <span className="font-mono text-electric-400">{data.observed_techniques.join(" · ")}</span>
            </p>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {data.frameworks.map((f) => (
                <span key={f.framework} className="badge border border-night-600 bg-night-800 text-slate-300">{f.framework} · {f.posture.toFixed(0)}%</span>
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* Per-framework */}
      <div className="grid gap-4 md:grid-cols-3">
        {data.frameworks.map((f) => (
          <Card key={f.framework} title={f.framework} subtitle={`${f.controls_covered}/${f.controls_total} mapped controls covered`}>
            <div className="mb-2 flex items-center justify-between">
              <span className="font-mono text-2xl font-bold" style={{ color: f.posture >= 75 ? "#4ade80" : f.posture >= 50 ? "#facc15" : "#f87171" }}>
                {f.posture.toFixed(0)}%
              </span>
              <BadgeCheck className="h-5 w-5" style={{ color: f.posture >= 75 ? "#4ade80" : "#64748b" }} />
            </div>
            <ProgressBar value={f.posture} color={f.posture >= 75 ? "#4ade80" : f.posture >= 50 ? "#facc15" : "#f87171"} />
            <div className="mt-4 space-y-2.5">
              {f.gaps.length === 0 ? (
                <p className="rounded-md bg-cyber-green/10 p-2 text-[11px] text-cyber-green">All mapped controls covered by observed techniques.</p>
              ) : (
                f.gaps.map((g) => (
                  <div key={g.control} className="rounded-md border border-cyber-yellow/20 bg-cyber-yellow/5 p-2">
                    <div className="flex items-center gap-1.5 text-[11px] font-semibold text-cyber-yellow">
                      <FileWarning className="h-3 w-3" /> {g.control}
                    </div>
                    <p className="mt-0.5 font-mono text-[9px] text-slate-500">missing: {g.missing.join(" · ")}</p>
                  </div>
                ))
              )}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
