import type { DataProvenance } from "../../types";

const STYLES: Record<DataProvenance, { cls: string; label: string }> = {
  LIVE: { cls: "border-cyber-green/40 bg-cyber-green/10 text-cyber-green", label: "LIVE" },
  DATASET: { cls: "border-electric-500/40 bg-electric-500/10 text-electric-400", label: "DATASET" },
  SIMULATED: { cls: "border-cyber-yellow/40 bg-cyber-yellow/10 text-cyber-yellow", label: "SIMULATED" },
  LOCAL: { cls: "border-slate-500/40 bg-slate-500/10 text-slate-300", label: "LOCAL" },
  MODEL: { cls: "border-cyber-purple/40 bg-cyber-purple/10 text-cyber-purple", label: "AI PREDICTION" },
  UNKNOWN: { cls: "border-slate-600/40 bg-slate-600/10 text-slate-500", label: "UNKNOWN" },
};

/**
 * Data-provenance badge. Every major metric in the platform must clearly state
 * whether it comes from the UNSW-NB15 dataset, live telemetry, simulation, an
 * ML model prediction, or local reference data — never mix them silently.
 */
export default function ProvenanceBadge({ source, compact = false }: { source?: string | null; compact?: boolean }) {
  const key = (source ?? "LOCAL").toUpperCase() as DataProvenance;
  const style = STYLES[key] ?? STYLES.UNKNOWN;
  const dot = key === "LIVE" || key === "DATASET" || key === "MODEL";
  return (
    <span className={`badge border whitespace-nowrap ${style.cls}`} title={`Data origin: ${style.label}`}>
      {dot && <span className={`mr-1 inline-block h-1.5 w-1.5 rounded-full ${key === "LIVE" ? "bg-cyber-green" : key === "MODEL" ? "bg-cyber-purple" : "bg-electric-400"} animate-pulse`} />}
      {compact ? style.label : style.label}
    </span>
  );
}
