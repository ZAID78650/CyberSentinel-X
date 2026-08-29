import { type ReactNode } from "react";
import { X } from "lucide-react";

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-cyber-red/15 text-cyber-red border-cyber-red/30",
    HIGH: "bg-cyber-orange/15 text-cyber-orange border-cyber-orange/30",
    MEDIUM: "bg-cyber-yellow/15 text-cyber-yellow border-cyber-yellow/30",
    LOW: "bg-cyber-green/15 text-cyber-green border-cyber-green/30",
  };
  const cls = map[(severity ?? "").toUpperCase()] ?? "bg-slate-500/15 text-slate-400 border-slate-500/30";
  return <span className={`badge border ${cls}`}>{severity ?? "—"}</span>;
}

export function StatusBadge({ status }: { status?: string | null }) {
  const map: Record<string, string> = {
    OPEN: "bg-cyber-yellow/15 text-cyber-yellow border-cyber-yellow/30",
    INVESTIGATING: "bg-electric-500/15 text-electric-400 border-electric-500/30",
    CONTAINED: "bg-cyber-purple/15 text-cyber-purple border-cyber-purple/30",
    RESOLVED: "bg-cyber-green/15 text-cyber-green border-cyber-green/30",
    CLOSED: "bg-slate-500/15 text-slate-400 border-slate-500/30",
    PENDING: "bg-cyber-yellow/15 text-cyber-yellow border-cyber-yellow/30",
    APPROVED: "bg-cyber-green/15 text-cyber-green border-cyber-green/30",
    REJECTED: "bg-cyber-red/15 text-cyber-red border-cyber-red/30",
    EXECUTED: "bg-electric-500/15 text-electric-400 border-electric-500/30",
    RUNNING: "bg-electric-500/15 text-electric-400 border-electric-500/30",
    COMPLETED: "bg-cyber-green/15 text-cyber-green border-cyber-green/30",
    FAILED: "bg-cyber-red/15 text-cyber-red border-cyber-red/30",
    WAITING: "bg-cyber-orange/15 text-cyber-orange border-cyber-orange/30",
  };
  const cls = map[(status ?? "").toUpperCase()] ?? "bg-slate-500/15 text-slate-400 border-slate-500/30";
  return <span className={`badge border ${cls}`}>{status ?? "—"}</span>;
}

export function Card({
  children,
  className = "",
  title,
  subtitle,
  actions,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className={`glass ${className}`}>
      {(title || actions) && (
        <div className="flex items-start justify-between border-b px-5 py-3.5" style={{ borderColor: "var(--surface-border)" }}>
          <div>
            {title && <h3 className="text-sm font-bold tracking-wide" style={{ color: "var(--on-surface)" }}>{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs" style={{ color: "var(--on-surface-faint)" }}>{subtitle}</p>}
          </div>
          {actions}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} />;
}

export function EmptyState({ icon, title, description }: { icon?: ReactNode; title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      {icon && <div style={{ color: "var(--on-surface-faint)" }}>{icon}</div>}
      <p className="text-sm font-semibold" style={{ color: "var(--on-surface-muted)" }}>{title}</p>
      {description && <p className="max-w-sm text-xs" style={{ color: "var(--on-surface-faint)" }}>{description}</p>}
    </div>
  );
}

export function StatCard({ label, value, color = "#38bdf8", icon, hint }: {
  label: string;
  value: number | string;
  color?: string;
  icon?: ReactNode;
  hint?: string;
}) {
  return (
    <div className="glass glass-hover relative overflow-hidden p-4">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: color, boxShadow: `0 0 12px ${color}` }} />
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: "var(--on-surface-faint)" }}>{label}</p>
        {icon && <div style={{ color }}>{icon}</div>}
      </div>
      <p className="kpi-value mt-1.5 truncate text-2xl xl:text-3xl" style={{ color }} title={typeof value === "number" ? value.toLocaleString() : String(value)}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {hint && <p className="mt-0.5 text-[11px]" style={{ color: "var(--on-surface-faint)" }}>{hint}</p>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, footer }: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="glass w-full max-w-lg p-0" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b px-5 py-3.5" style={{ borderColor: "var(--surface-border)" }}>
          <h3 className="text-sm font-bold" style={{ color: "var(--on-surface)" }}>{title}</h3>
          <button onClick={onClose} style={{ color: "var(--on-surface-faint)" }} className="hover:opacity-80">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t px-5 py-3.5" style={{ borderColor: "var(--surface-border)" }}>{footer}</div>}
      </div>
    </div>
  );
}

export function ProgressBar({ value, color = "#38bdf8", className = "" }: { value: number; color?: string; className?: string }) {
  return (
    <div className={`h-2 w-full overflow-hidden rounded-full ${className}`} style={{ background: "var(--surface-raised)" }}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${Math.min(100, Math.max(0, value))}%`, background: color, boxShadow: `0 0 8px ${color}` }}
      />
    </div>
  );
}

export function AccuracyGauge({ accuracy, precision, recall, f1 }: {
  accuracy: number;
  precision?: number;
  recall?: number;
  f1?: number;
}) {
  const color = accuracy >= 95 ? "#4ade80" : accuracy >= 85 ? "#38bdf8" : accuracy >= 70 ? "#facc15" : "#f87171";
  return (
    <div className="flex items-center gap-5">
      <div className="relative h-28 w-28 shrink-0">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="var(--surface-raised)" strokeWidth="10" />
          <circle
            cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${(accuracy / 100) * 264} 264`}
            style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dasharray 0.8s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-bold" style={{ color }}>{accuracy.toFixed(2)}%</span>
          <span className="text-[9px] uppercase tracking-wider" style={{ color: "var(--on-surface-faint)" }}>accuracy</span>
        </div>
      </div>
      <div className="space-y-1.5">
        {[
          { label: "Precision", value: precision },
          { label: "Recall", value: recall },
          { label: "F1 Score", value: f1 },
        ].map((m) => (
          <div key={m.label} className="flex items-center justify-between gap-6">
            <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: "var(--on-surface-faint)" }}>{m.label}</span>
            <span className="font-mono text-sm font-bold" style={{ color: "var(--on-surface)" }}>{m.value?.toFixed(2)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function RiskGauge({ score, label }: { score: number; label?: string }) {
  const color = score > 80 ? "#f87171" : score > 60 ? "#fb923c" : score > 30 ? "#facc15" : "#4ade80";
  return (
    <div className="flex items-center gap-4">
      <div className="relative h-24 w-24">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="var(--surface-raised)" strokeWidth="10" />
          <circle
            cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${(score / 100) * 264} 264`}
            style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dasharray 0.8s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-bold" style={{ color }}>{Math.round(score)}</span>
          <span className="text-[9px] uppercase tracking-wider" style={{ color: "var(--on-surface-faint)" }}>{label ?? "risk"}</span>
        </div>
      </div>
    </div>
  );
}
