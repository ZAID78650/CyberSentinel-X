import { type ReactNode } from "react";
import { X } from "lucide-react";

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
    HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    LOW: "bg-green-500/15 text-green-400 border-green-500/30",
  };
  const cls = map[(severity ?? "").toUpperCase()] ?? "bg-slate-500/15 text-slate-400 border-slate-500/30";
  return <span className={`badge border ${cls}`}>{severity ?? "—"}</span>;
}

export function StatusBadge({ status }: { status?: string | null }) {
  const map: Record<string, string> = {
    OPEN: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    INVESTIGATING: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    CONTAINED: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    RESOLVED: "bg-green-500/15 text-green-400 border-green-500/30",
    CLOSED: "bg-slate-500/15 text-slate-400 border-slate-500/30",
    PENDING: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    APPROVED: "bg-green-500/15 text-green-400 border-green-500/30",
    REJECTED: "bg-red-500/15 text-red-400 border-red-500/30",
    EXECUTED: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    RUNNING: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    COMPLETED: "bg-green-500/15 text-green-400 border-green-500/30",
    FAILED: "bg-red-500/15 text-red-400 border-red-500/30",
    WAITING: "bg-orange-500/15 text-orange-400 border-orange-500/30",
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
    <div className={`intel-card ${className}`}>
      {(title || actions) && (
        <div className="flex items-start justify-between border-b px-5 py-3.5" style={{ borderColor: "var(--border-primary)" }}>
          <div>
            {title && <h3 className="text-sm font-bold tracking-wide" style={{ color: "var(--text-primary)" }}>{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs" style={{ color: "var(--text-muted)" }}>{subtitle}</p>}
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
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      {icon && <div style={{ color: "var(--text-muted)" }}>{icon}</div>}
      <p className="text-sm font-semibold" style={{ color: "var(--text-secondary)" }}>{title}</p>
      {description && <p className="max-w-sm text-xs leading-relaxed" style={{ color: "var(--text-muted)" }}>{description}</p>}
    </div>
  );
}

export function StatCard({ label, value, color = "#3b82f6", icon, hint }: {
  label: string;
  value: number | string;
  color?: string;
  icon?: ReactNode;
  hint?: string;
}) {
  return (
    <div className="intel-card relative overflow-hidden p-4">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: color, boxShadow: `0 0 12px ${color}` }} />
      <div className="flex items-center justify-between">
        <p className="text-2xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{label}</p>
        {icon && <div style={{ color }}>{icon}</div>}
      </div>
      <p className="kpi-value mt-1.5 truncate text-2xl xl:text-3xl" style={{ color }} title={typeof value === "number" ? value.toLocaleString() : String(value)}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {hint && <p className="mt-1 text-2xs" style={{ color: "var(--text-muted)" }}>{hint}</p>}
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
      <div className="intel-card w-full max-w-lg p-0" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b px-5 py-3.5" style={{ borderColor: "var(--border-primary)" }}>
          <h3 className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{title}</h3>
          <button onClick={onClose} className="rounded p-1 hover:bg-white/5" style={{ color: "var(--text-muted)" }}>
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t px-5 py-3.5" style={{ borderColor: "var(--border-primary)" }}>{footer}</div>}
      </div>
    </div>
  );
}

export function ProgressBar({ value, color = "#3b82f6", className = "" }: { value: number; color?: string; className?: string }) {
  return (
    <div className={`h-2 w-full overflow-hidden rounded-full ${className}`} style={{ background: "var(--bg-tertiary)" }}>
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
  const color = accuracy >= 95 ? "#22c55e" : accuracy >= 85 ? "#3b82f6" : accuracy >= 70 ? "#f59e0b" : "#ef4444";
  return (
    <div className="flex items-center gap-5">
      <div className="relative h-28 w-28 shrink-0">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="var(--bg-tertiary)" strokeWidth="10" />
          <circle
            cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${(accuracy / 100) * 264} 264`}
            style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dasharray 0.8s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-bold" style={{ color }}>{accuracy.toFixed(2)}%</span>
          <span className="text-2xs uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>accuracy</span>
        </div>
      </div>
      <div className="space-y-1.5">
        {[
          { label: "Precision", value: precision },
          { label: "Recall", value: recall },
          { label: "F1 Score", value: f1 },
        ].map((m) => (
          <div key={m.label} className="flex items-center justify-between gap-6">
            <span className="text-2xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{m.label}</span>
            <span className="font-mono text-sm font-bold" style={{ color: "var(--text-primary)" }}>{m.value?.toFixed(2)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function RiskGauge({ score, label }: { score: number; label?: string }) {
  const color = score > 80 ? "#ef4444" : score > 60 ? "#f97316" : score > 30 ? "#f59e0b" : "#22c55e";
  return (
    <div className="flex items-center gap-4">
      <div className="relative h-24 w-24">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="var(--bg-tertiary)" strokeWidth="10" />
          <circle
            cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${(score / 100) * 264} 264`}
            style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dasharray 0.8s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-bold" style={{ color }}>{Math.round(score)}</span>
          <span className="text-2xs uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{label ?? "risk"}</span>
        </div>
      </div>
    </div>
  );
}
