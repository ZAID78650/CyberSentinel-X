import { type ReactNode } from "react";
import { X } from "lucide-react";

interface IntelligenceDrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
  actions?: ReactNode;
}

export function IntelligenceDrawer({ open, onClose, title, subtitle, children, actions }: IntelligenceDrawerProps) {
  if (!open) return null;
  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      {/* Panel */}
      <div className="drawer-panel" style={{ animation: "slideInRight 0.25s ease-out" }}>
        {/* Header */}
        <div className="sticky top-0 z-10 flex items-center justify-between border-b px-5 py-4 backdrop-blur-md" style={{ borderColor: "var(--border-primary)", background: "var(--bg-secondary)" }}>
          <div className="min-w-0">
            <h2 className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs" style={{ color: "var(--text-muted)" }}>{subtitle}</p>}
          </div>
          <div className="flex items-center gap-2">
            {actions}
            <button onClick={onClose} className="rounded-lg p-1.5 transition-colors hover:bg-white/5" style={{ color: "var(--text-muted)" }}>
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
        {/* Content */}
        <div className="overflow-y-auto p-5">{children}</div>
      </div>
    </>
  );
}

/* ── Drawer section helpers ── */

export function DrawerSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mb-5">
      <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>{title}</h3>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

export function DrawerField({ label, value, color }: { label: string; value: ReactNode; color?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs" style={{ color: "var(--text-secondary)" }}>{label}</span>
      <span className="text-sm font-semibold" style={{ color: color ?? "var(--text-primary)" }}>{value ?? "—"}</span>
    </div>
  );
}

export function DrawerKeyValue({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex justify-between rounded-lg px-3 py-2" style={{ background: "var(--bg-tertiary)" }}>
      <span className="text-xs" style={{ color: "var(--text-muted)" }}>{label}</span>
      <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{value ?? "—"}</span>
    </div>
  );
}
