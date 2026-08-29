import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity, AlertTriangle, BarChart3, Bug, FileText, Globe,
  LayoutDashboard, Map, Network, Radar, Search, Shield,
  TrendingUp, Zap, X,
} from "lucide-react";

interface CommandItem {
  id: string;
  label: string;
  description?: string;
  icon: React.ReactNode;
  shortcut?: string;
  action: () => void;
  category: string;
}

const COMMANDS: Array<{ category: string; items: Omit<CommandItem, "action" | "category">[] }> = [
  {
    category: "Navigate",
    items: [
      { id: "dashboard", label: "Overview Dashboard", icon: <LayoutDashboard className="h-4 w-4" /> },
      { id: "scanner", label: "Intelligence Scanner", description: "Upload and analyze datasets", icon: <Bug className="h-4 w-4" /> },
      { id: "complaints", label: "Complaints", description: "View all cybercrime complaints", icon: <FileText className="h-4 w-4" /> },
      { id: "transactions", label: "Transactions", description: "Financial intelligence", icon: <TrendingUp className="h-4 w-4" /> },
      { id: "predictions", label: "Predictions", description: "Predicted withdrawal locations", icon: <Zap className="h-4 w-4" /> },
      { id: "heatmap", label: "Risk Heatmap", description: "Geospatial risk analysis", icon: <Map className="h-4 w-4" /> },
      { id: "network", label: "Entity Network", description: "Relationship visualization", icon: <Network className="h-4 w-4" /> },
      { id: "alerts", label: "Alerts", description: "Real-time alert center", icon: <AlertTriangle className="h-4 w-4" /> },
      { id: "cases", label: "Cases", description: "Investigation case management", icon: <Shield className="h-4 w-4" /> },
      { id: "reports", label: "Reports", description: "Intelligence reports", icon: <FileText className="h-4 w-4" /> },
      { id: "models", label: "Model Center", description: "ML model performance", icon: <BarChart3 className="h-4 w-4" /> },
      { id: "monitoring", label: "System Monitor", description: "System health and metrics", icon: <Activity className="h-4 w-4" /> },
      { id: "sih-demo", label: "SIH Demo Mode", description: "Run the full demo scenario", icon: <Zap className="h-4 w-4" /> },
    ],
  },
  {
    category: "Actions",
    items: [
      { id: "run-scan", label: "Run Intelligence Scan", icon: <Radar className="h-4 w-4" />, shortcut: "⌘S" },
      { id: "view-hotspots", label: "View Predicted Hotspots", icon: <Map className="h-4 w-4" /> },
      { id: "generate-report", label: "Generate Report", icon: <FileText className="h-4 w-4" /> },
    ],
  },
];

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const ROUTE_MAP: Record<string, string> = {
    dashboard: "/dashboard",
    scanner: "/cybercrime-scanner",
    complaints: "/incidents",
    transactions: "/financial-intelligence",
    predictions: "/predictive-alerts",
    heatmap: "/gis-heatmap",
    network: "/entity-network",
    alerts: "/alerts",
    cases: "/investigation",
    reports: "/incident-reports",
    models: "/model-performance",
    monitoring: "/monitoring",
    "sih-demo": "/sih-demo",
  };

  const allCommands: CommandItem[] = useMemo(
    () =>
      COMMANDS.flatMap((group) =>
        group.items.map((item) => ({
          ...item,
          category: group.category,
          action: () => {
            const route = ROUTE_MAP[item.id];
            if (route) {
              navigate(route);
              onClose();
            }
          },
        })),
      ),
    [navigate, onClose],
  );

  const filtered = useMemo(() => {
    if (!query.trim()) return allCommands;
    const q = query.toLowerCase();
    return allCommands.filter(
      (cmd) =>
        cmd.label.toLowerCase().includes(q) ||
        cmd.description?.toLowerCase().includes(q) ||
        cmd.category.toLowerCase().includes(q),
    );
  }, [query, allCommands]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose],
  );

  if (!open) return null;

  return (
    <div className="cmd-overlay" onClick={onClose}>
      <div className="cmd-panel" onClick={(e) => e.stopPropagation()} onKeyDown={handleKeyDown}>
        {/* Search input */}
        <div className="flex items-center gap-3 border-b px-4" style={{ borderColor: "var(--border-primary)" }}>
          <Search className="h-4 w-4 shrink-0" style={{ color: "var(--text-muted)" }} />
          <input
            ref={inputRef}
            className="flex-1 bg-transparent py-3.5 text-sm outline-none"
            placeholder="Search complaints, cases, alerts, entities..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button onClick={onClose} className="rounded p-1 hover:bg-white/5" style={{ color: "var(--text-muted)" }}>
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>
              No results found for "{query}"
            </div>
          ) : (
            <>
              {/* Group by category */}
              {(["Navigate", "Actions"] as const).map((cat) => {
                const items = filtered.filter((c) => c.category === cat);
                if (items.length === 0) return null;
                return (
                  <div key={cat}>
                    <p className="px-3 py-1.5 text-2xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                      {cat}
                    </p>
                    {items.map((cmd) => (
                      <button
                        key={cmd.id}
                        className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition-colors hover:bg-white/5"
                        onClick={cmd.action}
                        style={{ color: "var(--text-primary)" }}
                      >
                        <span style={{ color: "var(--text-muted)" }}>{cmd.icon}</span>
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-medium">{cmd.label}</p>
                          {cmd.description && (
                            <p className="truncate text-xs" style={{ color: "var(--text-muted)" }}>{cmd.description}</p>
                          )}
                        </div>
                        {cmd.shortcut && (
                          <kbd className="rounded border px-1.5 py-0.5 text-2xs" style={{ borderColor: "var(--border-primary)", color: "var(--text-muted)" }}>
                            {cmd.shortcut}
                          </kbd>
                        )}
                      </button>
                    ))}
                  </div>
                );
              })}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-4 border-t px-4 py-2" style={{ borderColor: "var(--border-primary)" }}>
          <span className="text-2xs" style={{ color: "var(--text-muted)" }}>
            <kbd className="mr-1 rounded border px-1" style={{ borderColor: "var(--border-primary)" }}>↵</kbd> select
          </span>
          <span className="text-2xs" style={{ color: "var(--text-muted)" }}>
            <kbd className="mr-1 rounded border px-1" style={{ borderColor: "var(--border-primary)" }}>esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  );
}
