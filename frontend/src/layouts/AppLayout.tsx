import { useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  Boxes,
  Brain,
  Bug,
  Cpu,
  Database,
  Dna,
  FileText,
  Fingerprint,
  Gauge,
  GitBranch,
  Globe,
  LayoutDashboard,
  LogOut,
  Map,
  Menu,
  Microscope,
  Network,
  Radar,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  ShieldHalf,
  TrendingUp,
  UserCog,
  Users,
  X,
  Zap,
} from "lucide-react";
import { Logo } from "../components/Logo";
import { useAuth } from "../contexts/AuthContext";
import { useWebSocket } from "../hooks/useWebSocket";
import { isDemoMode } from "../services/api";
import { useTheme } from "../contexts/ThemeContext";
import { Moon, Sun } from "lucide-react";

const NAV_GROUPS: Array<{ label: string; items: Array<{ to: string; label: string; icon: ReactNode }> }> = [
  {
    label: "Command Center",
    items: [
      { to: "/dashboard", label: "Overview", icon: <LayoutDashboard className="h-4 w-4" /> },
      { to: "/cybercrime-scanner", label: "Cybercrime Scanner", icon: <Bug className="h-4 w-4" /> },
      { to: "/sih-demo", label: "SIH Demo Mode", icon: <Zap className="h-4 w-4" /> },
    ],
  },
  {
    label: "Financial Intelligence",
    items: [
      { to: "/financial-intelligence", label: "Financial Intel", icon: <TrendingUp className="h-4 w-4" /> },
      { to: "/predictive-alerts", label: "Predictive Intelligence", icon: <Brain className="h-4 w-4" /> },
      { to: "/gis-heatmap", label: "Risk Heatmap", icon: <Map className="h-4 w-4" /> },
      { to: "/threat-globe", label: "Threat Globe", icon: <Globe className="h-4 w-4" /> },
      { to: "/entity-network", label: "Entity Network", icon: <Network className="h-4 w-4" /> },
    ],
  },
  {
    label: "Alerts & Incidents",
    items: [
      { to: "/alerts", label: "Alerts", icon: <AlertTriangle className="h-4 w-4" /> },
      { to: "/incidents", label: "Incidents", icon: <ShieldHalf className="h-4 w-4" /> },
      { to: "/lea-dashboard", label: "LEA Dashboard", icon: <Shield className="h-4 w-4" /> },
      { to: "/live-events", label: "Live Events", icon: <Radar className="h-4 w-4" /> },
    ],
  },
  {
    label: "Investigation & Cases",
    items: [
      { to: "/investigation", label: "Investigation Cases", icon: <Search className="h-4 w-4" /> },
      { to: "/evidence-ledger", label: "Evidence & Audit", icon: <Boxes className="h-4 w-4" /> },
      { to: "/incident-reports", label: "Intelligence Reports", icon: <FileText className="h-4 w-4" /> },
    ],
  },
  {
    label: "ML & Analytics",
    items: [
      { to: "/model-performance", label: "Model Performance", icon: <Microscope className="h-4 w-4" /> },
      { to: "/what-if", label: "What-If Simulator", icon: <Cpu className="h-4 w-4" /> },
      { to: "/analytics", label: "Analytics", icon: <BarChart3 className="h-4 w-4" /> },
      { to: "/monitoring", label: "System Monitor", icon: <Activity className="h-4 w-4" /> },
    ],
  },
  {
    label: "Advanced Modules",
    items: [
      { to: "/threat-intelligence", label: "Threat Intel", icon: <Fingerprint className="h-4 w-4" /> },
      { to: "/risk-overview", label: "Risk Overview", icon: <Gauge className="h-4 w-4" /> },
      { to: "/attack-dna", label: "Attack DNA", icon: <Dna className="h-4 w-4" /> },
      { to: "/attack-graph", label: "Attack Graph", icon: <GitBranch className="h-4 w-4" /> },
      { to: "/campaigns", label: "Campaigns", icon: <Users className="h-4 w-4" /> },
      { to: "/data-sources", label: "Data Sources", icon: <Database className="h-4 w-4" /> },
      { to: "/response-center", label: "Response Center", icon: <ShieldCheck className="h-4 w-4" /> },
      { to: "/malware-analysis", label: "Malware Analysis", icon: <Bug className="h-4 w-4" /> },
    ],
  },
];

const ADMIN_NAV_GROUP = {
  label: "Administration",
  items: [{ to: "/admin/users", label: "Users", icon: <UserCog className="h-4 w-4" /> }],
};

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const isAdmin = user?.roles.includes("ADMIN") ?? false;
  const groups = isAdmin ? [...NAV_GROUPS, ADMIN_NAV_GROUP] : NAV_GROUPS;

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <>
      {open && <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={onClose} />}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r transition-transform backdrop-blur lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
        style={{ borderColor: "var(--surface-border)", backgroundColor: "var(--surface)" }}
      >
        <div className="flex h-16 items-center justify-between border-b px-5" style={{ borderColor: "var(--surface-border)" }}>
          <Logo />
          <button onClick={onClose} className="text-slate-500 lg:hidden">
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4">
          {groups.map((group) => (
            <div key={group.label}>
              <p className="mb-1.5 px-3 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-600">
                {group.label}
              </p>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={onClose}
                  className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                >
                  {item.icon}
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="border-t p-3" style={{ borderColor: "var(--surface-border)" }}>
          <NavLink to="/settings" onClick={onClose} className="nav-item">
            <Settings className="h-4 w-4" />
            Settings
          </NavLink>
          <div className="mt-2 flex items-center gap-3 rounded-lg px-3 py-2.5" style={{ background: "var(--surface-raised)" }}>
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-electric-500 to-cyber-purple text-xs font-bold text-white">
              {(user?.full_name ?? "A").slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-semibold" style={{ color: "var(--on-surface)" }}>{user?.full_name}</p>
              <p className="truncate text-[10px]" style={{ color: "var(--on-surface-faint)" }}>
                {user?.roles.join(", ")}
                {user?.oauth_provider
                  ? ` · via ${user.oauth_provider.charAt(0).toUpperCase() + user.oauth_provider.slice(1)}`
                  : ""}
              </p>
            </div>
            <button onClick={handleLogout} title="Log out" className="text-slate-500 hover:text-cyber-red">
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}

function TopBar({ onMenu }: { onMenu: () => void }) {
  const { connected } = useWebSocket();
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const groups = (user?.roles.includes("ADMIN") ?? false) ? [...NAV_GROUPS, ADMIN_NAV_GROUP] : NAV_GROUPS;
  const pageTitle = groups.flatMap((g) => g.items).find((i) => i.to === location.pathname)?.label ?? "Console";
  const demoMode = isDemoMode();

  const submitSearch = () => {
    const q = searchQuery.trim();
    if (q) {
      navigate(`/search?q=${encodeURIComponent(q)}`);
    } else {
      navigate("/search");
    }
  };

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b px-5 backdrop-blur" style={{ borderColor: "var(--surface-border)", backgroundColor: "var(--surface)" }}>
      <button onClick={onMenu} className="text-slate-400 hover:text-white lg:hidden">
        <Menu className="h-5 w-5" />
      </button>
      <div className="hidden flex-1 md:block">
        <h1 className="text-sm font-bold uppercase tracking-wider" style={{ color: "var(--on-surface)" }}>{pageTitle}</h1>
      </div>

      <form
        className="hidden items-center gap-2 rounded-lg border px-3 py-1.5 md:flex"
        onSubmit={(e) => { e.preventDefault(); submitSearch(); }}
      >
        <Search className="h-3.5 w-3.5" style={{ color: "var(--on-surface-faint)" }} />
        <input
          className="w-48 bg-transparent text-xs focus:outline-none"
          placeholder="Search complaints, zones, alerts…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <button type="submit" className="text-[10px] font-semibold uppercase text-electric-400 hover:underline">Go</button>
      </form>

      <div className="flex items-center gap-1.5 rounded-full border px-3 py-1" style={{ borderColor: demoMode ? "var(--border-warning, #f59e0b)" : connected ? "rgba(34,197,94,0.3)" : "rgba(234,179,8,0.3)", background: demoMode ? "rgba(245,158,11,0.1)" : connected ? "rgba(34,197,94,0.1)" : "rgba(234,179,8,0.1)" }}>
        <span className={`h-2 w-2 rounded-full animate-pulse`} style={{ background: demoMode ? "#f59e0b" : connected ? "#22c55e" : "#eab308" }} />
        <span className="text-[11px] font-semibold" style={{ color: demoMode ? "#f59e0b" : connected ? "#22c55e" : "#eab308" }}>{demoMode ? "DEMO MODE" : connected ? "REAL-TIME" : "CONNECTING"}</span>
      </div>

      <button
        onClick={toggleTheme}
        className="rounded-lg p-2 transition-colors"
        style={{ color: "var(--on-surface-muted)" }}
        title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      >
        {theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
      </button>

      <button className="relative" style={{ color: "var(--on-surface-muted)" }} title="Notifications">
        <Bell className="h-5 w-5" />
        <span className="absolute -right-0.5 -top-0.5 flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyber-red opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-cyber-red" />
        </span>
      </button>
    </header>
  );
}

export default function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="flex min-h-screen flex-col lg:pl-64">
        <TopBar onMenu={() => setSidebarOpen(true)} />
        <main className="flex-1 p-5 lg:p-6">
          <Outlet />
        </main>
        <footer className="border-t border-night-700/70 px-6 py-3 text-center text-[11px] text-slate-600">
          CyberSentinel X · Predictive Financial Cybercrime Intelligence · SIH 2026 (SIH26184)
        </footer>
      </div>
    </div>
  );
}
