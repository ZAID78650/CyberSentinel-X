import { useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  BarChart3,
  Bell,
  BookOpen,
  Boxes,
  Bug,
  ClipboardList,
  Cpu,
  Crosshair,
  Database,
  Dna,
  FileText,
  Fingerprint,
  Gauge,
  GitBranch,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  Radar,
  Search,
  Server,
  Settings,
  ShieldCheck,
  ShieldHalf,
  Target,
  Users,
  X,
  Zap,
} from "lucide-react";
import { Logo } from "../components/Logo";
import { useAuth } from "../contexts/AuthContext";
import { useWebSocket } from "../hooks/useWebSocket";

const NAV_GROUPS: Array<{ label: string; items: Array<{ to: string; label: string; icon: ReactNode }> }> = [
  {
    label: "Overview",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: <LayoutDashboard className="h-4 w-4" /> },
      { to: "/live-events", label: "Live Events", icon: <Activity className="h-4 w-4" /> },
      { to: "/data-sources", label: "Data Sources", icon: <Database className="h-4 w-4" /> },
    ],
  },
  {
    label: "Security",
    items: [
      { to: "/alerts", label: "Alerts", icon: <AlertTriangle className="h-4 w-4" /> },
      { to: "/incidents", label: "Incidents", icon: <ShieldHalf className="h-4 w-4" /> },
      { to: "/threat-hunting", label: "Threat Hunting", icon: <Crosshair className="h-4 w-4" /> },
      { to: "/campaigns", label: "Campaigns", icon: <Users className="h-4 w-4" /> },
      { to: "/malware-analysis", label: "Malware Analysis", icon: <Bug className="h-4 w-4" /> },
      { to: "/risk-overview", label: "Risk Overview", icon: <Gauge className="h-4 w-4" /> },
      { to: "/defense-center", label: "Defense Center", icon: <ShieldCheck className="h-4 w-4" /> },
    ],
  },
  {
    label: "Investigation",
    items: [
      { to: "/search", label: "Global Search", icon: <Search className="h-4 w-4" /> },
    ],
  },
  {
    label: "AI Analysis",
    items: [
      { to: "/investigation", label: "Investigation Agent", icon: <Radar className="h-4 w-4" /> },
      { to: "/attack-dna", label: "Attack DNA", icon: <Dna className="h-4 w-4" /> },
      { to: "/attack-graph", label: "Attack Graph", icon: <GitBranch className="h-4 w-4" /> },
      { to: "/threat-intelligence", label: "Threat Intelligence", icon: <Fingerprint className="h-4 w-4" /> },
      { to: "/mitre-matrix", label: "MITRE ATT&CK Matrix", icon: <Target className="h-4 w-4" /> },
    ],
  },
  {
    label: "Forensics & Evidence",
    items: [
      { to: "/evidence-ledger", label: "Evidence Ledger", icon: <Boxes className="h-4 w-4" /> },
    ],
  },
  {
    label: "Infrastructure",
    items: [
      { to: "/assets", label: "Assets", icon: <Database className="h-4 w-4" /> },
      { to: "/asset-risk", label: "Asset Risk Intelligence", icon: <Server className="h-4 w-4" /> },
      { to: "/playbooks", label: "Playbooks", icon: <BookOpen className="h-4 w-4" /> },
    ],
  },
  {
    label: "Response",
    items: [
      { to: "/response-center", label: "Response Center", icon: <ShieldCheck className="h-4 w-4" /> },
      { to: "/human-approvals", label: "Human Approvals", icon: <ListChecks className="h-4 w-4" /> },
      { to: "/actions-log", label: "Actions Log", icon: <ClipboardList className="h-4 w-4" /> },
    ],
  },
  {
    label: "Resilience",
    items: [
      { to: "/attack-simulator", label: "Attack Simulator", icon: <Zap className="h-4 w-4" /> },
      { to: "/model-center", label: "Model Center", icon: <Cpu className="h-4 w-4" /> },
      { to: "/compliance", label: "Compliance Center", icon: <BadgeCheck className="h-4 w-4" /> },
    ],
  },
  {
    label: "Reports",
    items: [
      { to: "/incident-reports", label: "Incident Reports", icon: <FileText className="h-4 w-4" /> },
      { to: "/analytics", label: "Analytics", icon: <BarChart3 className="h-4 w-4" /> },
    ],
  },
];

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <>
      {open && <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={onClose} />}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-night-700/70 bg-night-900/90 backdrop-blur transition-transform lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-night-700/70 px-5">
          <Logo />
          <button onClick={onClose} className="text-slate-500 lg:hidden">
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4">
          {NAV_GROUPS.map((group) => (
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

        <div className="border-t border-night-700/70 p-3">
          <NavLink to="/settings" onClick={onClose} className="nav-item">
            <Settings className="h-4 w-4" />
            Settings
          </NavLink>
          <div className="mt-2 flex items-center gap-3 rounded-lg bg-night-800/60 px-3 py-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-electric-500 to-cyber-purple text-xs font-bold text-white">
              {(user?.full_name ?? "A").slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-semibold text-slate-200">{user?.full_name}</p>
              <p className="truncate text-[10px] text-slate-500">{user?.roles.join(", ")}</p>
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
  const location = useLocation();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const pageTitle = NAV_GROUPS.flatMap((g) => g.items).find((i) => i.to === location.pathname)?.label ?? "Console";
  void connected;

  const submitSearch = () => {
    const q = searchQuery.trim();
    if (q) {
      navigate(`/search?q=${encodeURIComponent(q)}`);
    } else {
      navigate("/search");
    }
  };

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-night-700/70 bg-night-900/80 px-5 backdrop-blur">
      <button onClick={onMenu} className="text-slate-400 hover:text-white lg:hidden">
        <Menu className="h-5 w-5" />
      </button>
      <div className="hidden flex-1 md:block">
        <h1 className="text-sm font-bold uppercase tracking-wider text-slate-200">{pageTitle}</h1>
      </div>

      <form
        className="hidden items-center gap-2 rounded-lg border border-night-700 bg-night-850 px-3 py-1.5 md:flex"
        onSubmit={(e) => { e.preventDefault(); submitSearch(); }}
      >
        <Search className="h-3.5 w-3.5 text-slate-500" />
        <input
          className="w-48 bg-transparent text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none"
          placeholder="Global search: IP, incident, DNA…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <button type="submit" className="text-[10px] font-semibold uppercase text-electric-400 hover:underline">Go</button>
      </form>

      <div className="flex items-center gap-1.5 rounded-full border border-cyber-green/30 bg-cyber-green/10 px-3 py-1">
        <span className={`h-2 w-2 rounded-full ${connected ? "bg-cyber-green" : "bg-cyber-yellow"} animate-pulse`} />
        <span className="text-[11px] font-semibold text-cyber-green">{connected ? "REAL-TIME" : "CONNECTING"}</span>
      </div>

      <button className="relative text-slate-400 hover:text-white" title="Notifications">
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
          CyberSentinel X · Agentic AI-Powered SOC Platform · Smart India Hackathon 2026 Prototype
        </footer>
      </div>
    </div>
  );
}
