import { useCallback, useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity, AlertTriangle, BarChart3, Bell, Brain, Bug,
  ChevronLeft, ChevronRight, Database, FileText, Gauge,
  Globe, LayoutDashboard, LogOut, Map, Menu, Microscope,
  Network, Radar, Search, Settings, Shield, TrendingUp,
  UserCog, Users, Zap, X,
} from "lucide-react";
import { Logo } from "../components/Logo";
import { CommandPalette } from "../components/CommandPalette";
import { useAuth } from "../contexts/AuthContext";
import { useWebSocket } from "../hooks/useWebSocket";
import { isDemoMode } from "../services/api";
import { useTheme } from "../contexts/ThemeContext";

/* ── Navigation Structure ────────────────────────────────────────────── */

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  badge?: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const CORE_NAV: NavGroup[] = [
  {
    label: "OVERVIEW",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: <LayoutDashboard className="h-4 w-4" /> },
    ],
  },
  {
    label: "INTELLIGENCE",
    items: [
      { to: "/cybercrime-scanner", label: "Scanner", icon: <Bug className="h-4 w-4" /> },
      { to: "/financial-intelligence", label: "Complaints", icon: <FileText className="h-4 w-4" /> },
      { to: "/predictive-alerts", label: "Transactions", icon: <TrendingUp className="h-4 w-4" /> },
      { to: "/model-performance", label: "Predictions", icon: <Brain className="h-4 w-4" /> },
    ],
  },
  {
    label: "ANALYTICS",
    items: [
      { to: "/gis-heatmap", label: "Heatmap", icon: <Map className="h-4 w-4" /> },
      { to: "/entity-network", label: "Network", icon: <Network className="h-4 w-4" /> },
    ],
  },
  {
    label: "OPERATIONS",
    items: [
      { to: "/alerts", label: "Alerts", icon: <AlertTriangle className="h-4 w-4" />, badge: "3" },
      { to: "/investigation", label: "Cases", icon: <Shield className="h-4 w-4" /> },
      { to: "/incident-reports", label: "Reports", icon: <FileText className="h-4 w-4" /> },
    ],
  },
  {
    label: "SYSTEM",
    items: [
      { to: "/model-performance", label: "Models", icon: <Microscope className="h-4 w-4" /> },
      { to: "/monitoring", label: "Monitoring", icon: <Activity className="h-4 w-4" /> },
      { to: "/sih-demo", label: "SIH Demo", icon: <Zap className="h-4 w-4" /> },
    ],
  },
];

const ADMIN_GROUP: NavGroup = {
  label: "ADMIN",
  items: [
    { to: "/admin/users", label: "Users", icon: <UserCog className="h-4 w-4" /> },
  ],
};

/* ── Sidebar ─────────────────────────────────────────────────────────── */

function Sidebar({
  collapsed,
  onToggle,
  mobileOpen,
  onMobileClose,
}: {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const isAdmin = user?.roles.includes("ADMIN") ?? false;
  const groups = isAdmin ? [...CORE_NAV, ADMIN_GROUP] : CORE_NAV;

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const sidebarWidth = collapsed ? "var(--sidebar-collapsed-width)" : "var(--sidebar-width)";

  return (
    <>
      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden" onClick={onMobileClose} />
      )}

      <aside
        className="fixed inset-y-0 left-0 z-50 flex flex-col border-r transition-all duration-200"
        style={{
          width: sidebarWidth,
          minWidth: sidebarWidth,
          borderColor: "var(--border-primary)",
          background: "var(--bg-secondary)",
          transform: mobileOpen ? "translateX(0)" : undefined,
        }}
      >
        {/* Logo */}
        <div className="flex h-14 items-center justify-between border-b px-4" style={{ borderColor: "var(--border-primary)" }}>
          <Logo collapsed={collapsed} />
          {/* Mobile close */}
          <button onClick={onMobileClose} className="rounded p-1 hover:bg-white/5 lg:hidden" style={{ color: "var(--text-muted)" }}>
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {groups.map((group) => (
            <div key={group.label} className="mb-3">
              {!collapsed && (
                <p className="mb-1 px-3 text-2xs font-bold uppercase tracking-widest" style={{ color: "var(--text-muted)" }}>
                  {group.label}
                </p>
              )}
              {group.items.map((item) => (
                <NavLink
                  key={item.to + item.label}
                  to={item.to}
                  onClick={onMobileClose}
                  title={collapsed ? item.label : undefined}
                  className={({ isActive }) =>
                    `nav-item ${collapsed ? "justify-center px-0" : ""} ${isActive ? "active" : ""}`
                  }
                >
                  {item.icon}
                  {!collapsed && (
                    <>
                      <span className="flex-1 truncate">{item.label}</span>
                      {item.badge && (
                        <span className="flex h-5 min-w-[20px] items-center justify-center rounded-full bg-red-500/20 px-1.5 text-2xs font-bold text-red-400">
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* Sidebar footer */}
        <div className="border-t px-2 py-2" style={{ borderColor: "var(--border-primary)" }}>
          {/* Settings */}
          <NavLink
            to="/settings"
            onClick={onMobileClose}
            title={collapsed ? "Settings" : undefined}
            className={({ isActive }) => `nav-item ${collapsed ? "justify-center px-0" : ""} ${isActive ? "active" : ""}`}
          >
            <Settings className="h-4 w-4" />
            {!collapsed && <span>Settings</span>}
          </NavLink>

          {/* User card */}
          {!collapsed && (
            <div className="mt-2 flex items-center gap-3 rounded-lg px-3 py-2" style={{ background: "var(--bg-tertiary)" }}>
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-bold text-white" style={{ background: "linear-gradient(135deg, #3b82f6, #8b5cf6)" }}>
                {(user?.full_name ?? "A").slice(0, 1).toUpperCase()}
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-semibold" style={{ color: "var(--text-primary)" }}>{user?.full_name}</p>
                <p className="truncate text-2xs" style={{ color: "var(--text-muted)" }}>
                  {user?.roles?.[0] ?? "User"}
                  {user?.oauth_provider ? ` · ${user.oauth_provider}` : ""}
                </p>
              </div>
              <button onClick={handleLogout} title="Log out" className="rounded p-1 transition-colors hover:bg-white/5 hover:text-red-400" style={{ color: "var(--text-muted)" }}>
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          )}

          {/* Collapsed user avatar */}
          {collapsed && (
            <button onClick={handleLogout} title="Log out" className="mx-auto mt-2 flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold text-white" style={{ background: "linear-gradient(135deg, #3b82f6, #8b5cf6)" }}>
              {(user?.full_name ?? "A").slice(0, 1).toUpperCase()}
            </button>
          )}
        </div>

        {/* Collapse toggle (desktop only) */}
        <button
          onClick={onToggle}
          className="hidden lg:flex absolute -right-3 top-20 z-50 h-6 w-6 items-center justify-center rounded-full border"
          style={{ borderColor: "var(--border-primary)", background: "var(--bg-secondary)", color: "var(--text-muted)" }}
        >
          {collapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronLeft className="h-3 w-3" />}
        </button>
      </aside>
    </>
  );
}

/* ── Top Bar ─────────────────────────────────────────────────────────── */

function TopBar({
  onMobileMenu,
  onOpenCmdPalette,
}: {
  onMobileMenu: () => void;
  onOpenCmdPalette: () => void;
}) {
  const { connected } = useWebSocket();
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const demoMode = isDemoMode();

  // Derive page title from route
  const pageTitles: Record<string, string> = {
    "/dashboard": "Dashboard",
    "/cybercrime-scanner": "Scanner",
    "/financial-intelligence": "Complaints",
    "/predictive-alerts": "Transactions",
    "/model-performance": "Predictions",
    "/gis-heatmap": "Heatmap",
    "/entity-network": "Network",
    "/alerts": "Alerts",
    "/investigation": "Cases",
    "/incident-reports": "Reports",
    "/monitoring": "Monitoring",
    "/sih-demo": "SIH Demo Mode",
    "/admin/users": "User Management",
    "/settings": "Settings",
  };
  const pageTitle = pageTitles[location.pathname] ?? "Console";

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b px-4 backdrop-blur-md lg:px-5" style={{ borderColor: "var(--border-primary)", background: "rgba(12, 19, 34, 0.85)" }}>
      {/* Mobile menu */}
      <button onClick={onMobileMenu} className="rounded-lg p-1.5 hover:bg-white/5 lg:hidden" style={{ color: "var(--text-secondary)" }}>
        <Menu className="h-5 w-5" />
      </button>

      {/* Page title */}
      <h1 className="text-sm font-bold tracking-wide" style={{ color: "var(--text-primary)" }}>
        {pageTitle}
      </h1>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Global search trigger */}
      <button
        onClick={onOpenCmdPalette}
        className="flex items-center gap-2 rounded-lg border px-3 py-1.5 transition-colors hover:border-[var(--border-accent)]"
        style={{ borderColor: "var(--border-primary)", color: "var(--text-muted)" }}
      >
        <Search className="h-3.5 w-3.5" />
        <span className="hidden text-xs md:inline">Search...</span>
        <kbd className="hidden rounded border px-1.5 py-0.5 text-2xs md:inline" style={{ borderColor: "var(--border-primary)" }}>⌘K</kbd>
      </button>

      {/* Data mode indicator */}
      {demoMode ? (
        <div className="mode-demo">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
          <span className="text-2xs font-semibold text-amber-400">DEMO</span>
        </div>
      ) : connected ? (
        <div className="mode-live">
          <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
          <span className="text-2xs font-semibold text-green-400">LIVE</span>
        </div>
      ) : (
        <div className="mode-offline">
          <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />
          <span className="text-2xs font-semibold text-slate-400">OFFLINE</span>
        </div>
      )}

      {/* Theme toggle */}
      <button
        onClick={toggleTheme}
        className="rounded-lg p-1.5 transition-colors hover:bg-white/5"
        style={{ color: "var(--text-secondary)" }}
        title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      >
        {theme === "dark" ? "☀️" : "🌙"}
      </button>

      {/* Notifications */}
      <button className="relative rounded-lg p-1.5 transition-colors hover:bg-white/5" style={{ color: "var(--text-secondary)" }} title="Notifications">
        <Bell className="h-4.5 w-4.5" />
        <span className="absolute right-0.5 top-0.5 flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-500 opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500" />
        </span>
      </button>

      {/* System status */}
      <div className="hidden items-center gap-2 xl:flex">
        <span className="h-1.5 w-1.5 rounded-full bg-green-400" />
        <span className="text-2xs font-medium" style={{ color: "var(--text-muted)" }}>SYSTEM OK</span>
      </div>
    </header>
  );
}

/* ── Main Layout ─────────────────────────────────────────────────────── */

export default function AppLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return localStorage.getItem("csx-sidebar-collapsed") === "true";
    } catch {
      return false;
    }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);

  // Persist sidebar state
  useEffect(() => {
    try {
      localStorage.setItem("csx-sidebar-collapsed", String(sidebarCollapsed));
    } catch {}
  }, [sidebarCollapsed]);

  // CMD+K keyboard shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCmdOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const sidebarWidth = sidebarCollapsed ? "var(--sidebar-collapsed-width)" : "var(--sidebar-width)";

  return (
    <div className="min-h-screen">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((p) => !p)}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      <div className="flex min-h-screen flex-col transition-all duration-200" style={{ marginLeft: sidebarWidth }}>
        <TopBar
          onMobileMenu={() => setMobileOpen(true)}
          onOpenCmdPalette={() => setCmdOpen(true)}
        />
        <main className="flex-1 p-4 lg:p-5">
          <Outlet />
        </main>
        <footer className="border-t px-6 py-3 text-center text-2xs" style={{ borderColor: "var(--border-primary)", color: "var(--text-muted)" }}>
          CyberSentinel-X · Predictive Cybercrime Intelligence · SIH 2026 (SIH26184)
        </footer>
      </div>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  );
}
