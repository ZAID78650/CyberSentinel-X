import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff, Github, Loader2, Lock, Mail, ShieldCheck, Zap } from "lucide-react";
import { HeroLogo } from "../components/Logo";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import { getErrorMessage, oauthAuthorize, oauthProviders, isDemoMode } from "../services/api";
import { useTheme } from "../contexts/ThemeContext";
import { Moon, Sun } from "lucide-react";
import type { OAuthProviderStatus } from "../types";

function GoogleIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden="true">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.1c-.22-.66-.35-1.36-.35-2.1s.13-1.44.35-2.1V7.06H2.18A10.97 10.97 0 0 0 1 12c0 1.77.43 3.45 1.18 4.94l3.66-2.84z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
    </svg>
  );
}

export default function Login() {
  const { login } = useAuth();
  const { success, warning, error, info } = useToast();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [ssoBusy, setSsoBusy] = useState<string | null>(null);
  const [providers, setProviders] = useState<OAuthProviderStatus[]>([]);

  const demoMode = isDemoMode();
  const { theme, toggleTheme } = useTheme();

  useEffect(() => {
    oauthProviders().then((p) => setProviders(p)).catch(() => undefined);
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      warning("Missing credentials", "Enter your email and password.");
      return;
    }
    setSubmitting(true);
    try {
      await login(email, password, rememberMe);
      success("Welcome back", "Successfully authenticated to the SOC console.");
      navigate("/dashboard");
    } catch (err) {
      error("Login failed", getErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleOAuth = async (provider: string) => {
    setSsoBusy(provider);
    try {
      const res = await oauthAuthorize(provider);
      if (res.configured && res.authorize_url) {
        // Real OAuth — redirect to the provider's consent screen
        window.location.href = res.authorize_url;
      } else {
        // Demo mode — tokens & user are already stored in localStorage by
        // oauthAuthorize.  Use a hard redirect so the fresh page load picks
        // them up via tokenStore.getUser() in AuthProvider's useState,
        // avoiding the React-state race condition that blocked navigate().
        const providerName = provider === "google" ? "Google" : "GitHub";
        info(
          `${providerName} Demo`,
          res.message ?? `Signed in with ${providerName} (demo mode)`,
        );
        window.location.href = "/dashboard";
      }
    } catch (err) {
      error("SSO error", getErrorMessage(err));
    } finally {
      setSsoBusy(null);
    }
  };

  const fillDemo = (role: string) => {
    if (role === "admin") {
      setEmail("admin@cybersentinel.io");
      setPassword("Admin@2026");
    } else if (role === "analyst") {
      setEmail("analyst@cybersentinel.io");
      setPassword("Analyst@2026");
    } else {
      setEmail("viewer@cybersentinel.io");
      setPassword("Viewer@2026");
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10" style={{ background: "var(--surface)" }}>
      {/* animated aurora background */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-electric-500/20 blur-[120px] animate-pulse-slow" />
        <div className="absolute -right-32 top-1/4 h-96 w-96 rounded-full bg-cyber-purple/20 blur-[120px] animate-pulse-slower" />
        <div className="absolute bottom-0 left-1/3 h-80 w-80 rounded-full bg-cyber-cyan/10 blur-[100px]" />
        <div className="absolute inset-0 bg-soc-grid opacity-60" />
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-electric-500/60 to-transparent" />
      </div>

      <div className="absolute top-4 right-4 z-20">
        <button
          onClick={toggleTheme}
          className="rounded-lg p-2 transition-colors"
          style={{ color: "var(--on-surface-muted)" }}
          title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        >
          {theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
        </button>
      </div>
      <div className="relative z-10 w-full max-w-md">
        {/* Demo mode banner */}
        {demoMode && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-cyber-yellow/30 bg-cyber-yellow/10 px-4 py-2.5">
            <Zap className="h-4 w-4 text-cyber-yellow" />
            <div>
              <p className="text-xs font-semibold text-cyber-yellow">Demo Mode Active</p>
              <p className="text-[10px] text-cyber-yellow/70">
                Backend server not detected — using local demo authentication
              </p>
            </div>
          </div>
        )}

        <div className="mb-8 flex justify-center">
          <HeroLogo />
        </div>

        <div className="glass relative overflow-hidden p-8 shadow-[0_0_60px_rgba(56,189,248,0.12)]">
          <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-electric-500 via-cyber-cyan to-cyber-purple" />
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-electric-400" />
            <h2 className="text-xl font-bold" style={{ color: "var(--on-surface)" }}>Sign in to the SOC</h2>
          </div>
          <p className="mt-1 text-sm" style={{ color: "var(--on-surface-faint)" }}>Access the CyberSentinel X command console</p>

          <form onSubmit={handleSubmit} className="mt-6 space-y-4">
            <div>
              <label className="label" htmlFor="email">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" style={{ color: "var(--on-surface-faint)" }} />
                <input
                  id="email"
                  type="email"
                  className="input pl-10"
                  placeholder="analyst@cybersentinel.io"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                />
              </div>
            </div>

            <div>
              <label className="label" htmlFor="password">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" style={{ color: "var(--on-surface-faint)" }} />
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  className="input pl-10 pr-10"
                  placeholder="••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 hover:opacity-80"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 text-xs" style={{ color: "var(--on-surface-muted)" }}>
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="h-3.5 w-3.5 accent-electric-500"
                />
                Remember me
              </label>
              <Link to="/forgot-password" className="text-xs text-electric-400 hover:underline">
                Forgot password?
              </Link>
            </div>

            <button type="submit" disabled={submitting} className="btn-primary w-full">
              {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
              {submitting ? "Authenticating…" : "Sign In"}
            </button>
          </form>

          {/* Social login */}
          <div className="mt-6">
            <div className="flex items-center gap-3">
              <div className="h-px flex-1" style={{ background: "var(--surface-border)" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.2em]" style={{ color: "var(--on-surface-faint)" }}>or continue with</span>
              <div className="h-px flex-1" style={{ background: "var(--surface-border)" }} />
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => handleOAuth("google")}
                disabled={ssoBusy !== null}
                className="flex items-center justify-center gap-2 rounded-lg border px-3 py-2.5 text-sm font-medium transition disabled:opacity-50"
                style={{ borderColor: "var(--surface-border)", background: "var(--surface-raised)", color: "var(--on-surface-muted)" }}
              >
                {ssoBusy === "google" ? <Loader2 className="h-4 w-4 animate-spin" /> : <GoogleIcon />}
                Google
              </button>
              <button
                type="button"
                onClick={() => handleOAuth("github")}
                disabled={ssoBusy !== null}
                className="flex items-center justify-center gap-2 rounded-lg border px-3 py-2.5 text-sm font-medium transition disabled:opacity-50"
                style={{ borderColor: "var(--surface-border)", background: "var(--surface-raised)", color: "var(--on-surface-muted)" }}
              >
                {ssoBusy === "github" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Github className="h-4 w-4" />}
                GitHub
              </button>
            </div>
            <p className="mt-2 text-center text-[11px]" style={{ color: "var(--on-surface-faint)" }}>
              {providers.some((p) => p.configured)
                ? "SSO is configured — click to sign in"
                : "Demo mode — SSO simulates login without external providers"}
            </p>
          </div>

          {/* Demo accounts */}
          <div className="mt-6 rounded-lg border p-3 text-xs" style={{ borderColor: "var(--surface-border)", background: "var(--surface-raised)", color: "var(--on-surface-muted)" }}>
            <p className="mb-2 font-semibold" style={{ color: "var(--on-surface)" }}>Demo Accounts (click to fill)</p>
            <div className="space-y-1.5">
              <button
                type="button"
                onClick={() => fillDemo("admin")}
                className="flex w-full items-center justify-between rounded-md px-2 py-1 text-left transition hover:opacity-80"
              >
                <span><span className="font-mono text-electric-400">admin@cybersentinel.io</span> / Admin@2026</span>
                <span className="text-[9px] uppercase text-electric-500">ADMIN</span>
              </button>
              <button
                type="button"
                onClick={() => fillDemo("analyst")}
                className="flex w-full items-center justify-between rounded-md px-2 py-1 text-left transition hover:opacity-80"
              >
                <span><span className="font-mono text-electric-400">analyst@cybersentinel.io</span> / Analyst@2026</span>
                <span className="text-[9px] uppercase text-cyber-purple">ANALYST</span>
              </button>
              <button
                type="button"
                onClick={() => fillDemo("viewer")}
                className="flex w-full items-center justify-between rounded-md px-2 py-1 text-left transition hover:opacity-80"
              >
                <span><span className="font-mono text-electric-400">viewer@cybersentinel.io</span> / Viewer@2026</span>
                <span className="text-[9px] uppercase text-cyber-green">VIEWER</span>
              </button>
            </div>
          </div>
        </div>

        <p className="mt-6 text-center text-sm" style={{ color: "var(--on-surface-faint)" }}>
          New analyst?{" "}
          <Link to="/register" className="font-semibold text-electric-400 hover:underline">
            Create an account
          </Link>
        </p>
      </div>
    </div>
  );
}
