import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff, Github, Loader2, Lock, Mail, ShieldCheck } from "lucide-react";
import { HeroLogo } from "../components/Logo";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import { getErrorMessage, oauthAuthorize, oauthProviders } from "../services/api";
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
      if (!res.configured) {
        info("SSO not configured", res.message ?? `${provider} login is not set up on the server.`);
      } else if (res.authorize_url) {
        window.location.href = res.authorize_url;
      }
    } catch (err) {
      error("SSO error", getErrorMessage(err));
    } finally {
      setSsoBusy(null);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-night-950 px-4 py-10">
      {/* animated aurora background */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-electric-500/20 blur-[120px] animate-pulse-slow" />
        <div className="absolute -right-32 top-1/4 h-96 w-96 rounded-full bg-cyber-purple/20 blur-[120px] animate-pulse-slower" />
        <div className="absolute bottom-0 left-1/3 h-80 w-80 rounded-full bg-cyber-cyan/10 blur-[100px]" />
        <div className="absolute inset-0 bg-soc-grid opacity-60" />
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-electric-500/60 to-transparent" />
      </div>

      <div className="relative z-10 w-full max-w-md">
        <div className="mb-8 flex justify-center">
          <HeroLogo />
        </div>

        <div className="glass relative overflow-hidden p-8 shadow-[0_0_60px_rgba(56,189,248,0.12)]">
          <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-electric-500 via-cyber-cyan to-cyber-purple" />
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-electric-400" />
            <h2 className="text-xl font-bold text-slate-100">Sign in to the SOC</h2>
          </div>
          <p className="mt-1 text-sm text-slate-500">Access the CyberSentinel X command console</p>

          <form onSubmit={handleSubmit} className="mt-6 space-y-4">
            <div>
              <label className="label" htmlFor="email">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
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
                <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
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
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 text-xs text-slate-400">
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
              <div className="h-px flex-1 bg-night-700" />
              <span className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-600">or continue with</span>
              <div className="h-px flex-1 bg-night-700" />
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => handleOAuth("google")}
                disabled={ssoBusy !== null}
                className="flex items-center justify-center gap-2 rounded-lg border border-night-700 bg-night-850/60 px-3 py-2.5 text-sm font-medium text-slate-300 transition hover:border-electric-500/50 hover:bg-night-800 disabled:opacity-50"
              >
                {ssoBusy === "google" ? <Loader2 className="h-4 w-4 animate-spin" /> : <GoogleIcon />}
                Google
              </button>
              <button
                type="button"
                onClick={() => handleOAuth("github")}
                disabled={ssoBusy !== null}
                className="flex items-center justify-center gap-2 rounded-lg border border-night-700 bg-night-850/60 px-3 py-2.5 text-sm font-medium text-slate-300 transition hover:border-cyber-purple/50 hover:bg-night-800 disabled:opacity-50"
              >
                {ssoBusy === "github" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Github className="h-4 w-4" />}
                GitHub
              </button>
            </div>
            {providers.length > 0 && !providers.some((p) => p.configured) && (
              <p className="mt-2 text-center text-[11px] text-slate-600">
                SSO is not configured on the server — set GOOGLE_CLIENT_ID / GITHUB_CLIENT_ID to enable.
              </p>
            )}
          </div>

          <div className="mt-6 rounded-lg border border-night-700 bg-night-850/60 p-3 text-xs text-slate-400">
            <p className="mb-1 font-semibold text-slate-300">Demo accounts</p>
            <p>admin@cybersentinel.io / Admin@2026</p>
            <p>analyst@cybersentinel.io / Analyst@2026</p>
            <p>viewer@cybersentinel.io / Viewer@2026</p>
          </div>
        </div>

        <p className="mt-6 text-center text-sm text-slate-500">
          New analyst?{" "}
          <Link to="/register" className="font-semibold text-electric-400 hover:underline">
            Create an account
          </Link>
        </p>
      </div>
    </div>
  );
}
