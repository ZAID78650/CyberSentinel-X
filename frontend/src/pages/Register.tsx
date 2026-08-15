import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Loader2, ShieldCheck, UserPlus } from "lucide-react";
import { HeroLogo } from "../components/Logo";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import { getErrorMessage } from "../services/api";

export default function Register() {
  const { register } = useAuth();
  const { success, warning, error } = useToast();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    full_name: "",
    email: "",
    organization: "",
    password: "",
    confirm_password: "",
    accept_terms: false,
  });
  const [submitting, setSubmitting] = useState(false);

  const set = (key: keyof typeof form, value: string | boolean) => setForm((f) => ({ ...f, [key]: value }));

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (form.password.length < 8) {
      warning("Weak password", "Password must be at least 8 characters with letters and numbers.");
      return;
    }
    if (form.password !== form.confirm_password) {
      warning("Passwords do not match", "Please re-enter your password.");
      return;
    }
    if (!form.accept_terms) {
      warning("Terms required", "You must accept the terms and conditions.");
      return;
    }
    setSubmitting(true);
    try {
      await register({ ...form, accept_terms: form.accept_terms });
      success("Account created", "Welcome to CyberSentinel X.");
      navigate("/dashboard");
    } catch (err) {
      error("Registration failed", getErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  const inputCls = "input";
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-night-950 px-4 py-10">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-electric-500/20 blur-[120px] animate-pulse-slow" />
        <div className="absolute -right-32 top-1/4 h-96 w-96 rounded-full bg-cyber-purple/20 blur-[120px] animate-pulse-slower" />
        <div className="absolute inset-0 bg-soc-grid opacity-60" />
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-electric-500/60 to-transparent" />
      </div>
      <div className="relative z-10 w-full max-w-lg">
        <div className="mb-8 flex justify-center">
          <HeroLogo />
        </div>
        <div className="glass relative overflow-hidden p-8 shadow-[0_0_60px_rgba(56,189,248,0.12)]">
          <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-electric-500 via-cyber-cyan to-cyber-purple" />
          <h2 className="flex items-center gap-2 text-xl font-bold text-slate-100">
            <UserPlus className="h-5 w-5 text-electric-400" /> Create analyst account
          </h2>
          <p className="mt-1 text-sm text-slate-500">Join the CyberSentinel X security operations center</p>

          <form onSubmit={handleSubmit} className="mt-6 grid gap-4 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <label className="label">Full name</label>
              <input className={inputCls} placeholder="Ava Security Analyst" value={form.full_name}
                onChange={(e) => set("full_name", e.target.value)} required />
            </div>
            <div className="sm:col-span-2">
              <label className="label">Email</label>
              <input type="email" className={inputCls} placeholder="you@company.io" value={form.email}
                onChange={(e) => set("email", e.target.value)} required />
            </div>
            <div className="sm:col-span-2">
              <label className="label">Organization</label>
              <input className={inputCls} placeholder="Acme Corp SOC" value={form.organization}
                onChange={(e) => set("organization", e.target.value)} />
            </div>
            <div>
              <label className="label">Password</label>
              <input type="password" className={inputCls} placeholder="Min 8 chars, letters + numbers" value={form.password}
                onChange={(e) => set("password", e.target.value)} required />
            </div>
            <div>
              <label className="label">Confirm password</label>
              <input type="password" className={inputCls} placeholder="Repeat password" value={form.confirm_password}
                onChange={(e) => set("confirm_password", e.target.value)} required />
            </div>
            <label className="flex items-center gap-2 text-xs text-slate-400 sm:col-span-2">
              <input type="checkbox" checked={form.accept_terms} onChange={(e) => set("accept_terms", e.target.checked)}
                className="h-3.5 w-3.5 accent-electric-500" />
              I accept the Terms of Service and Security Policy
            </label>

            <button type="submit" disabled={submitting} className="btn-primary w-full sm:col-span-2">
              {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
              {submitting ? "Creating account…" : "Create Account"}
            </button>
          </form>
        </div>

        <p className="mt-6 text-center text-sm text-slate-500">
          Already have an account?{" "}
          <Link to="/login" className="font-semibold text-electric-400 hover:underline">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
