import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { KeyRound, Loader2 } from "lucide-react";
import { HeroLogo } from "../components/Logo";
import { useToast } from "../components/ui/Toast";
import { api, getErrorMessage } from "../services/api";

export default function ForgotPassword() {
  const { error } = useToast();
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await api.post("/auth/forgot-password", { email });
      setSent(true);
    } catch (err) {
      error("Request failed", getErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-night-950 px-4">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-electric-500/20 blur-[120px] animate-pulse-slow" />
        <div className="absolute -right-32 top-1/4 h-96 w-96 rounded-full bg-cyber-purple/20 blur-[120px] animate-pulse-slower" />
        <div className="absolute inset-0 bg-soc-grid opacity-60" />
      </div>
      <div className="relative z-10 w-full max-w-md">
        <div className="mb-8 flex justify-center">
          <HeroLogo />
        </div>
        <div className="glass relative overflow-hidden p-8">
          <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-electric-500 via-cyber-cyan to-cyber-purple" />
          <h2 className="flex items-center gap-2 text-xl font-bold text-slate-100">
            <KeyRound className="h-5 w-5 text-electric-400" /> Reset password
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            {sent
              ? "If that email is registered, a reset link has been sent. Check your inbox."
              : "Enter your email and we'll send you a reset link."}
          </p>
          {!sent && (
            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <div>
                <label className="label">Email</label>
                <input type="email" className="input" placeholder="you@company.io" value={email}
                  onChange={(e) => setEmail(e.target.value)} required />
              </div>
              <button type="submit" disabled={submitting} className="btn-primary w-full">
                {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Send reset link"}
              </button>
            </form>
          )}
          <p className="mt-6 text-center text-sm text-slate-500">
            <Link to="/login" className="font-semibold text-electric-400 hover:underline">Back to sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
