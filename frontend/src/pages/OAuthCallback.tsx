import { useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, ShieldCheck } from "lucide-react";
import { completeOAuth } from "../services/api";

export default function OAuthCallback() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  useEffect(() => {
    const access = params.get("access");
    const refresh = params.get("refresh");
    if (access && refresh) {
      completeOAuth(access, refresh);
      window.dispatchEvent(new CustomEvent("auth:oauth"));
      navigate("/dashboard", { replace: true });
    } else {
      navigate("/login", { replace: true });
    }
  }, [params, navigate]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-night-950">
      <div className="relative">
        <div className="absolute inset-0 -z-10 scale-150 rounded-full bg-electric-500/20 blur-2xl" />
        <ShieldCheck className="h-16 w-16 text-electric-400" />
      </div>
      <Loader2 className="h-5 w-5 animate-spin text-electric-400" />
      <p className="text-sm text-slate-400">Completing secure sign-in…</p>
    </div>
  );
}
