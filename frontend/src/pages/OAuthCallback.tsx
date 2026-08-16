import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, ShieldCheck } from "lucide-react";
import { completeOAuth } from "../services/api";

function readParams(): { access: string | null; refresh: string | null } {
  // Tokens arrive in the URL fragment (#access=...&refresh=...) so they never
  // hit server/referrer logs. Fall back to the query string for older links.
  const raw = window.location.hash.replace(/^#/, "") || window.location.search.replace(/^\?/, "");
  const params = new URLSearchParams(raw);
  return { access: params.get("access"), refresh: params.get("refresh") };
}

export default function OAuthCallback() {
  const navigate = useNavigate();
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    const { access, refresh } = readParams();
    if (access && refresh) {
      done.current = true;
      completeOAuth(access, refresh);
      // Strip the credentials from the URL now that they are stored.
      window.history.replaceState({}, document.title, "/oauth/callback");
      navigate("/dashboard", { replace: true });
    } else {
      navigate("/login", { replace: true });
    }
  }, [navigate]);

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
