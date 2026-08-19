import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, ShieldCheck } from "lucide-react";
import { api, tokenStore } from "../services/api";

function readParams(): { access: string | null; refresh: string | null; linked: string | null } {
  // Tokens arrive in the URL fragment (#access=...&refresh=...) so they never
  // hit server/referrer logs. Fall back to the query string for older links.
  const raw = window.location.hash.replace(/^#/, "") || window.location.search.replace(/^\?/, "");
  const params = new URLSearchParams(raw);
  return { access: params.get("access"), refresh: params.get("refresh"), linked: params.get("linked") };
}

export default function OAuthCallback() {
  const navigate = useNavigate();
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    const { access, refresh, linked } = readParams();
    
    if (linked) {
      done.current = true;
      window.history.replaceState({}, document.title, "/oauth/callback");
      window.dispatchEvent(new CustomEvent("auth:oauth")); 
      navigate("/settings", { replace: true });
      return;
    } 
    
    if (access && refresh) {
      done.current = true;
      
      // 1. Store tokens immediately
      tokenStore.set({ 
        access_token: access, 
        refresh_token: refresh, 
        token_type: "bearer", 
        expires_in: 7 * 24 * 60 * 60 
      });
      
      // 2. Clean the URL
      window.history.replaceState({}, document.title, "/oauth/callback");
      
      // 3. Directly fetch the user to guarantee it exists before doing ANYTHING else
      api.get("/auth/me")
        .then((res) => {
          // 4. Force save the user to localStorage so next render sees it
          tokenStore.setUser(res.data);
          
          // 5. Force a hard navigation to the dashboard to completely reset React state
          window.location.href = "/dashboard";
        })
        .catch((err) => {
          console.error("Failed to fetch profile during OAuth callback:", err);
          setErrorMsg("Failed to load your user profile from the server. Please try logging in again.");
          setTimeout(() => navigate("/login", { replace: true }), 3000);
        });
    } else {
      // If we landed here without access/refresh tokens in the URL fragment
      const searchParams = new URLSearchParams(window.location.search);
      const errorParam = searchParams.get("error");
      if (errorParam) {
        setErrorMsg(`Authentication provider returned an error: ${errorParam}`);
      } else {
        setErrorMsg("Missing authentication tokens in the URL.");
      }
      setTimeout(() => navigate("/login", { replace: true }), 3000);
    }
  }, [navigate]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-night-950 px-4 text-center">
      <div className="relative">
        <div className="absolute inset-0 -z-10 scale-150 rounded-full bg-electric-500/20 blur-2xl" />
        <ShieldCheck className="h-16 w-16 text-electric-400" />
      </div>
      
      {errorMsg ? (
        <div className="mt-4 flex flex-col items-center gap-2">
          <p className="text-red-400 font-medium">{errorMsg}</p>
          <p className="text-sm text-slate-400">Redirecting to login...</p>
        </div>
      ) : (
        <>
          <Loader2 className="h-5 w-5 animate-spin text-electric-400" />
          <p className="text-sm text-slate-400">Completing secure sign-in…</p>
        </>
      )}
    </div>
  );
}
