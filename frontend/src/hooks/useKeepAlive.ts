import { useEffect, useRef } from "react";

const PING_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Pings the backend health endpoint at regular intervals to prevent
 * Render free-tier services from spinning down due to inactivity.
 *
 * Only runs when the browser tab is visible (uses Page Visibility API).
 * Automatically stops when the component unmounts.
 */
export function useKeepAlive() {
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const ping = async () => {
      try {
        // Only ping if the tab is visible — don't waste resources on background tabs
        if (document.hidden) return;
        await fetch("/healthz", { method: "GET", cache: "no-store" });
      } catch {
        // Silently ignore — the point is just to keep the service alive
      }
    };

    // Start pinging
    intervalRef.current = setInterval(ping, PING_INTERVAL_MS);

    // Also ping immediately on mount
    void ping();

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);
}
