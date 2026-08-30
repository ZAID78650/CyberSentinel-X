import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { WS_URL } from "../config";
import { tokenStore, isDemoMode } from "../services/api";

export interface WsMessage {
  event: string;
  data: Record<string, unknown>;
}

interface WebSocketContextValue {
  connected: boolean;
  lastMessage: WsMessage | null;
  on: (event: string, handler: (data: Record<string, unknown>) => void) => () => void;
  send: (payload: Record<string, unknown>) => void;
}

const WebSocketContext = createContext<WebSocketContextValue | null>(null);

export function WebSocketProvider({ children }: { children: ReactNode }) {
  // Start as TRUE so the UI shows "ONLINE" immediately — all API calls already
  // have retry/warm-up logic, so showing "CONNECTING" only confuses users.
  const [connected, setConnected] = useState(true);
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const handlersRef = useRef<Map<string, Set<(data: Record<string, unknown>) => void>>>(new Map());
  const reconnectAttempt = useRef(0);
  const disposedRef = useRef(false);

  const on = useCallback((event: string, handler: (data: Record<string, unknown>) => void) => {
    if (!handlersRef.current.has(event)) handlersRef.current.set(event, new Set());
    handlersRef.current.get(event)!.add(handler);
    return () => handlersRef.current.get(event)?.delete(handler);
  }, []);

  const send = useCallback((payload: Record<string, unknown>) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(payload));
    }
  }, []);

  useEffect(() => {
    // In demo mode, don't try to connect — stay "connected" so UI looks good
    if (isDemoMode()) {
      setConnected(true);
      return;
    }

    disposedRef.current = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let healthTimer: ReturnType<typeof setInterval> | undefined;
    let failedAttempts = 0;
    let consecutiveHealthFailures = 0;

    // HTTP health poll — used when WebSocket fails (e.g. on Vercel)
    const pollHealth = async () => {
      if (disposedRef.current) return;
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        const res = await fetch("/health", { method: "GET", signal: controller.signal });
        clearTimeout(timeout);
        if (res.ok) {
          consecutiveHealthFailures = 0;
          setConnected(true);
        } else {
          consecutiveHealthFailures += 1;
          // Only go offline after 3 consecutive failures (avoids flapping on cold starts)
          if (consecutiveHealthFailures >= 3) setConnected(false);
        }
      } catch {
        consecutiveHealthFailures += 1;
        if (consecutiveHealthFailures >= 3) setConnected(false);
      }
    };

    const startHealthPoll = () => {
      if (healthTimer) return;
      // Don't immediately set disconnected — try health first
      pollHealth();
      healthTimer = setInterval(pollHealth, 30000);
    };

    const connect = () => {
      if (disposedRef.current) return;
      const token = tokenStore.getAccess();
      if (!token) { startHealthPoll(); return; }

      try {
        const url = `${WS_URL}?token=${encodeURIComponent(token)}`;
        const ws = new WebSocket(url);
        wsRef.current = ws;

        ws.onopen = () => {
          reconnectAttempt.current = 0;
          failedAttempts = 0;
          consecutiveHealthFailures = 0;
          setConnected(true);
          if (healthTimer) { clearInterval(healthTimer); healthTimer = undefined; }
        };
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data as string) as WsMessage;
            setLastMessage(msg);
            handlersRef.current.get(msg.event)?.forEach((h) => h(msg.data));
          } catch {
            // ignore malformed frames
          }
        };
        ws.onclose = () => {
          if (disposedRef.current) return;
          failedAttempts += 1;
          if (failedAttempts > 3) {
            // WebSocket not supported (e.g. Vercel) — fall back to HTTP health polling
            // But keep connected=true unless health checks fail 3x
            startHealthPoll();
            return;
          }
          const delay = Math.min(1000 * 2 ** reconnectAttempt.current, 10000);
          reconnectAttempt.current += 1;
          retryTimer = setTimeout(connect, delay);
        };
        ws.onerror = () => ws.close();
      } catch {
        // WebSocket constructor failed — fall back to health polling
        startHealthPoll();
      }
    };

    connect();
    return () => {
      disposedRef.current = true;
      if (retryTimer) clearTimeout(retryTimer);
      if (healthTimer) clearInterval(healthTimer);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  const value = useMemo(
    () => ({ connected, lastMessage, on, send }),
    [connected, lastMessage, on, send],
  );

  return (
    <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>
  );
}

export function useSocket(): WebSocketContextValue {
  const ctx = useContext(WebSocketContext);
  if (!ctx) throw new Error("useSocket must be used within WebSocketProvider");
  return ctx;
}
