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
  const [connected, setConnected] = useState(false);
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
    // In demo mode, don't try to connect — just stay disconnected
    if (isDemoMode()) {
      setConnected(false);
      return;
    }

    disposedRef.current = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let failedAttempts = 0;

    const connect = () => {
      if (disposedRef.current) return;
      const token = tokenStore.getAccess();
      if (!token) return;
      const url = `${WS_URL}?token=${encodeURIComponent(token)}`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttempt.current = 0;
        failedAttempts = 0;
        setConnected(true);
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
        setConnected(false);
        if (disposedRef.current) return;
        failedAttempts += 1;
        // Stop reconnecting after 5 failed attempts to avoid infinite loop
        if (failedAttempts > 5) return;
        const delay = Math.min(1000 * 2 ** reconnectAttempt.current, 15000);
        reconnectAttempt.current += 1;
        retryTimer = setTimeout(connect, delay);
      };
      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      disposedRef.current = true;
      if (retryTimer) clearTimeout(retryTimer);
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
