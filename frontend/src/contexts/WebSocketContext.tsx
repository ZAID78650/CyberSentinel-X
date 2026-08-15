import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { WS_URL } from "../config";
import { tokenStore } from "../services/api";

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
    disposedRef.current = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      if (disposedRef.current) return;
      const token = tokenStore.getAccess();
      if (!token) return;
      const url = `${WS_URL}?token=${encodeURIComponent(token)}`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttempt.current = 0;
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

  return (
    <WebSocketContext.Provider value={{ connected, lastMessage, on, send }}>{children}</WebSocketContext.Provider>
  );
}

export function useSocket(): WebSocketContextValue {
  const ctx = useContext(WebSocketContext);
  if (!ctx) throw new Error("useSocket must be used within WebSocketProvider");
  return ctx;
}
