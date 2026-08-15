import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";

type ToastKind = "success" | "error" | "info" | "warning";

interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  description?: string;
}

interface ToastContextValue {
  toast: (kind: ToastKind, title: string, description?: string) => void;
  success: (title: string, description?: string) => void;
  error: (title: string, description?: string) => void;
  info: (title: string, description?: string) => void;
  warning: (title: string, description?: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const ICONS: Record<ToastKind, ReactNode> = {
  success: <CheckCircle2 className="h-4 w-4 text-cyber-green" />,
  error: <XCircle className="h-4 w-4 text-cyber-red" />,
  info: <Info className="h-4 w-4 text-electric-400" />,
  warning: <AlertTriangle className="h-4 w-4 text-cyber-yellow" />,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(
    (kind: ToastKind, title: string, description?: string) => {
      const id = Date.now() + Math.random();
      setToasts((prev) => [...prev.slice(-4), { id, kind, title, description }]);
      setTimeout(() => remove(id), 5000);
    },
    [remove],
  );

  const value = useMemo<ToastContextValue>(
    () => ({
      toast,
      success: (t, d) => toast("success", t, d),
      error: (t, d) => toast("error", t, d),
      info: (t, d) => toast("info", t, d),
      warning: (t, d) => toast("warning", t, d),
    }),
    [toast],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[100] flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="glass pointer-events-auto flex items-start gap-3 px-4 py-3 animate-in"
            style={{ animation: "slideIn 0.2s ease-out" }}
          >
            <div className="mt-0.5 shrink-0">{ICONS[t.kind]}</div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-slate-100">{t.title}</p>
              {t.description && <p className="mt-0.5 text-xs text-slate-400">{t.description}</p>}
            </div>
            <button onClick={() => remove(t.id)} className="text-slate-500 hover:text-slate-200">
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
      <style>{`@keyframes slideIn { from { opacity: 0; transform: translateX(16px); } to { opacity: 1; transform: none; } }`}</style>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
