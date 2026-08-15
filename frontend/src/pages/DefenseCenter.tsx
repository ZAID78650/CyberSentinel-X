import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, ShieldCheck, ShieldAlert, Lock, Ban, Radar, Flame, Activity, Bug, Loader2 } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, ProgressBar, Skeleton } from "../components/ui";
import type { FirewallLayer, FirewallSummary } from "../types";

const LAYER_ICONS: Record<string, React.ReactNode> = {
  REQUEST_ID: <Activity className="h-4 w-4" />,
  BODY_LIMIT: <Ban className="h-4 w-4" />,
  WAF_PAYLOAD: <Flame className="h-4 w-4" />,
  SECURITY_HDR: <ShieldCheck className="h-4 w-4" />,
  RATE_LIMIT: <Lock className="h-4 w-4" />,
  IP_WATCH: <Radar className="h-4 w-4" />,
  MALWARE_GUARD: <Bug className="h-4 w-4" />,
  BRUTE_GUARD: <Shield className="h-4 w-4" />,
};

export default function DefenseCenter() {
  const { data, isLoading } = useQuery({
    queryKey: ["firewall"],
    queryFn: async () => (await api.get<FirewallSummary>("/security/firewall")).data,
  });
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const testMalwareGuard = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      // Send a payload that references a known malware hash (EICAR). The
      // MALWARE_GUARD middleware intercepts it and returns 403 before the
      // route runs — that 403 IS the demonstration.
      const res = await api.post("/security/firewall/test-malware", { note: "firewall test", hash: "44d88612fea8a8f36de82e1278abb02f" });
      setTestResult(`No block: ${(res.data as { hint?: string }).hint ?? "request passed through"}`);
    } catch (err) {
      const resp = (err as { response?: { status?: number; data?: { detail?: string } } }).response;
      if (resp && resp.status === 403) {
        setTestResult(`Blocked — HTTP 403: ${resp.data?.detail ?? "Request references known malware indicator"}`);
      } else {
        setTestResult(`Request failed: ${getErrorMessage(err)}`);
      }
    } finally {
      setTesting(false);
    }
  };

  if (isLoading || !data) {
    return <div className="grid gap-4 md:grid-cols-2"><Skeleton className="h-40" /><Skeleton className="h-40" /><Skeleton className="h-64 md:col-span-2" /></div>;
  }

  const maxBlocked = Math.max(1, ...data.layers.map((l) => l.blocked));
  const active = data.layers.filter((l) => l.status === "ACTIVE").length;

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyber-cyan/10 text-cyber-cyan">
          <Shield className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-slate-100">Defense Center</h2>
          <p className="text-xs text-slate-500">Defense-in-depth firewall · {data.protection_level}</p>
        </div>
        <button className="btn-primary ml-auto" onClick={testMalwareGuard} disabled={testing}>
          {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bug className="h-4 w-4" />}
          Test malware guard
        </button>
      </div>

      {testResult && (
        <div className={`flex items-start gap-2 rounded-lg border p-3 text-xs ${testResult.startsWith("Blocked") ? "border-cyber-red/40 bg-cyber-red/10 text-cyber-red" : "border-night-700 bg-night-850/60 text-slate-300"}`}>
          <ShieldAlert className={`mt-0.5 h-4 w-4 shrink-0 ${testResult.startsWith("Blocked") ? "text-cyber-red" : "text-slate-500"}`} />
          <span>{testResult}</span>
        </div>
      )}

      {/* Protection overview */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[
          { label: "Active Layers", value: `${active}/${data.layers.length}`, color: "#4ade80" },
          { label: "Requests Inspected", value: data.total_requests.toLocaleString(), color: "#38bdf8" },
          { label: "Threats Blocked", value: data.total_blocked.toLocaleString(), color: "#f87171" },
          { label: "Protection Level", value: "DEFENSE-IN-DEPTH", color: "#a78bfa" },
        ].map((k) => (
          <div key={k.label} className="glass glass-hover p-4">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{k.label}</p>
            <p className="mt-1 font-mono text-2xl font-bold" style={{ color: k.color }}>{k.value}</p>
          </div>
        ))}
      </div>

      {/* Layered stack */}
      <Card title="Firewall Layers" subtitle="Every request passes through this stack">
        <div className="space-y-3">
          {data.layers.map((layer: FirewallLayer, idx: number) => (
            <div key={layer.layer} className="flex items-center gap-4 rounded-lg border border-night-700/60 bg-night-850/40 px-4 py-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-md" style={{ background: `${layer.color}18`, color: layer.color }}>
                {LAYER_ICONS[layer.layer] ?? <Shield className="h-4 w-4" />}
              </div>
              <div className="w-10 text-center font-mono text-xs text-slate-600">{idx + 1}</div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-semibold text-slate-200">{layer.name}</p>
                  <span className="badge border border-cyber-green/30 bg-cyber-green/10 text-[10px] text-cyber-green">
                    {layer.status}
                  </span>
                </div>
                <p className="mt-0.5 truncate text-xs text-slate-500">{layer.description}</p>
                <div className="mt-2 flex items-center gap-3">
                  <ProgressBar value={(layer.blocked / maxBlocked) * 100} color={layer.color} className="max-w-xs" />
                  <span className="text-[11px] text-slate-500">
                    <span className="font-mono text-cyber-red">{layer.blocked}</span> blocked ·{" "}
                    <span className="font-mono text-cyber-green">{layer.passed}</span> passed
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
