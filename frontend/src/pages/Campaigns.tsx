import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, Radar, Siren, Target, TrendingUp } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import { useWebSocket } from "../hooks/useWebSocket";

interface CommandRow {
  campaign_id: string;
  category: string;
  severity: string;
  risk_score: number;
  confidence: number;
  event_count: number;
  incident_count: number;
  asset_count: number;
  techniques: string[];
  status: string;
  momentum: number;
  momentum_status: string;
  velocity: number;
  velocity_band: string;
  escalation_detected: boolean;
  prediction: { current_stage: string; predicted_stage: string; probability: number } | null;
}

interface CommandCenter {
  summary: { active: number; critical: number; escalating: number; predicted: number; contained: number; total: number };
  campaigns: CommandRow[];
  funnel: { events: number; alerts: number; incidents: number; campaigns: number; dedup_ratio: number };
  note: string;
}

function sevColor(sev: string) {
  return sev === "CRITICAL" ? "#f87171" : sev === "HIGH" ? "#fb923c" : sev === "MEDIUM" ? "#facc15" : "#4ade80";
}

function SummaryCard({ label, value, color, icon }: { label: string; value: number; color: string; icon: React.ReactNode }) {
  return (
    <div className="glass glass-hover relative overflow-hidden p-4">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: color, boxShadow: `0 0 12px ${color}` }} />
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
        <span style={{ color }}>{icon}</span>
      </div>
      <p className="mt-1.5 font-mono text-3xl font-black" style={{ color }}>{value}</p>
    </div>
  );
}

export default function Campaigns() {
  const navigate = useNavigate();
  const { on } = useWebSocket();
  const [data, setData] = useState<CommandCenter | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const res = await api.get<CommandCenter>("/campaigns/command-center?limit=50");
      setData(res.data);
      setError(null);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    // Live: refetch when the detection pipeline produces new correlated state.
    const unsubs = ["new_alert", "new_incident", "incident_updated", "analyst_feedback"].map((ev) =>
      on(ev, () => void load())
    );
    return () => unsubs.forEach((u) => u());
  }, [on]);

  if (loading && !data) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  const s = data?.summary;
  const funnel = data?.funnel;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-bold text-slate-100">Campaign Command Center</h2>
        <ProvenanceBadge source="DATASET" />
        <span className="badge border border-night-700 text-slate-500">live updates via WebSocket</span>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <SummaryCard label="Active campaigns" value={s?.active ?? 0} color="#38bdf8" icon={<Radar className="h-4 w-4" />} />
        <SummaryCard label="Critical campaigns" value={s?.critical ?? 0} color="#f87171" icon={<Siren className="h-4 w-4" />} />
        <SummaryCard label="Escalating campaigns" value={s?.escalating ?? 0} color="#fb923c" icon={<TrendingUp className="h-4 w-4" />} />
        <SummaryCard label="Predicted campaigns" value={s?.predicted ?? 0} color="#c084fc" icon={<Target className="h-4 w-4" />} />
        <SummaryCard label="Campaigns contained" value={s?.contained ?? 0} color="#4ade80" icon={<Activity className="h-4 w-4" />} />
      </div>

      <Card
        title={`Attack Campaigns (${data?.campaigns.length ?? 0})`}
        subtitle={`${funnel?.events ?? 0} events → ${funnel?.alerts ?? 0} alerts → ${funnel?.incidents ?? 0} incidents → ${funnel?.campaigns ?? 0} campaigns (dedup ratio ${funnel?.dedup_ratio ?? 0})`}
        actions={<ProvenanceBadge source="DATASET" />}
      >
        {error && <div className="mb-3 rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>}
        {!data || data.campaigns.length === 0 ? (
          <EmptyState icon={<Target className="h-8 w-8" />} title="No campaigns detected yet"
            description="Campaigns appear once incidents share source IPs and attack categories." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Campaign</th><th>Attack family</th><th>Severity</th><th>Risk</th><th>Confidence</th>
                  <th>Events</th><th>Assets</th><th>Techniques</th><th>Momentum</th><th>Velocity</th>
                  <th>Prediction</th><th>Status</th>
                </tr>
              </thead>
              <tbody>
                {data.campaigns.map((c) => (
                  <tr key={c.campaign_id} className="cursor-pointer hover:bg-night-850/60" onClick={() => navigate(`/campaigns/${c.campaign_id}`)}>
                    <td className="font-mono text-xs font-bold text-electric-400">{c.campaign_id}</td>
                    <td className="max-w-[180px] truncate text-xs text-slate-200">{c.category}</td>
                    <td><SeverityBadge severity={c.severity} /></td>
                    <td className="font-mono text-xs" style={{ color: sevColor(c.severity) }}>{c.risk_score.toFixed(0)}</td>
                    <td className="font-mono text-xs text-slate-400">{(c.confidence * 100).toFixed(0)}%</td>
                    <td className="font-mono text-xs text-slate-400">{c.event_count.toLocaleString()}</td>
                    <td className="font-mono text-xs text-slate-400">{c.asset_count}</td>
                    <td>
                      <div className="flex max-w-[180px] flex-wrap gap-1">
                        {c.techniques.slice(0, 3).map((t) => (
                          <span key={t} className="rounded bg-cyber-purple/10 px-1.5 py-0.5 font-mono text-[9px] text-cyber-purple">{t}</span>
                        ))}
                        {c.techniques.length > 3 && <span className="text-[9px] text-slate-600">+{c.techniques.length - 3}</span>}
                      </div>
                    </td>
                    <td>
                      <span className={`font-mono text-xs font-bold ${c.momentum_status === "ESCALATING" ? "text-cyber-red" : c.momentum_status === "STABLE" ? "text-cyber-yellow" : "text-cyber-green"}`}>
                        {c.momentum.toFixed(0)}
                      </span>
                      {c.escalation_detected && <span className="ml-1 rounded bg-cyber-red/15 px-1 py-0.5 text-[8px] font-bold text-cyber-red">ESC</span>}
                    </td>
                    <td><span className="badge border border-night-700 text-slate-300">{c.velocity_band}</span></td>
                    <td className="max-w-[150px] text-xs text-slate-400">
                      {c.prediction ? (
                        <>
                          <span className="text-cyber-purple">{c.prediction.predicted_stage}</span>
                          <span className="text-slate-600"> · {(c.prediction.probability * 100).toFixed(0)}%</span>
                        </>
                      ) : <span className="text-slate-600">—</span>}
                    </td>
                    <td><StatusBadge status={c.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data?.note && <p className="mt-4 rounded-lg border border-night-700 bg-night-850/60 p-3 text-[11px] leading-relaxed text-slate-400">{data.note}</p>}
      </Card>
    </div>
  );
}
