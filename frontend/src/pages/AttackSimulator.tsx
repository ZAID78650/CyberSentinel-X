import { useEffect, useState } from "react";
import { Activity, ArrowRight, Link2, Play, RadioTower, ShieldAlert, ShieldCheck, TrendingDown } from "lucide-react";
import { Link } from "react-router-dom";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, ProgressBar, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { AssetItem, AttackSimulation, LiveScenarioResult } from "../types";

const STAGES = [
  "Reconnaissance", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Lateral Movement", "Collection", "Exfiltration",
];

export default function AttackSimulator() {
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [assetId, setAssetId] = useState("");
  const [stage, setStage] = useState("Initial Access");
  const [sim, setSim] = useState<AttackSimulation | null>(null);
  const [live, setLive] = useState<LiveScenarioResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [liveRunning, setLiveRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get<{ items: AssetItem[] }>("/security/assets", { params: { page_size: 200 } });
        const list = res.data.items ?? [];
        setAssets(list);
        if (list.length > 0) setAssetId(list[0].name || list[0].id);
      } catch (err) {
        setError(getErrorMessage(err));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const run = async () => {
    if (!assetId) return;
    setRunning(true);
    setError(null);
    try {
      const res = await api.post<AttackSimulation>("/soc/simulate", {
        asset_id: assetId,
        starting_stage: stage,
        scenario: "generic",
      });
      setSim(res.data);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setRunning(false);
    }
  };

  const runLive = async () => {
    if (!assetId) return;
    setLiveRunning(true);
    setError(null);
    setLive(null);
    try {
      const res = await api.post<LiveScenarioResult>("/soc/simulate/run-live", {
        asset_id: assetId,
        starting_stage: stage,
        scenario: "generic",
      });
      setLive(res.data);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLiveRunning(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-40" />
        <Skeleton className="h-80" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <Card
        title="What-if Attack Simulator"
        subtitle="Project a deterministic kill-chain from an asset entry point — SIMULATION only, never a confirmed attack"
        actions={<ProvenanceBadge source="SIMULATED" />}
      >
        <div className="grid gap-4 lg:grid-cols-[1fr_1fr_auto]">
          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">Target asset</label>
            <select
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              className="w-full rounded-lg border border-night-700 bg-night-850 px-3 py-2 text-sm text-slate-200 outline-none focus:border-electric-500/60"
            >
              {assets.map((a) => (
                <option key={a.id} value={a.name || a.id}>{a.name} · {a.asset_type} · criticality {a.criticality}/10</option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">Starting stage</label>
            <select
              value={stage}
              onChange={(e) => setStage(e.target.value)}
              className="w-full rounded-lg border border-night-700 bg-night-850 px-3 py-2 text-sm text-slate-200 outline-none focus:border-electric-500/60"
            >
              {STAGES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={run}
              disabled={running || !assetId}
              className="flex items-center gap-2 rounded-lg bg-electric-500 px-5 py-2.5 text-sm font-bold text-night-950 transition hover:bg-electric-400 disabled:opacity-50"
            >
              <Play className="h-4 w-4" /> {running ? "Simulating…" : "Project risk"}
            </button>
          </div>
        </div>

        {/* Live replay */}
        <div className="mt-4 rounded-lg border border-cyber-yellow/25 bg-cyber-yellow/5 p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyber-yellow/15">
                <RadioTower className="h-5 w-5 text-cyber-yellow" />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-100">Run live scenario</p>
                <p className="text-[11px] text-slate-500">
                  Replays this kill chain as SIMULATED events through the real detection pipeline — watch detection, alert &amp; incident happen live
                </p>
              </div>
            </div>
            <button
              onClick={runLive}
              disabled={liveRunning || !assetId}
              className="flex shrink-0 items-center gap-2 rounded-lg border border-cyber-yellow/40 bg-cyber-yellow/10 px-5 py-2.5 text-sm font-bold text-cyber-yellow transition hover:bg-cyber-yellow/20 disabled:opacity-50"
            >
              <Activity className={`h-4 w-4 ${liveRunning ? "animate-pulse" : ""}`} />
              {liveRunning ? "Replaying through pipeline…" : "Run live scenario"}
            </button>
          </div>
        </div>

        {error && <div className="mt-3 rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>}
      </Card>

      {!sim && !live && !error && (
        <Card>
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" />}
            title="No simulation yet"
            description="Pick an asset and starting stage, then project the kill chain, or run it live through the detection pipeline."
          />
        </Card>
      )}

      {live && (
        <Card
          title="Live Replay Result"
          subtitle={`${live.asset.name} · starting at ${live.starting_stage} · ${live.events_ingested} SIMULATED events replayed through the real pipeline`}
          actions={<ProvenanceBadge source="SIMULATED" />}
        >
          {live.incident_id ? (
            <div className="flex flex-col gap-3 rounded-lg border border-cyber-green/30 bg-cyber-green/10 p-4 md:flex-row md:items-center md:justify-between">
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-6 w-6 text-cyber-green" />
                <div>
                  <p className="text-sm font-bold text-cyber-green">Attack detected &amp; correlated</p>
                  <p className="font-mono text-[11px] text-slate-400">
                    alert <span className="text-electric-400">{live.alert_id}</span> → incident <span className="text-electric-400">{live.incident_id}</span> · {live.anomalous_count}/{live.events_ingested} events anomalous
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {live.incident && (
                  <Link to={`/incidents/${live.incident}/war-room`} className="flex items-center gap-1.5 rounded-lg bg-cyber-green px-4 py-2 text-xs font-bold text-night-950 transition hover:brightness-110">
                    Open War Room <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                )}
                <Link to="/incidents" className="flex items-center gap-1.5 rounded-lg border border-night-600 px-4 py-2 text-xs font-bold text-slate-300 transition hover:bg-night-800">
                  <Link2 className="h-3.5 w-3.5" /> Incidents
                </Link>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-cyber-yellow/25 bg-cyber-yellow/5 p-4 text-xs text-cyber-yellow">
              Events replayed but nothing met the detection threshold — no alert triggered.
            </div>
          )}

          <div className="mt-4 space-y-1.5">
            {live.timeline.map((e, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 rounded-md border border-night-700/60 bg-night-850/40 px-3 py-2">
                <span className="w-24 shrink-0 truncate text-[10px] font-semibold uppercase tracking-wide text-slate-500">{e.stage ?? "—"}</span>
                <span className="w-40 shrink-0 font-mono text-[11px] font-bold text-slate-200">{e.event_type}</span>
                <SeverityBadge severity={e.severity} />
                {e.is_anomalous ? (
                  <span className="flex items-center gap-1 rounded bg-cyber-red/15 px-1.5 py-0.5 text-[9px] font-bold text-cyber-red"><Activity className="h-3 w-3" /> ANOMALY</span>
                ) : (
                  <span className="rounded bg-slate-500/10 px-1.5 py-0.5 text-[9px] font-bold text-slate-500">normal</span>
                )}
                <span className="ml-auto hidden truncate font-mono text-[10px] text-slate-600 md:inline">{e.reason ?? ""}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 rounded-lg border border-night-700 bg-night-850/60 p-3 text-[11px] leading-relaxed text-slate-400">{live.note}</p>
        </Card>
      )}

      {sim && (
        <>
          {/* Risk before/after */}
          <div className="grid gap-4 md:grid-cols-2">
            <Card title="Risk Before Mitigation" subtitle={`${sim.asset.name} · ${sim.asset.type} · criticality ${sim.asset.criticality}/10 · ${sim.incidents_on_asset} real incidents`}>
              <div className="flex items-center gap-4">
                <div className="relative h-28 w-28 shrink-0">
                  <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                    <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="10" />
                    <circle cx="50" cy="50" r="42" fill="none" stroke="#f87171" strokeWidth="10" strokeLinecap="round"
                      strokeDasharray={`${(sim.risk_before / 100) * 264} 264`} style={{ filter: "drop-shadow(0 0 6px #f87171)" }} />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="font-mono text-2xl font-bold text-cyber-red">{Math.round(sim.risk_before)}</span>
                    <span className="text-[9px] uppercase tracking-wider text-slate-500">/ 100</span>
                  </div>
                </div>
                <div className="flex-1 space-y-2">
                  <div className="flex justify-between text-xs"><span className="text-slate-500">Projected affected assets</span><span className="font-mono font-bold text-cyber-red">{sim.affected_assets_before}</span></div>
                  <ProgressBar value={sim.risk_before} color="#f87171" />
                  <p className="text-[10px] leading-relaxed text-slate-600">
                    Before applying the mitigation stack for {sim.kill_chain.length} exposed stages.
                  </p>
                </div>
              </div>
            </Card>
            <Card title="Risk After Mitigation" subtitle="With the full control stack applied per exposed stage">
              <div className="flex items-center gap-4">
                <div className="relative h-28 w-28 shrink-0">
                  <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                    <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="10" />
                    <circle cx="50" cy="50" r="42" fill="none" stroke="#4ade80" strokeWidth="10" strokeLinecap="round"
                      strokeDasharray={`${(sim.risk_after / 100) * 264} 264`} style={{ filter: "drop-shadow(0 0 6px #4ade80)" }} />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="font-mono text-2xl font-bold text-cyber-green">{Math.round(sim.risk_after)}</span>
                    <span className="text-[9px] uppercase tracking-wider text-slate-500">/ 100</span>
                  </div>
                </div>
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-2 text-xs">
                    <TrendingDown className="h-4 w-4 text-cyber-green" />
                    <span className="font-mono font-bold text-cyber-green">-{Math.round((1 - sim.risk_after / Math.max(sim.risk_before, 1)) * 100)}%</span>
                    <span className="text-slate-500">risk reduction</span>
                  </div>
                  <div className="flex justify-between text-xs"><span className="text-slate-500">Affected assets after</span><span className="font-mono font-bold text-cyber-green">{sim.affected_assets_after}</span></div>
                  <ProgressBar value={sim.risk_after} color="#4ade80" />
                </div>
              </div>
            </Card>
          </div>

          {/* Kill chain */}
          <Card title="Simulated Kill Chain" subtitle={`${sim.starting_stage} → up to 6 stages · deterministic probabilities`}>
            <div className="space-y-3">
              {sim.kill_chain.map((p, i) => (
                <div key={p.stage} className="rounded-lg border border-night-700/70 bg-night-850/50 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="flex h-7 w-7 items-center justify-center rounded-md bg-electric-500/10 font-mono text-xs font-bold text-electric-400">{i + 1}</span>
                      <div>
                        <p className="text-sm font-bold text-slate-100">{p.stage}</p>
                        <p className="text-[11px] text-slate-500">exposes: {p.exposure}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <StatusBadge status="SIMULATED" />
                      <span className="font-mono text-sm font-bold text-electric-400">{(p.probability * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                  <ProgressBar value={p.probability * 100} color="#38bdf8" className="mt-3" />
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {p.controls.map((c) => (
                      <span key={c} className="flex items-center gap-1 rounded bg-cyber-green/10 px-2 py-0.5 text-[10px] text-cyber-green">
                        <ShieldCheck className="h-3 w-3" /> {c}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-4 rounded-lg border border-cyber-yellow/20 bg-cyber-yellow/5 p-3 text-[11px] leading-relaxed text-cyber-yellow/90">{sim.note}</p>
          </Card>
        </>
      )}
    </div>
  );
}
