import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowLeft, Boxes, Dna, GitBranch, Radar, Siren, Zap } from "lucide-react";
import { api } from "../services/api";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import { Card, EmptyState, SeverityBadge, Skeleton, StatCard } from "../components/ui";
import type { Campaign, CampaignsResponse } from "../types";

interface CampaignIntel {
  velocity: {
    band: string; attack_velocity: number; acceleration: number; stages_per_hour: number;
    campaign_escalation_detected: boolean; stage_times: Array<{ stage: string; minutes: number }>;
  };
  momentum: { momentum: number; status: string; signals: Array<{ signal: string; value: number; direction: string }> };
  mitre_coverage: { overall_coverage: number; per_tactic: Array<{ tactic: string; coverage: number; detected: number; expected: number }>; gaps: string[] };
}

interface SimilarItem { campaign_id: string; similarity: number; reasons: string[]; severity: string }
interface BusinessImpact { impact: string; critical_assets: number; critical_services: number; sensitive_data_stores: number; affected_users: number; affected_external: number }
interface MutationItem { campaign_id: string; behavioral_similarity: number; ioc_similarity: number; technique_similarity: number }
interface Dna { dna_id: string; fingerprint: string; family: string; confidence: number; severity: string; risk_score: number | null; behaviors: string[]; techniques: Array<{ technique_id?: string; name?: string }>; historical_similarity: number | null }
interface Prediction { current_stage: string; predicted_stage: string; probability: number; confidence: number; recommended_control: string | null; rationale: string | null; model_version: string }
interface BlastRadius { blast_radius: number; affected_assets: number; affected_users: number; path: Array<{ label: string }>; level: string }
interface Recommendation { id: string; action: string; impact: string; status: string; reason: string | null }
interface EvidenceItem { id: string; evidence_id: string; evidence_type: string; title: string; status: string; chain_index: number; record_hash: string; created_at: string }

const TABS = ["Overview", "Similarity", "Prediction", "Blast Radius", "Response", "Evidence & Blockchain"] as const;
type Tab = (typeof TABS)[number];

function sevColor(sev?: string | null) {
  return sev === "CRITICAL" ? "#f87171" : sev === "HIGH" ? "#fb923c" : sev === "MEDIUM" ? "#facc15" : "#4ade80";
}

export default function CampaignDetail() {
  const { id = "" } = useParams();
  const [tab, setTab] = useState<Tab>("Overview");

  const { data: listData, isLoading: loadingList } = useQuery({
    queryKey: ["campaigns-list"],
    queryFn: async () => (await api.get<CampaignsResponse>("/soc/campaigns?limit=100")).data,
  });
  const campaign: Campaign | undefined = listData?.campaigns.find((c) => c.campaign_id === id);
  const incidentId = campaign?.incidents[0];

  const intel = useQuery({
    queryKey: ["campaign-intel", id],
    queryFn: async () => (await api.get<CampaignIntel>(`/campaigns/${id}/intel`)).data,
    enabled: !!campaign,
  });
  const similar = useQuery({
    queryKey: ["campaign-similar", id],
    queryFn: async () => (await api.get<{ items: SimilarItem[] }>(`/campaigns/${id}/similar?limit=6`)).data,
    enabled: !!campaign,
  });
  const impact = useQuery({
    queryKey: ["campaign-impact", id],
    queryFn: async () => (await api.get<BusinessImpact>(`/campaigns/${id}/business-impact`)).data,
    enabled: !!campaign,
  });
  const mutation = useQuery({
    queryKey: ["campaign-mutation", id],
    queryFn: async () => (await api.get<{ items: MutationItem[] }>(`/campaigns/${id}/mutation`)).data,
    enabled: !!campaign,
  });
  const dna = useQuery({
    queryKey: ["campaign-dna", incidentId],
    queryFn: async () => (await api.get<Dna>(`/attack-dna/${incidentId}`)).data,
    enabled: !!incidentId,
  });
  const prediction = useQuery({
    queryKey: ["campaign-prediction", incidentId],
    queryFn: async () => (await api.get<Prediction>(`/predictions/${incidentId}`)).data,
    enabled: !!incidentId,
  });
  const blast = useQuery({
    queryKey: ["campaign-blast", incidentId],
    queryFn: async () => (await api.get<BlastRadius>(`/soc/blast-radius/${incidentId}`)).data,
    enabled: !!incidentId,
  });
  const responses = useQuery({
    queryKey: ["campaign-responses", incidentId],
    queryFn: async () => (await api.get<Recommendation[]>(`/response-recommendations/${incidentId}`)).data,
    enabled: !!incidentId,
  });
  const evidence = useQuery({
    queryKey: ["campaign-evidence", incidentId],
    queryFn: async () => (await api.get<{ items: EvidenceItem[]; total: number }>(`/evidence?incident_id=${incidentId}`)).data,
    enabled: !!incidentId,
  });

  if (loadingList && !campaign) {
    return <div className="space-y-4">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24" />)}</div>;
  }
  if (!campaign) {
    return (
      <EmptyState icon={<Siren className="h-8 w-8" />} title="Campaign not found"
        description="Open a campaign from the Campaigns page." />
    );
  }

  const v = intel.data?.velocity;
  const m = intel.data?.momentum;
  const mc = intel.data?.mitre_coverage;
  const velColor = v ? sevColor(v.band) : "#38bdf8";
  const momColor = m?.status === "ESCALATING" ? "#f87171" : m?.status === "STABLE" ? "#facc15" : "#4ade80";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Link to="/campaigns" className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300">
          <ArrowLeft className="h-3.5 w-3.5" /> Campaigns
        </Link>
        <h2 className="font-mono text-lg font-black text-slate-100">{campaign.campaign_id}</h2>
        <SeverityBadge severity={campaign.severity} />
        <span className="badge border border-night-700 text-slate-400">{campaign.category}</span>
        <ProvenanceBadge source="DATASET" />
        {v?.campaign_escalation_detected && (
          <span className="rounded bg-cyber-red/15 px-2 py-0.5 text-[10px] font-bold text-cyber-red">CAMPAIGN ESCALATION DETECTED</span>
        )}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Risk score" value={`${campaign.risk_score.toFixed(0)}/100`} color={sevColor(campaign.severity)} hint={`${campaign.event_count.toLocaleString()} events · ${campaign.incident_count} incidents`} />
        <StatCard label="Attack velocity" value={v ? `${v.band} · ${v.attack_velocity.toFixed(1)}` : "…"} color={velColor} hint={v ? `${v.stages_per_hour.toFixed(1)} stages/hr · accel ${v.acceleration.toFixed(2)}` : "computing"} />
        <StatCard label="Momentum" value={m ? `${m.momentum.toFixed(0)}/100` : "…"} color={momColor} hint={m ? `status ${m.status}` : "computing"} />
        <StatCard label="MITRE coverage" value={mc ? `${mc.overall_coverage.toFixed(0)}%` : "…"} color="#a78bfa" hint={`${(campaign.techniques ?? []).length} techniques mapped`} />
      </div>

      <div className="flex flex-wrap gap-1 border-b border-night-700/70">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`border-b-2 px-4 py-2.5 text-sm font-semibold ${tab === t ? "border-electric-500 text-electric-400" : "border-transparent text-slate-500 hover:text-slate-300"}`}>
            {t}
          </button>
        ))}
      </div>

      {tab === "Overview" && (
        <div className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Attack DNA" subtitle="Behavioral fingerprint of this campaign">
              {dna.isLoading && !dna.data ? <Skeleton className="h-40" /> : dna.data ? (
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Dna className="h-4 w-4 text-cyber-purple" />
                    <span className="font-mono text-sm font-bold text-cyber-purple">{dna.data.dna_id}</span>
                    <span className="badge border border-cyber-purple/40 bg-cyber-purple/10 text-cyber-purple">{dna.data.family}</span>
                    <span className="badge border border-night-700 text-slate-400">confidence {(dna.data.confidence * 100).toFixed(0)}%</span>
                  </div>
                  <p className="mt-3 font-mono text-xs text-slate-500">fingerprint {dna.data.fingerprint}</p>
                  {dna.data.historical_similarity !== null && (
                    <p className="mt-1 text-xs text-slate-400">historical similarity {(dna.data.historical_similarity * 100).toFixed(0)}%</p>
                  )}
                  <div className="mt-3 flex flex-wrap gap-1">
                    {dna.data.behaviors.slice(0, 8).map((b) => (
                      <span key={b} className="rounded bg-night-850/70 px-1.5 py-0.5 text-[10px] text-slate-400">{b}</span>
                    ))}
                  </div>
                </div>
              ) : <EmptyState icon={<Dna className="h-6 w-6" />} title="No DNA generated yet" />}
            </Card>
            <Card title="Business impact" subtitle="Qualitative impact from critical assets, data stores and affected users">
              {impact.data ? (
                <div className="grid grid-cols-2 gap-3">
                  <StatCard label="Impact" value={impact.data.impact} color={sevColor(impact.data.impact)} />
                  <StatCard label="Critical assets" value={impact.data.critical_assets} color="#f87171" />
                  <StatCard label="Critical services" value={impact.data.critical_services} color="#fb923c" />
                  <StatCard label="Sensitive data stores" value={impact.data.sensitive_data_stores} color="#facc15" />
                  <StatCard label="Affected users" value={impact.data.affected_users} color="#a78bfa" />
                  <StatCard label="External endpoints" value={impact.data.affected_external} color="#38bdf8" />
                </div>
              ) : <Skeleton className="h-40" />}
            </Card>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Momentum signals" subtitle="What is driving the momentum score">
              {m ? (
                <div className="space-y-2">
                  {m.signals.map((s) => (
                    <div key={s.signal} className="flex items-center justify-between rounded-lg border border-night-700 bg-night-850/60 px-3 py-2 text-xs">
                      <span className="text-slate-300">{s.signal}</span>
                      <span className={`font-mono ${s.direction === "up" ? "text-cyber-red" : s.direction === "down" ? "text-cyber-green" : "text-slate-400"}`}>
                        {s.direction === "up" ? "+" : ""}{s.value.toFixed(1)}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <Skeleton className="h-40" />}
            </Card>
            <Card title="Mutation watch" subtitle="Campaigns with similar behavior but diverging IOCs">
              {mutation.data && mutation.data.items.length > 0 ? (
                <div className="space-y-2">
                  {mutation.data.items.map((mu) => (
                    <div key={mu.campaign_id} className="rounded-lg border border-cyber-red/30 bg-cyber-red/5 p-3 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-cyber-red">{mu.campaign_id}</span>
                        <span className="badge border border-cyber-red/40 bg-cyber-red/10 text-cyber-red">POSSIBLE MUTATION</span>
                      </div>
                      <p className="mt-1.5 text-slate-400">
                        behavioral {(mu.behavioral_similarity * 100).toFixed(0)}% · IOC {(mu.ioc_similarity * 100).toFixed(0)}% · technique {(mu.technique_similarity * 100).toFixed(0)}%
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500">No behavioral look-alikes with divergent IOCs detected.</p>
              )}
            </Card>
          </div>

          {v && (
            <Card title="Attack timeline" subtitle="Kill-chain stage transition times (attack velocity engine)">
              <div className="space-y-1.5">
                {v.stage_times.map((s) => (
                  <div key={s.stage} className="flex items-center gap-3 text-xs">
                    <span className="w-40 shrink-0 text-slate-300">{s.stage}</span>
                    <div className="h-1.5 flex-1 rounded bg-night-800">
                      <div className="h-1.5 rounded" style={{ width: `${Math.min(100, Math.max(4, (s.minutes / Math.max(v.stage_times[0]?.minutes ?? 1, 1)) * 100))}%`, background: velColor }} />
                    </div>
                    <span className="w-16 shrink-0 text-right font-mono text-slate-400">{s.minutes.toFixed(1)}m</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}

      {tab === "Similarity" && (
        <Card title="Similar campaigns" subtitle="Ranked by explainable feature similarity (Jaccard + cosine, with reasons)">
          {similar.isLoading && !similar.data ? <Skeleton className="h-48" /> : !similar.data || similar.data.items.length === 0 ? (
            <EmptyState icon={<GitBranch className="h-8 w-8" />} title="No similar campaigns" description="Needs more than one campaign with overlapping features." />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {similar.data.items.map((s) => (
                <div key={s.campaign_id} className="rounded-lg border border-night-700 bg-night-850/60 p-4">
                  <div className="flex items-center justify-between">
                    <Link to={`/campaigns/${s.campaign_id}`} className="font-mono text-sm font-bold text-electric-400 hover:underline">{s.campaign_id}</Link>
                    <span className="font-mono text-lg font-black" style={{ color: sevColor(s.severity) }}>{(s.similarity * 100).toFixed(0)}%</span>
                  </div>
                  <div className="mt-2 space-y-1">
                    {s.reasons.slice(0, 4).map((r) => (
                      <p key={r} className="text-[11px] text-slate-400">· {r}</p>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {tab === "Prediction" && (
        <Card title="Attack progression prediction" subtitle="Markov transition model — always labeled MODEL PREDICTION">
          {prediction.isLoading && !prediction.data ? <Skeleton className="h-48" /> : prediction.data ? (
            <div className="grid gap-6 md:grid-cols-[1fr_auto_1fr]">
              <div className="rounded-lg border border-night-700 bg-night-850/60 p-5 text-center">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">current stage</p>
                <p className="mt-2 text-lg font-bold text-slate-200">{prediction.data.current_stage}</p>
              </div>
              <div className="flex flex-col items-center justify-center">
                <Radar className="h-6 w-6 text-cyber-purple" />
                <p className="mt-1 font-mono text-2xl font-black text-cyber-purple">{(prediction.data.probability * 100).toFixed(0)}%</p>
                <p className="text-[10px] text-slate-500">confidence {(prediction.data.confidence * 100).toFixed(0)}%</p>
              </div>
              <div className="rounded-lg border border-cyber-purple/40 bg-cyber-purple/5 p-5 text-center">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">predicted next</p>
                <p className="mt-2 text-lg font-bold text-cyber-purple">{prediction.data.predicted_stage}</p>
              </div>
              {prediction.data.recommended_control && (
                <div className="md:col-span-3 rounded-lg border border-night-700 bg-night-850/60 p-3 text-xs text-slate-400">
                  <b className="text-slate-200">Recommended control:</b> {prediction.data.recommended_control}
                  {prediction.data.rationale && <span className="block mt-1">{prediction.data.rationale}</span>}
                  <span className="mt-1 block text-[10px] text-slate-600">model {prediction.data.model_version} · not verified accuracy</span>
                </div>
              )}
            </div>
          ) : <EmptyState icon={<Radar className="h-8 w-8" />} title="No prediction generated" />}
        </Card>
      )}

      {tab === "Blast Radius" && (
        <Card title="Blast radius" subtitle="Attack-graph reachability from this campaign's incident">
          {blast.isLoading && !blast.data ? <Skeleton className="h-48" /> : blast.data ? (
            <div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <StatCard label="Blast radius" value={`${blast.data.blast_radius}/100`} color={sevColor(blast.data.level)} hint={blast.data.level} />
                <StatCard label="Affected assets" value={blast.data.affected_assets} color="#f87171" />
                <StatCard label="Affected users" value={blast.data.affected_users} color="#fb923c" />
              </div>
              <div className="mt-4">
                <p className="mb-2 text-[10px] uppercase tracking-wider text-slate-500">attack path</p>
                <div className="flex flex-wrap items-center gap-1.5">
                  {(blast.data.path ?? []).map((p, i) => (
                    <span key={i} className="flex items-center gap-1.5">
                      <span className="rounded border border-night-700 bg-night-850/70 px-2 py-1 font-mono text-[11px] text-slate-300">{p.label}</span>
                      {i < (blast.data.path ?? []).length - 1 && <span className="text-slate-600">→</span>}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : <EmptyState icon={<GitBranch className="h-8 w-8" />} title="No blast radius computed" />}
        </Card>
      )}

      {tab === "Response" && (
        <Card title="Response recommendations" subtitle="Human-in-the-loop — nothing executes without approval">
          {responses.isLoading && !responses.data ? <Skeleton className="h-48" /> : !responses.data || responses.data.length === 0 ? (
            <EmptyState icon={<Zap className="h-8 w-8" />} title="No recommendations" />
          ) : (
            <div className="space-y-2">
              {responses.data.map((r) => (
                <div key={r.id} className="flex items-center justify-between rounded-lg border border-night-700 bg-night-850/60 px-4 py-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-200">{r.action}</p>
                    {r.reason && <p className="mt-0.5 text-xs text-slate-500">{r.reason}</p>}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`badge border ${r.impact === "HIGH" ? "border-cyber-red/40 bg-cyber-red/10 text-cyber-red" : r.impact === "MEDIUM" ? "border-cyber-yellow/40 bg-cyber-yellow/10 text-cyber-yellow" : "border-cyber-green/40 bg-cyber-green/10 text-cyber-green"}`}>impact {r.impact}</span>
                    <span className="badge border border-night-700 text-slate-400">{r.status}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {tab === "Evidence & Blockchain" && (
        <Card title="Forensic evidence" subtitle="Tamper-evident chain of custody — hashes, Merkle roots, verification">
          {evidence.isLoading && !evidence.data ? <Skeleton className="h-48" /> : !evidence.data || evidence.data.items.length === 0 ? (
            <EmptyState icon={<Boxes className="h-8 w-8" />} title="No evidence for this campaign" description="Evidence is generated by the Evidence Agent during investigation." />
          ) : (
            <div className="space-y-2">
              {evidence.data.items.map((e) => (
                <div key={e.id} className="rounded-lg border border-night-700 bg-night-850/60 px-4 py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Boxes className="h-4 w-4 text-electric-400" />
                      <span className="font-mono text-xs font-bold text-electric-400">{e.evidence_id}</span>
                      <span className="badge border border-night-700 text-slate-500">{e.evidence_type}</span>
                      <span className={`badge border ${e.status === "VALID" ? "border-cyber-green/40 bg-cyber-green/10 text-cyber-green" : "border-cyber-red/40 bg-cyber-red/10 text-cyber-red"}`}>{e.status}</span>
                    </div>
                    <span className="font-mono text-[10px] text-slate-600">#{e.chain_index} · {e.record_hash.slice(0, 16)}…</span>
                  </div>
                  <p className="mt-1.5 text-sm text-slate-300">{e.title}</p>
                </div>
              ))}
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-night-700 bg-night-850/60 p-3 text-[11px] text-slate-500">
                <Activity className="mt-0.5 h-4 w-4 shrink-0 text-cyber-green" />
                <span>Evidence → SHA-256 hash → Merkle root → mined ledger block. Verification recomputes every hash; any edit flips status to TAMPERED. Full chain audit on the Evidence Ledger page.</span>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
