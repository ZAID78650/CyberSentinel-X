import { useEffect, useState } from "react";
import { Link2, Radar, Target } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, Skeleton } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import type { Campaign, CampaignsResponse } from "../types";

function shortId(s: string): string {
  return s.length > 12 ? `${s.slice(0, 12)}…` : s;
}

interface CampaignIntel {
  velocity: { band: string; attack_velocity: number; campaign_escalation_detected: boolean };
  momentum: { momentum: number; status: string };
  mitre_coverage: { overall_coverage: number };
}

function useCampaignIntel(campaignId: string): CampaignIntel | null {
  const [intel, setIntel] = useState<CampaignIntel | null>(null);
  useEffect(() => {
    let alive = true;
    api.get<CampaignIntel>(`/campaigns/${campaignId}/intel`)
      .then((res) => { if (alive) setIntel(res.data); })
      .catch(() => { if (alive) setIntel(null); });
    return () => { alive = false; };
  }, [campaignId]);
  return intel;
}

const VELOCITY_COLORS: Record<string, string> = {
  LOW: "#4ade80", MEDIUM: "#facc15", HIGH: "#fb923c", CRITICAL: "#f87171",
};

function IntelBadge({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <span className="flex items-center gap-1 rounded bg-night-850/70 px-1.5 py-0.5 text-[9px] text-slate-400">
      <span className="uppercase tracking-wide text-slate-600">{label}</span>
      <b style={{ color }}>{value}</b>
    </span>
  );
}

export default function Campaigns() {
  const [data, setData] = useState<CampaignsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get<CampaignsResponse>("/soc/campaigns?limit=50");
        setData(res.data);
      } catch (err) {
        setError(getErrorMessage(err));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  const funnel = data?.funnel;

  return (
    <div className="space-y-5">
      {/* Funnel */}
      <Card
        title="Alert Fatigue Funnel"
        subtitle="How correlation collapses raw events into a manageable incident list"
        actions={<ProvenanceBadge source="DATASET" />}
      >
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          <FunnelBox label="Events" value={funnel?.events ?? 0} color="#38bdf8" />
          <FunnelBox label="Alerts" value={funnel?.alerts ?? 0} color="#a78bfa" />
          <FunnelBox label="Incidents" value={funnel?.incidents ?? 0} color="#facc15" />
          <FunnelBox label="Campaigns" value={funnel?.campaigns ?? 0} color="#4ade80" />
          <FunnelBox label="Dedup ratio" value={funnel?.dedup_ratio ?? 0} color="#f87171" hint="events per alert" />
        </div>
        <p className="mt-4 rounded-lg border border-night-700 bg-night-850/60 p-3 text-[11px] leading-relaxed text-slate-400">
          {data?.note}
        </p>
      </Card>

      {/* Campaign list */}
      <Card title="Attack Campaigns" subtitle={`${data?.campaigns.length ?? 0} campaigns grouped by source + attack category`}>
        {error && <div className="mb-3 rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>}
        {!data || data.campaigns.length === 0 ? (
          <EmptyState icon={<Target className="h-8 w-8" />} title="No campaigns detected yet"
            description="Campaigns appear once incidents share source IPs and attack categories." />
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {data.campaigns.map((c) => (
              <CampaignCard key={c.campaign_id} c={c} />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function FunnelBox({ label, value, color, hint }: { label: string; value: number; color: string; hint?: string }) {
  return (
    <div className="glass glass-hover relative overflow-hidden p-4 text-center">
      <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: color, boxShadow: `0 0 12px ${color}` }} />
      <p className="font-mono text-2xl font-bold" style={{ color }}>{typeof value === "number" ? value.toLocaleString() : value}</p>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
      {hint && <p className="mt-0.5 text-[9px] text-slate-600">{hint}</p>}
    </div>
  );
}

function CampaignCard({ c }: { c: Campaign }) {
  const navigate = useNavigate();
  const sevColor = c.severity === "CRITICAL" ? "#f87171" : c.severity === "HIGH" ? "#fb923c" : c.severity === "MEDIUM" ? "#facc15" : "#4ade80";
  const intel = useCampaignIntel(c.campaign_id);
  const momentumStatusColor =
    intel?.momentum.status === "ESCALATING" ? "#f87171" : intel?.momentum.status === "STABLE" ? "#facc15" : "#4ade80";
  return (
    <div className="glass glass-hover cursor-pointer p-4" onClick={() => navigate(`/campaigns/${c.campaign_id}`)}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radar className="h-4 w-4" style={{ color: sevColor }} />
          <span className="font-mono text-sm font-bold" style={{ color: sevColor }}>{c.campaign_id}</span>
        </div>
        <span className="badge border" style={{ color: sevColor, borderColor: `${sevColor}44`, background: `${sevColor}11` }}>{c.severity}</span>
      </div>
      <p className="mt-2 text-sm font-semibold text-slate-100">{c.category}</p>
      <p className="font-mono text-[10px] text-slate-500">source {shortId(c.source)} · risk {c.risk_score.toFixed(0)}/100</p>

      <div className="mt-3 grid grid-cols-3 gap-2 text-center">
        <div className="rounded-md bg-night-850/60 p-2">
          <p className="font-mono text-lg font-bold text-electric-400">{c.incident_count}</p>
          <p className="text-[8px] uppercase tracking-wider text-slate-500">incidents</p>
        </div>
        <div className="rounded-md bg-night-850/60 p-2">
          <p className="font-mono text-lg font-bold text-cyber-purple">{c.event_count.toLocaleString()}</p>
          <p className="text-[8px] uppercase tracking-wider text-slate-500">events</p>
        </div>
        <div className="rounded-md bg-night-850/60 p-2">
          <p className="font-mono text-lg font-bold text-cyber-yellow">{c.duration_hours}h</p>
          <p className="text-[8px] uppercase tracking-wider text-slate-500">window</p>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-1">
        {(c.techniques ?? []).slice(0, 6).map((t) => (
          <span key={t} className="rounded bg-cyber-purple/10 px-1.5 py-0.5 font-mono text-[9px] text-cyber-purple">{t}</span>
        ))}
        {(c.techniques ?? []).length === 0 && <span className="text-[9px] text-slate-600">no MITRE mapping</span>}
      </div>

      <div className="mt-3 flex items-center gap-1.5 border-t border-night-800/70 pt-2.5">
        <Link2 className="h-3 w-3 text-slate-600" />
        <span className="ml-auto text-[9px] uppercase tracking-wide text-electric-400/70">open command center →</span>
        <div className="flex flex-wrap gap-1">
          {c.incidents.slice(0, 4).map((i) => (
            <span key={i} className="font-mono text-[9px] text-slate-500">{shortId(i)}</span>
          ))}
          {c.incident_count > 4 && <span className="text-[9px] text-slate-600">+{c.incident_count - 4} more</span>}
        </div>
      </div>

      {intel ? (
        <div className="mt-2.5 flex flex-wrap gap-1.5 border-t border-night-800/70 pt-2.5">
          <IntelBadge label="velocity" value={intel.velocity.band} color={VELOCITY_COLORS[intel.velocity.band] ?? "#38bdf8"} />
          <IntelBadge label="momentum" value={`${intel.momentum.momentum.toFixed(0)} · ${intel.momentum.status}`} color={momentumStatusColor} />
          <IntelBadge label="mitre" value={`${intel.mitre_coverage.overall_coverage.toFixed(0)}%`} color="#a78bfa" />
          {intel.velocity.campaign_escalation_detected && (
            <span className="rounded bg-cyber-red/15 px-1.5 py-0.5 text-[9px] font-bold text-cyber-red">ESCALATING</span>
          )}
        </div>
      ) : (
        <div className="mt-2.5 border-t border-night-800/70 pt-2.5 text-[9px] text-slate-600">computing campaign intelligence…</div>
      )}
    </div>
  );
}
