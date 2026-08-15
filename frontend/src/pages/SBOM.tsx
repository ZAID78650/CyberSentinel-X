import { useQuery } from "@tanstack/react-query";
import { Boxes, Package } from "lucide-react";
import { api } from "../services/api";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import { Card, EmptyState, Skeleton, StatCard } from "../components/ui";

interface SbomCve { cve: string; severity: string; confidence: number; source: string; description: string | null }
interface SbomDep { name: string; version: string; ecosystem: string; type: string; license: string; known_cves: SbomCve[]; vulnerable: boolean }
interface SbomData {
  manifests: Array<{ file: string; format: string; dependencies: number }>;
  dependencies: SbomDep[];
  totals: { dependencies: number; ecosystems: string[]; vulnerable: number; critical: number; unpinned: number; unlicensed: number };
  findings: Array<{ dependency: string; version: string; cves: SbomCve[] }>;
  supply_chain_risk: { score: number; level: string; factors: Array<{ factor: string; contribution: number; evidence: string }> };
  provenance: { mode: string; source: string; cve_feed: string };
}

export default function SBOM() {
  const { data, isLoading } = useQuery({
    queryKey: ["sbom"],
    queryFn: async () => (await api.get<SbomData>("/sbom")).data,
  });

  if (isLoading && !data) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-slate-100">SBOM & Supply Chain</h2>
        {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24" />)}
      </div>
    );
  }
  if (!data) return null;

  const t = data.totals;
  const risk = data.supply_chain_risk;
  const riskColor = risk.level === "HIGH" ? "#f87171" : risk.level === "MEDIUM" ? "#fbbf24" : "#34d399";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-bold text-slate-100">SBOM & Supply Chain Security</h2>
        <ProvenanceBadge source={data.provenance.mode} />
        <span className="badge border border-night-700 text-slate-500">{data.provenance.source}</span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <StatCard label="Dependencies" value={t.dependencies.toLocaleString()} color="#38bdf8" icon={<Package className="h-4 w-4" />} hint={t.ecosystems.join(" + ")} />
        <StatCard label="Known vulnerable" value={t.vulnerable.toLocaleString()} color={t.vulnerable ? "#f87171" : "#34d399"} hint="matches in local CVE feed" />
        <StatCard label="Critical CVEs" value={t.critical.toLocaleString()} color={t.critical ? "#ef4444" : "#34d399"} hint="CRITICAL severity findings" />
        <StatCard label="Unpinned" value={t.unpinned.toLocaleString()} color="#fbbf24" hint="versions not pinned exactly" />
        <StatCard label="Supply chain risk" value={`${risk.score}/100`} color={riskColor} hint={`${risk.level} · explainable below`} />
      </div>

      <Card title="Supply chain risk — explainable" subtitle="Weighting is visible; every contribution cites evidence.">
        <div className="grid gap-2 md:grid-cols-2">
          {risk.factors.map((f) => (
            <div key={f.factor} className="rounded-lg border border-night-700 bg-night-850/60 p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300">{f.factor}</span>
                <span className="font-mono text-cyber-yellow">+{f.contribution}</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-500">{f.evidence}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[11px] text-slate-600">
          CVE data: <span className="text-cyber-yellow">{data.provenance.cve_feed}</span> — no external NVD/OSV feed is assumed; dependencies with no local CVE match are reported as not known-vulnerable, never guessed.
        </p>
      </Card>

      <Card title={`Dependencies (${t.dependencies})`} subtitle="Scanned from the platform's own manifests.">
        {data.dependencies.length === 0 ? (
          <EmptyState icon={<Boxes className="h-8 w-8" />} title="No manifests found" description="Scan package-lock.json / requirements.txt from the repo root." />
        ) : (
          <div className="max-h-[480px] overflow-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Package</th><th>Version</th><th>Ecosystem</th><th>Type</th><th>License</th><th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {data.dependencies.map((d, i) => (
                  <tr key={`${d.name}-${i}`}>
                    <td className="font-mono text-xs font-medium text-slate-200">{d.name}</td>
                    <td className="font-mono text-xs text-slate-400">{d.version}</td>
                    <td className="text-xs text-slate-400">{d.ecosystem}</td>
                    <td className="text-xs text-slate-500">{d.type}</td>
                    <td className="text-xs text-slate-500">{d.license}</td>
                    <td>
                      {d.vulnerable ? (
                        <div className="flex flex-wrap gap-1">
                          {d.known_cves.map((c) => (
                            <span key={c.cve} className={`badge border ${c.severity === "CRITICAL" ? "border-cyber-red/40 bg-cyber-red/10 text-cyber-red" : "border-cyber-orange/40 bg-cyber-orange/10 text-cyber-orange"}`} title={c.description ?? c.cve}>
                              {c.cve}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="badge border border-cyber-green/40 bg-cyber-green/10 text-cyber-green">no known CVE</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
