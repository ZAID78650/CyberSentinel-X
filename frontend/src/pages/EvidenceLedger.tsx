import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle, Boxes, CheckCircle2, Download, Fingerprint, GitCommitHorizontal, Hash, Loader2, Lock,
  Paperclip, RefreshCw, ShieldCheck, ShieldX, Trash2,
} from "lucide-react";
import { api, downloadEvidenceAttachment, getErrorMessage, uploadEvidenceAttachment } from "../services/api";
import { Card, EmptyState, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import ProvenanceBadge from "../components/ui/ProvenanceBadge";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import type { EvidenceRecordItem, LedgerBlockItem, LedgerVerifyReport } from "../types";

function short(hash?: string | null, n = 12): string {
  if (!hash) return "—";
  return `${hash.slice(0, n)}…${hash.slice(-6)}`;
}

export default function EvidenceLedger() {
  const { hasRole } = useAuth();
  const { success, error: toastError } = useToast();
  const [records, setRecords] = useState<EvidenceRecordItem[]>([]);
  const [blocks, setBlocks] = useState<LedgerBlockItem[]>([]);
  const [report, setReport] = useState<LedgerVerifyReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [backfilling, setBackfilling] = useState(false);
  const [mining, setMining] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [recRes, blockRes] = await Promise.all([
        api.get<{ items: EvidenceRecordItem[] }>("/evidence"),
        api.get<{ blocks: LedgerBlockItem[] }>("/evidence/ledger"),
      ]);
      setRecords(recRes.data.items);
      setBlocks(blockRes.data.blocks);
      setError(null);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const verifyChain = useCallback(async () => {
    setVerifying(true);
    try {
      const res = await api.post<LedgerVerifyReport>("/evidence/ledger/verify");
      setReport(res.data);
      await load();
    } catch (err) {
      toastError("Verification failed", getErrorMessage(err));
    } finally {
      setVerifying(false);
    }
  }, [load, toastError]);

  useEffect(() => {
    void load();
  }, [load]);

  const mineBlock = async () => {
    setMining(true);
    try {
      const res = await api.post<{ block_index: number; block_hash: string; nonce: number; record_count: number }>("/evidence/ledger/mine");
      success("Block mined", `Block #${res.data.block_index} anchored ${res.data.record_count} records (nonce ${res.data.nonce}).`);
      await load();
    } catch (err) {
      toastError("Mining failed", getErrorMessage(err));
    } finally {
      setMining(false);
    }
  };

  const tamperTest = async (evidenceId: string) => {
    setBusyId(evidenceId);
    try {
      const res = await api.post<{ tamper_detected: boolean; status: string }>(`/evidence/${evidenceId}/tamper-test`);
      success("Integrity alert fired", res.data.tamper_detected ? "Hash mismatch detected — record marked TAMPERED (simulation)." : "No tamper detected.");
      await load();
    } catch (err) {
      toastError("Tamper test failed", getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  };

  const restore = async (evidenceId: string) => {
    setBusyId(evidenceId);
    try {
      const res = await api.post<{ valid: boolean; status: string }>(`/evidence/${evidenceId}/restore`);
      success("Evidence restored", res.data.valid ? "Original payload restored — record VALID again." : "Restore did not validate.");
      await load();
    } catch (err) {
      toastError("Restore failed", getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  };

  const handleAttach = async (evidenceId: string, file?: File) => {
    if (!file) return;
    setBusyId(evidenceId);
    try {
      await uploadEvidenceAttachment(evidenceId, file);
      success("Attachment added", `${file.name} attached — SHA-256 stored with the record.`);
      await load();
    } catch (err) {
      toastError("Upload failed", getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  };

  const handleDownload = async (evidenceId: string) => {
    try {
      await downloadEvidenceAttachment(evidenceId);
    } catch (err) {
      toastError("Download failed", getErrorMessage(err));
    }
  };

  const isAdmin = hasRole("ADMIN");
  const canAttach = isAdmin || hasRole("SECURITY_ANALYST");
  const tampered = records.filter((r) => r.status === "TAMPERED").length;
  const integrityOk = report ? report.valid : tampered === 0;

  if (loading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-64" />
        <Skeleton className="h-80" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <div className={`glass glass-hover relative overflow-hidden p-4 ${integrityOk ? "" : "ring-1 ring-cyber-red/50"}`}>
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: integrityOk ? "#4ade80" : "#f87171", boxShadow: `0 0 12px ${integrityOk ? "#4ade80" : "#f87171"}` }} />
          <div className="flex items-center justify-between">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Ledger Integrity</p>
            {integrityOk ? <ShieldCheck className="h-4 w-4 text-cyber-green" /> : <ShieldX className="h-4 w-4 text-cyber-red" />}
          </div>
          <p className="mt-1.5 text-2xl font-bold" style={{ color: integrityOk ? "#4ade80" : "#f87171" }}>{integrityOk ? "VALID" : "TAMPERED"}</p>
          {report && <p className="mt-0.5 text-[10px] text-slate-600">verified {new Date(report.audited_at).toLocaleTimeString()}</p>}
        </div>
        <div className="glass glass-hover relative overflow-hidden p-4">
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: "#38bdf8", boxShadow: "0 0 12px #38bdf8" }} />
          <div className="flex items-center justify-between">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Evidence Records</p>
            <Fingerprint className="h-4 w-4 text-electric-400" />
          </div>
          <p className="kpi-value mt-1.5 text-2xl" style={{ color: "#38bdf8" }}>{records.length.toLocaleString()}</p>
        </div>
        <div className="glass glass-hover relative overflow-hidden p-4">
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: "#a78bfa", boxShadow: "0 0 12px #a78bfa" }} />
          <div className="flex items-center justify-between">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Mined Blocks</p>
            <Boxes className="h-4 w-4 text-cyber-purple" />
          </div>
          <p className="kpi-value mt-1.5 text-2xl" style={{ color: "#a78bfa" }}>{blocks.length.toLocaleString()}</p>
        </div>
        <div className="glass glass-hover relative overflow-hidden p-4">
          <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: tampered ? "#f87171" : "#4ade80", boxShadow: `0 0 12px ${tampered ? "#f87171" : "#4ade80"}` }} />
          <div className="flex items-center justify-between">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Tampered Records</p>
            <AlertTriangle className="h-4 w-4" style={{ color: tampered ? "#f87171" : "#4ade80" }} />
          </div>
          <p className="kpi-value mt-1.5 text-2xl" style={{ color: tampered ? "#f87171" : "#4ade80" }}>{tampered.toLocaleString()}</p>
        </div>
      </div>

      {/* Integrity audit panel */}
      <Card
        title="Evidence Ledger — Chain of Custody"
        subtitle="SHA-256 hash chain with proof-of-work anchoring. Only hashes and provenance are stored — never raw logs."
        actions={
          <div className="flex flex-wrap gap-2">
            <button className="btn-ghost" onClick={verifyChain} disabled={verifying}>
              {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              {report ? "Re-verify chain" : "Verify chain"}
            </button>
            {isAdmin && (
              <button className="btn-ghost" onClick={async () => {
                setBackfilling(true);
                try {
                  const res = await api.post<{ backfilled: number }>("/evidence/ledger/backfill-merkle");
                  success("Merkle backfill", res.data.backfilled > 0 ? `Computed ${res.data.backfilled} missing Merkle root(s) from committed record hashes.` : "No pre-Merkle blocks to backfill.");
                  await load();
                } catch (err) {
                  toastError("Backfill failed", getErrorMessage(err));
                } finally {
                  setBackfilling(false);
                }
              }} disabled={backfilling}>
                {backfilling ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitCommitHorizontal className="h-4 w-4" />}
                Backfill Merkle roots
              </button>
            )}
            {isAdmin && (
              <button className="btn-primary" onClick={mineBlock} disabled={mining}>
                {mining ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
                Mine block
              </button>
            )}
          </div>
        }
      >
        {report ? (
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-4">
              <div className="flex items-center gap-2">
                {report.valid ? <CheckCircle2 className="h-5 w-5 text-cyber-green" /> : <ShieldX className="h-5 w-5 text-cyber-red" />}
                <span className={`badge border ${report.valid ? "border-cyber-green/40 bg-cyber-green/10 text-cyber-green" : "border-cyber-red/40 bg-cyber-red/10 text-cyber-red"}`}>
                  INTEGRITY: {report.integrity}
                </span>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-3 text-[11px]">
                <div><p className="text-slate-500">Evidence verified</p><p className="font-mono font-bold text-slate-200">{report.evidence_verified}/{report.evidence_records}</p></div>
                <div><p className="text-slate-500">Blocks valid</p><p className="font-mono font-bold text-slate-200">{report.ledger_blocks_valid}/{report.ledger_blocks}</p></div>
                <div><p className="text-slate-500">Method</p><p className="font-mono text-slate-300">{report.method}</p></div>
                <div><p className="text-slate-500">Audited at</p><p className="font-mono text-slate-300">{new Date(report.audited_at).toLocaleString()}</p></div>
              </div>
              {report.evidence_tampered.length > 0 && (
                <div className="mt-3 rounded-md border border-cyber-red/40 bg-cyber-red/10 p-2 text-[11px] text-cyber-red">
                  <p className="font-bold">INTEGRITY ALERT — tampered: {report.evidence_tampered.join(", ")}</p>
                  {report.issues.slice(0, 5).map((i) => <p key={i} className="mt-0.5">• {i}</p>)}
                </div>
              )}
            </div>
            <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-4">
              <p className="mb-2 text-[11px] font-bold uppercase tracking-wider text-slate-500">Mined blocks (proof-of-work)</p>
              {blocks.length === 0 ? (
                <p className="text-xs text-slate-500">No blocks mined yet — create evidence then “Mine block” to anchor it.</p>
              ) : (
                <div className="space-y-2">
                  {blocks.slice().reverse().map((b) => (
                    <div key={b.block_index} className="rounded-md bg-night-900/60 p-3 font-mono text-[10px]">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyber-purple">BLOCK #{b.block_index}</span>
                        <span className="text-slate-500">{b.record_count} records · nonce {b.nonce} · diff {b.difficulty}</span>
                      </div>
                      <p className="mt-1 text-electric-400">hash 0x{short(b.block_hash, 16)}</p>
                      <p className="text-slate-600">prev 0x{short(b.prev_block_hash, 16)}</p>
                      <p className="text-slate-600">digest 0x{short(b.records_digest, 16)} · mined {new Date(b.mined_at).toLocaleTimeString()}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-500">Run “Verify chain” to recompute every hash and audit the full chain of custody.</p>
        )}
      </Card>

      {/* Evidence records */}
      <Card
        title="Evidence Records"
        subtitle="Chain-linked hashes — any modification after hashing triggers an integrity alert"
        actions={<ProvenanceBadge source="LOCAL" />}
      >
        {records.length === 0 ? (
          <EmptyState icon={<Fingerprint className="h-8 w-8" />} title="No evidence recorded yet"
            description="Evidence is created automatically when incidents are investigated (attack DNA, predictions) or manually by analysts." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-xs">
              <thead>
                <tr className="border-b border-night-700/70 text-[10px] uppercase tracking-wider text-slate-500">
                  <th className="py-2 pr-3">ID</th>
                  <th className="py-2 pr-3">Type</th>
                  <th className="py-2 pr-3">Title</th>
                  <th className="py-2 pr-3">Source</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Record hash</th>
                  <th className="py-2 pr-3">Chain</th>
                  <th className="py-2 pr-3">Created</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.id} className={`border-b border-night-800/60 ${r.status === "TAMPERED" ? "bg-cyber-red/5" : "hover:bg-night-850/40"}`}>
                    <td className="py-2.5 pr-3 font-mono font-bold text-electric-400">{r.evidence_id}</td>
                    <td className="py-2.5 pr-3"><SeverityBadge severity={r.evidence_type} /></td>
                    <td className="py-2.5 pr-3 max-w-[240px]">
                      <p className="truncate text-slate-200" title={r.title}>{r.title}</p>
                      {r.incident_id && <p className="font-mono text-[9px] text-slate-600">{r.incident_id}</p>}
                    </td>
                    <td className="py-2.5 pr-3"><ProvenanceBadge source={r.data_source} compact /></td>
                    <td className="py-2.5 pr-3"><StatusBadge status={r.status} /></td>
                    <td className="py-2.5 pr-3">
                      <span className="font-mono text-[10px] text-slate-400" title={r.record_hash}>0x{short(r.record_hash)}</span>
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-[10px] text-slate-500">#{r.chain_index}</td>
                    <td className="py-2.5 pr-3 text-[10px] text-slate-500">{new Date(r.created_at).toLocaleString()}</td>
                    <td className="py-2.5">
                      {canAttach && (
                        <div className="flex flex-wrap items-center justify-end gap-1">
                          {r.attachment && (
                            <>
                              <button className="btn-ghost !px-2 !py-1 text-[10px]" onClick={() => handleDownload(r.evidence_id)} title={`${r.attachment.name} (sha256 ${r.attachment.hash.slice(0, 12)}…)`}>
                                <Download className="h-3 w-3" /> {r.attachment.name.length > 12 ? `${r.attachment.name.slice(0, 12)}…` : r.attachment.name}
                              </button>
                            </>
                          )}
                          <label className="btn-ghost !cursor-pointer !px-2 !py-1 text-[10px]">
                            <Paperclip className="h-3 w-3" /> Attach
                            <input
                              type="file"
                              className="hidden"
                              onChange={(e) => { void handleAttach(r.evidence_id, e.target.files?.[0]); e.target.value = ""; }}
                            />
                          </label>
                          {isAdmin && (r.status === "TAMPERED" ? (
                            <button className="btn-ghost !px-2 !py-1 text-[10px]" onClick={() => restore(r.evidence_id)} disabled={busyId === r.id}>
                              {busyId === r.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />} Restore
                            </button>
                          ) : (
                            <button className="btn-ghost !px-2 !py-1 text-[10px]" onClick={() => tamperTest(r.evidence_id)} disabled={busyId === r.id} title="SIMULATION — mutate payload without updating hash to demo integrity detection">
                              {busyId === r.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <AlertTriangle className="h-3 w-3" />} Tamper test
                            </button>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!isAdmin && <p className="mt-3 text-[11px] text-slate-600">ADMIN role required for tamper tests, restores and block mining. Analysts can attach files to evidence records.</p>}
      </Card>

      {error && (
        <div className="rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">{error}</div>
      )}

      <Card title="How integrity works" subtitle="Blockchain-compatible ledger abstraction">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { t: "1 · Record hash", d: "SHA-256 over (chain_index | prev_hash | content_hash | timestamp) — each record links to the previous one.", c: "#38bdf8", i: <Hash className="h-4 w-4" /> },
            { t: "2 · Content hash", d: "SHA-256 over the canonical payload (title, description, meta). Editing a record changes this hash.", c: "#22d3ee", i: <Fingerprint className="h-4 w-4" /> },
            { t: "3 · Mined block", d: "Proof-of-work (leading-zeros nonce) anchors a batch of record hashes into an immutable block.", c: "#a78bfa", i: <Boxes className="h-4 w-4" /> },
            { t: "4 · Verification", d: "Recomputes every hash from stored fields. Any mismatch flags the record TAMPERED and breaks the chain.", c: "#4ade80", i: <ShieldCheck className="h-4 w-4" /> },
          ].map((s) => (
            <div key={s.t} className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <div className="flex items-center gap-2" style={{ color: s.c }}>
                {s.i}
                <p className="text-xs font-bold">{s.t}</p>
              </div>
              <p className="mt-1.5 text-[11px] leading-snug text-slate-400">{s.d}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[10px] text-slate-600">
          Privacy note: raw security logs are never stored on any external chain — only hashes, IDs and provenance metadata. This abstraction can be migrated to Hyperledger Fabric or another permissioned chain without changing call sites.
        </p>
      </Card>
    </div>
  );
}
