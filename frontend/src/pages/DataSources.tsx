import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, CheckCircle2, Database, FileJson, FolderOpen, HardDrive,
  Loader2, RefreshCw, ScanSearch, Trash2, UploadCloud,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, ProgressBar, SeverityBadge, Skeleton, StatCard } from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/ui/Toast";
import type { DatasetStatus, UploadedDataset } from "../types";

function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

const CATEGORY_COLORS = [
  "#38bdf8", "#a78bfa", "#f87171", "#4ade80", "#facc15", "#fb923c", "#22d3ee", "#f472b6", "#94a3b8",
];

function fmt(n: number): string {
  return (n ?? 0).toLocaleString();
}

export default function DataSources() {
  const { hasRole } = useAuth();
  const { success, error: toastError } = useToast();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<DatasetStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ingesting, setIngesting] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [tab, setTab] = useState<"connected" | "upload">("connected");

  const load = useCallback(async () => {
    try {
      const res = await api.get<DatasetStatus>("/dataset/status");
      setStatus(res.data);
      setError(null);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    // Light poll so the page stays fresh even when idle.
    const timer = window.setInterval(() => void load(), 15_000);
    return () => window.clearInterval(timer);
  }, [load]);

  // Tight 3s poll while ingesting
  useEffect(() => {
    if (!status?.progress.running) return;
    const timer = window.setInterval(() => void load(), 3_000);
    return () => window.clearInterval(timer);
  }, [status?.progress.running, load]);

  const startIngest = async () => {
    setIngesting(true);
    try {
      const res = await api.post("/dataset/unsw/ingest");
      success("Ingestion started", res.data.message as string);
      await load();
    } catch (err) {
      toastError("Ingestion failed", getErrorMessage(err));
    } finally {
      setIngesting(false);
    }
  };

  const clearData = async () => {
    if (!confirmClear) {
      setConfirmClear(true);
      return;
    }
    setClearing(true);
    try {
      const res = await api.post("/dataset/clear");
      success("Data cleared", res.data.message as string);
      setConfirmClear(false);
      await load();
      await queryClient.invalidateQueries();
    } catch (err) {
      toastError("Clear failed", getErrorMessage(err));
    } finally {
      setClearing(false);
    }
  };

  const progress = status?.progress;
  const stats = status?.stats;
  const pct = progress?.total_rows
    ? Math.round(((progress.processed_rows ?? 0) / progress.total_rows) * 100)
    : 0;

  const categoryEntries = Object.entries(stats?.by_category ?? {})
    .sort((a, b) => b[1] - a[1]);
  const maxCat = Math.max(1, ...categoryEntries.map(([, v]) => v));

  if (loading && !status) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-72" />
      </div>
    );
  }

  if (error && !status) {
    return (
      <div className="glass p-8 text-center">
        <AlertTriangle className="mx-auto h-10 w-10 text-cyber-red" />
        <p className="mt-3 text-sm text-slate-300">Failed to load dataset status: {error}</p>
        <button className="btn-ghost mt-4" onClick={() => { setLoading(true); void load(); }}>
          <RefreshCw className="h-4 w-4" /> Retry
        </button>
      </div>
    );
  }

  const isAdmin = hasRole("ADMIN");

  return (
    <div className="space-y-5">
      {/* Tabs */}
      <div className="flex gap-1.5">
        <button
          onClick={() => setTab("connected")}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition ${tab === "connected" ? "bg-electric-500/15 text-electric-400" : "bg-night-800/60 text-slate-400 hover:text-slate-200"}`}
        >
          <FolderOpen className="h-4 w-4" /> Connected Datasets
        </button>
        <button
          onClick={() => setTab("upload")}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition ${tab === "upload" ? "bg-electric-500/15 text-electric-400" : "bg-night-800/60 text-slate-400 hover:text-slate-200"}`}
        >
          <UploadCloud className="h-4 w-4" /> Upload Dataset
        </button>
      </div>      {tab === "upload" && <UploadTab />}

      {tab === "connected" && (
        <>
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total Events" value={stats?.events_total ?? 0} color="#38bdf8" icon={<Database className="h-4 w-4" />} />
        <StatCard label="UNSW-NB15 Flows" value={stats?.unsw_events ?? 0} color="#22d3ee" icon={<FileJson className="h-4 w-4" />} />
        <StatCard label="Attack Flows" value={stats?.attack_flows ?? 0} color="#f87171" icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard label="Benign Flows" value={stats?.normal_flows ?? 0} color="#4ade80" icon={<CheckCircle2 className="h-4 w-4" />} />
      </div>

      {/* Ingest controls */}
      <Card
        title="UNSW-NB15 Dataset Connection"
        subtitle="Real network-traffic corpus — 2.5M+ labeled flows, nine attack families + normal"
        actions={
          <span className={`badge border ${status?.configured ? "border-cyber-green/30 bg-cyber-green/10 text-cyber-green" : "border-cyber-yellow/30 bg-cyber-yellow/10 text-cyber-yellow"}`}>
            {status?.configured ? "CONFIGURED" : "NOT CONFIGURED"}
          </span>
        }
      >
        <div className="grid gap-5 lg:grid-cols-2">
          <div>
            <p className="label">Dataset directory</p>
            <code className="block rounded-lg bg-night-850 px-3 py-2 font-mono text-xs text-electric-400">
              {status?.dataset_dir || "— (set UNSW_DATASET_DIR in backend/.env)"}
            </code>
            <div className="mt-3 space-y-1.5">
              {status?.files.map((f) => (
                <div key={f.path} className="flex items-center justify-between rounded-md bg-night-850/60 px-3 py-1.5 font-mono text-[11px]">
                  <span className="text-slate-300">{f.name}</span>
                  <span className={`badge border ${f.exists ? "border-cyber-green/30 bg-cyber-green/10 text-cyber-green" : "border-cyber-red/30 bg-cyber-red/10 text-cyber-red"}`}>
                    {f.exists ? "FOUND" : "MISSING"}
                  </span>
                </div>
              ))}
            </div>

            {progress?.running && (
              <div className="mt-4 rounded-lg border border-electric-500/30 bg-electric-500/5 p-3">
                <div className="flex items-center gap-2 text-xs font-semibold text-electric-400">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Ingesting dataset… {fmt(progress.processed_rows ?? 0)} / {fmt(progress.total_rows ?? 0)} rows ({pct}%)
                </div>
                <ProgressBar value={pct} color="#38bdf8" className="mt-2" />
                <p className="mt-2 text-[10px] text-slate-500">
                  scored {fmt(progress.attack_flows ?? 0)} attack flows so far · {fmt(progress.alerts_created ?? 0)} alerts · {fmt(progress.incidents_created ?? 0)} incidents
                </p>
              </div>
            )}

            {progress?.last_error && (
              <div className="mt-4 rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">
                {progress.last_error}
              </div>
            )}
            {progress?.finished_at && !progress.running && (
              <p className="mt-3 text-[11px] text-slate-500">
                Last ingest finished {new Date(progress.finished_at).toLocaleString()} — {fmt(progress.inserted_rows ?? 0)} flows, {fmt(progress.alerts_created ?? 0)} alerts, {fmt(progress.incidents_created ?? 0)} incidents auto-opened.
              </p>
            )}

            {isAdmin && (
              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  className="btn-primary"
                  onClick={startIngest}
                  disabled={ingesting || progress?.running || !status?.configured}
                  title={status?.configured ? undefined : "UNSW-NB15 CSVs are not present on this server — upload a CSV via the Upload Dataset tab instead"}
                >
                  {ingesting || progress?.running ? <Loader2 className="h-4 w-4 animate-spin" /> : <UploadCloud className="h-4 w-4" />}
                  {progress?.running ? "Ingesting…" : "Ingest UNSW-NB15"}
                </button>
                <button
                  className={confirmClear ? "btn-danger" : "btn-ghost"}
                  onClick={clearData}
                  disabled={clearing || progress?.running}
                >
                  {clearing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                  {confirmClear ? "Click again to confirm" : "Remove all data"}
                </button>
              </div>
            )}
            {isAdmin && !status?.configured && (
              <p className="mt-2 text-[11px] text-slate-500">
                The UNSW-NB15 CSVs aren&apos;t configured on this deployment — upload a CSV from the{" "}
                <button onClick={() => setTab("upload")} className="text-electric-400 underline hover:text-electric-300">
                  Upload Dataset
                </button>{" "}
                tab instead.
              </p>
            )}
            {!isAdmin && (
              <p className="mt-3 text-[11px] text-slate-600">ADMIN role required to ingest or clear dataset data.</p>
            )}
          </div>

          <div>
            <p className="label">Ingested corpus</p>
            {stats && stats.events_total > 0 ? (
              <>
                <div className="mb-3 grid grid-cols-3 gap-2 text-center">
                  <div className="rounded-lg bg-night-850/60 px-2 py-2">
                    <p className="font-mono text-lg font-bold text-cyber-red">{fmt(stats.attack_flows)}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">attacks</p>
                  </div>
                  <div className="rounded-lg bg-night-850/60 px-2 py-2">
                    <p className="font-mono text-lg font-bold text-cyber-green">{fmt(stats.normal_flows)}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">benign</p>
                  </div>
                  <div className="rounded-lg bg-night-850/60 px-2 py-2">
                    <p className="font-mono text-lg font-bold text-electric-400">{fmt(stats.alerts)}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">alerts</p>
                  </div>
                </div>
                <div className="mb-2 flex items-center justify-between text-[10px] text-slate-500">
                  <span>Attack families (detected flows)</span>
                  <span>{stats.by_severity ? Object.entries(stats.by_severity).length : 0} severities</span>
                </div>
                <div className="space-y-1.5">
                  {categoryEntries.map(([cat, count], i) => (
                    <div key={cat} className="flex items-center gap-2">
                      <span className="w-40 truncate text-[11px] text-slate-400">{cat}</span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-night-800">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.min(100, (count / maxCat) * 100)}%`,
                            background: CATEGORY_COLORS[i % CATEGORY_COLORS.length],
                            boxShadow: `0 0 8px ${CATEGORY_COLORS[i % CATEGORY_COLORS.length]}`,
                          }}
                        />
                      </div>
                      <span className="w-14 text-right font-mono text-[11px] text-slate-300">{fmt(count)}</span>
                    </div>
                  ))}
                </div>
                {Object.keys(stats.by_severity ?? {}).length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {Object.entries(stats.by_severity).map(([sev, count]) => (
                      <span key={sev} className="flex items-center gap-1.5 rounded-md bg-night-850/70 px-2 py-1 font-mono text-[10px] text-slate-400">
                        <SeverityBadge severity={sev} />
                        {fmt(count)}
                      </span>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <EmptyState
                icon={<HardDrive className="h-8 w-8" />}
                title="No events ingested yet"
                description="Upload a CSV from the Upload Dataset tab to load real traffic — detection, alerts and incidents are created automatically. (The full UNSW-NB15 CSVs are not configured on this deployment.)"
              />
            )}
          </div>
        </div>
      </Card>

      {/* What happens automatically */}
      <Card title="Automatic Detection System" subtitle="What runs when flows are ingested">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { t: "1 · Score", d: "Isolation Forest fitted on a stratified sample scores every flow; category rules flag known attack families.", c: "#38bdf8" },
            { t: "2 · Ingest", d: "257k+ flows land in the event store with full UNSW feature metadata for 3D analysis.", c: "#22d3ee" },
            { t: "3 · Correlate", d: "Attack flows are grouped by family into alerts, then escalated to incidents with severity + confidence.", c: "#a78bfa" },
            { t: "4 · Investigate", d: "The agent orchestrator investigates the top incident — evidence, MITRE mapping, risk, response recommendations, report.", c: "#f87171" },
          ].map((s) => (
            <div key={s.t} className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <p className="text-xs font-bold" style={{ color: s.c }}>{s.t}</p>
              <p className="mt-1 text-[11px] leading-snug text-slate-400">{s.d}</p>
            </div>
          )          )}
        </div>
      </Card>
        </>
      )}
    </div>
  );
}

function UploadTab() {
  const navigate = useNavigate();
  const { hasRole } = useAuth();
  const { success, error: toastError } = useToast();
  const [datasets, setDatasets] = useState<UploadedDataset[]>([]);
  const [loading, setLoading] = useState(true);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [deleting, setDeleting] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ datasets: UploadedDataset[] }>("/dataset/uploads");
      setDatasets(res.data.datasets);
    } catch (err) {
      toastError("Failed to list datasets", getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [toastError]);

  useEffect(() => { void load(); }, [load]);

  const doUpload = async (file: File) => {
    if (!file.name.toLowerCase().endsWith(".csv")) {
      toastError("Unsupported file", "Only .csv datasets can be uploaded.");
      return;
    }
    setUploading(true);
    setProgress(0);
    const form = new FormData();
    form.append("file", file);
    try {
      await api.post("/dataset/upload", form, {
        timeout: 600000, // 10 minutes for large files
        onUploadProgress: (e) => {
          if (e.total) setProgress(Math.round((e.loaded / e.total) * 100));
        },
      });
      success("Dataset uploaded", `${file.name} is ready for scanning or ingestion.`);
      await load();
    } catch (err) {
      toastError("Upload failed", getErrorMessage(err));
    } finally {
      setUploading(false);
    }
  };

  const doDelete = async (name: string) => {
    setDeleting(name);
    try {
      await api.delete(`/dataset/uploads/${encodeURIComponent(name)}`);
      success("Dataset removed", name);
      await load();
    } catch (err) {
      toastError("Delete failed", getErrorMessage(err));
    } finally {
      setDeleting(null);
    }
  };

  const isAdmin = hasRole("ADMIN");

  return (
    <div className="space-y-5">
      <Card title="Upload a CSV Dataset" subtitle="Bring your own dataset — scan it for malware before ingestion, then ingest it into the SOC">
        <div
          className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-10 text-center transition ${dragOver ? "border-electric-500/70 bg-electric-500/5" : "border-night-700 bg-night-850/40"}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files?.[0];
            if (f) void doUpload(f);
          }}
        >
          {uploading ? (
            <>
              <Loader2 className="h-10 w-10 animate-spin text-electric-400" />
              <p className="mt-3 text-sm font-semibold text-slate-200">Uploading… {progress}%</p>
              <div className="mt-3 h-2 w-64 overflow-hidden rounded-full bg-night-800">
                <div className="h-full rounded-full bg-electric-500 transition-all" style={{ width: `${progress}%` }} />
              </div>
            </>
          ) : (
            <>
              <UploadCloud className="h-10 w-10 text-electric-400" />
              <p className="mt-3 text-sm font-semibold text-slate-200">Drop a CSV here or</p>
              <button className="btn-primary mt-3" onClick={() => fileRef.current?.click()} disabled={!isAdmin}>
                <FolderOpen className="h-4 w-4" /> Choose file
              </button>
              <input
                ref={fileRef}
                type="file"
                accept=".csv,text/csv"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void doUpload(f);
                  e.target.value = "";
                }}
              />
              <p className="mt-2 text-[11px] text-slate-500">CSV only · up to 256 MB · metadata (rows / columns) is parsed on upload</p>
            </>
          )}
        </div>
        {!isAdmin && <p className="mt-3 text-[11px] text-slate-600">ADMIN role required to upload or delete datasets.</p>}
      </Card>

      <Card title="Available Datasets" subtitle="Uploaded CSVs and configured UNSW-NB15 files">
        {loading ? (
          <div className="space-y-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-16" />)}</div>
        ) : datasets.length === 0 ? (
          <EmptyState icon={<Database className="h-8 w-8" />} title="No datasets yet" description="Upload a CSV above, or configure UNSW_DATASET_DIR in backend/.env to connect the UNSW-NB15 corpus." />
        ) : (
          <div className="space-y-2.5">
            {datasets.map((d) => (
              <div key={d.name} className="flex items-center gap-3 rounded-lg border border-night-700/70 bg-night-850/40 px-3.5 py-2.5">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-electric-500/10 text-electric-400">
                  <FileJson className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-xs font-semibold text-slate-200">{d.name}</p>
                  <p className="text-[10px] text-slate-500">
                    {d.source === "uploaded" ? (
                      <>uploaded {d.uploaded_at ? new Date(d.uploaded_at).toLocaleString() : ""} · </>
                    ) : "configured · "}
                    {fmtBytes(d.size_bytes)} · {d.rows ? d.rows.toLocaleString() : "—"} rows{d.columns.length ? ` · ${d.columns.length} columns` : ""}
                  </p>
                </div>
                <span className={`badge border shrink-0 ${d.source === "uploaded" ? "border-electric-500/30 bg-electric-500/10 text-electric-400" : "border-cyber-green/30 bg-cyber-green/10 text-cyber-green"}`}>
                  {d.source === "uploaded" ? "UPLOADED" : "UNSW"}
                </span>
                <button
                  className="btn-ghost shrink-0"
                  title="Scan this dataset for malware"
                  onClick={() => navigate(`/malware-analysis?dataset=${encodeURIComponent(d.name)}`)}
                >
                  <ScanSearch className="h-4 w-4" /> Scan
                </button>
                {d.source === "uploaded" && isAdmin && (
                  <button
                    className="btn-ghost shrink-0 text-electric-400"
                    title="Ingest this dataset through the detection pipeline"
                    onClick={async () => {
                      try {
                        const res = await api.post(`/dataset/uploads/${encodeURIComponent(d.name)}/ingest`);
                        success("Ingestion started", res.data.message as string);
                      } catch (err) {
                        toastError("Ingest failed", getErrorMessage(err));
                      }
                    }}
                  >
                    <UploadCloud className="h-4 w-4" /> Ingest
                  </button>
                )}
                {d.source === "uploaded" && isAdmin && (
                  <button className="btn-ghost shrink-0 text-cyber-red" title="Delete dataset" onClick={() => void doDelete(d.name)} disabled={deleting === d.name}>
                    {deleting === d.name ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
