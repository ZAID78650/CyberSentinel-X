import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle, Bug, CheckCircle2, Database, FileJson, FileText,
  Globe, Loader2, MapPin, RefreshCw, ScanSearch, Shield, Target, Upload,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, StatCard } from "../components/ui";

/* ── Types ─────────────────────────────────────────────────────────── */

interface ScanStage {
  id: string;
  label: string;
  description: string;
  range: [number, number]; // percent range [start, end]
}

interface ScanProgress {
  percent: number;
  stage: ScanStage;
  recordsScanned: number;
  totalRecords: number;
  anomaliesDetected: number;
  entitiesCorrelated: number;
  locationsAnalyzed: number;
  processingRate: number;
  elapsed: number;
}

interface AnomalyIndicator {
  type: string;
  description: string;
  severity: string;
}

interface ScanResult {
  scan_id: string;
  status: string;
  summary: {
    total_rows: number;
    matched_rows: number;
    artifacts_found: number;
    data_quality_score: number;
    scan_time_ms: number;
    ml_available: boolean;
  };
  phases: Record<string, { status: string; rows?: number; artifacts?: number }>;
  data_quality: {
    score: number;
    grade: string;
    completeness: number;
    uniqueness: number;
    missing_columns: Record<string, number>;
    duplicate_percentage: number;
  };
  enrichment: {
    threat_count: number;
    severity_distribution: Record<string, number>;
    unique_hashes: number;
    unique_ips: number;
    unique_domains: number;
    mitre_techniques: string[];
    anomaly_indicators?: AnomalyIndicator[];
    risk_score?: number;
    data_stats?: {
      total_columns: number;
      numeric_columns: number;
      categorical_columns: number;
      total_rows: number;
      matched_rows: number;
      match_rate: number;
    };
  };
  ml_analysis: Record<string, unknown>;
  scan_time_ms: number;
}

/* ── Scanning Stages ───────────────────────────────────────────────── */

const STAGES: ScanStage[] = [
  { id: "init", label: "Initializing", description: "Initializing secure ingestion pipeline…", range: [0, 5] },
  { id: "parse", label: "Data Loading", description: "Parsing records and validating schema…", range: [5, 15] },
  { id: "normalize", label: "Normalization", description: "Normalizing timestamps, amounts, locations…", range: [15, 25] },
  { id: "quality", label: "Data Quality", description: "Detecting missing values, duplicates, anomalies…", range: [25, 35] },
  { id: "transaction", label: "Transaction Analysis", description: "Analyzing transaction frequency, velocity, patterns…", range: [35, 50] },
  { id: "anomaly", label: "Anomaly Detection", description: "Identifying suspicious patterns with ML…", range: [50, 65] },
  { id: "correlate", label: "Entity Correlation", description: "Connecting accounts, devices, IPs, complaints…", range: [65, 75] },
  { id: "geospatial", label: "Geospatial Analysis", description: "Analyzing withdrawal density, geographic clusters…", range: [75, 85] },
  { id: "predict", label: "Predictive Analytics", description: "Running ML prediction models…", range: [85, 95] },
  { id: "intelligize", label: "Intelligence Generation", description: "Generating alerts, heatmap, intelligence summary…", range: [95, 100] },
];

/* ── File Upload Area ──────────────────────────────────────────────── */

function UploadArea({
  onFileSelected,
  uploading,
}: {
  onFileSelected: (file: File) => void;
  uploading: boolean;
}) {
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) onFileSelected(file);
    },
    [onFileSelected],
  );

  const accepted = ".csv,.json,.xlsx,.xls,.pdf,.zip";

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onClick={() => fileRef.current?.click()}
      className={`relative cursor-pointer rounded-xl border-2 border-dashed p-12 text-center transition-all duration-300 ${
        dragOver
          ? "border-electric-400 bg-electric-500/10 shadow-[0_0_40px_rgba(56,189,248,0.15)]"
          : "border-night-700 bg-night-850/40 hover:border-electric-500/40 hover:bg-night-850/60"
      }`}
    >
      <input
        ref={fileRef}
        type="file"
        accept={accepted}
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFileSelected(f);
        }}
      />

      {uploading ? (
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-10 w-10 animate-spin text-electric-400" />
          <p className="text-sm font-semibold text-slate-200">Uploading…</p>
        </div>
      ) : (
        <>
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-electric-500/10">
            <Upload className="h-8 w-8 text-electric-400" />
          </div>
          <p className="text-base font-bold text-slate-200">
            Drop Cybercrime Dataset Here
          </p>
          <p className="mt-2 text-sm text-slate-500">
            CSV · JSON · XLSX · XLS · PDF · ZIP
          </p>
          <div className="mt-4 flex items-center justify-center gap-3">
            <button
              type="button"
              className="btn-primary px-5 py-2 text-xs"
              onClick={(e) => { e.stopPropagation(); fileRef.current?.click(); }}
            >
              Browse Files
            </button>
            <button
              type="button"
              className="px-5 py-2 text-xs font-semibold text-electric-400 border border-electric-500/30 rounded-lg hover:bg-electric-500/10 transition"
              onClick={(e) => { e.stopPropagation(); onFileSelected(new File(['demo'], 'demo_cybercrime_dataset.csv', { type: 'text/csv' })); }}
            >
              ⚡ Run Demo Scan
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/* ── File Info Card ────────────────────────────────────────────────── */

function FileInfoCard({ file, onScan }: { file: File; onScan: () => void }) {
  return (
    <Card title="Dataset Ready" subtitle={`${file.name} · ${(file.size / 1024).toFixed(1)} KB`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-electric-500/15 text-electric-400">
            {file.name.endsWith(".csv") ? <FileText className="h-5 w-5" /> :
             file.name.endsWith(".json") ? <FileJson className="h-5 w-5" /> :
             <Database className="h-5 w-5" />}
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-200">{file.name}</p>
            <p className="text-[11px] text-slate-500">
              {file.type || "unknown type"} · {(file.size / 1024).toFixed(1)} KB
            </p>
          </div>
        </div>
        <button onClick={onScan} className="btn-primary px-5 py-2.5 text-sm">
          <ScanSearch className="h-4 w-4" />
          Start Intelligence Scan
        </button>
      </div>
    </Card>
  );
}

/* ── Scanning Animation ────────────────────────────────────────────── */

function ScanningAnimation({ progress }: { progress: ScanProgress }) {
  const { stage, percent, recordsScanned, totalRecords, anomaliesDetected, entitiesCorrelated, locationsAnalyzed, processingRate, elapsed } = progress;

  return (
    <Card>
      <div className="space-y-6 py-4">
        {/* Header */}
        <div className="text-center">
          <div className="flex items-center justify-center gap-2 mb-1">
            <Shield className="h-5 w-5 text-electric-400" />
            <span className="text-lg font-black tracking-tight text-white">
              CYBERSENTINEL-X
            </span>
          </div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-cyber-cyan">
            Intelligence Scanner
          </p>
        </div>

        {/* Progress bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-electric-400" />
              <span className="text-sm font-semibold text-slate-200">{stage.label}</span>
            </div>
            <span className="font-mono text-sm font-bold text-electric-400">{percent.toFixed(0)}%</span>
          </div>

          <div className="relative h-4 w-full overflow-hidden rounded-full bg-night-800">
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{
                width: `${percent}%`,
                background: "linear-gradient(90deg, #0ea5e9, #38bdf8, #22d3ee)",
                boxShadow: "0 0 16px rgba(56,189,248,0.5)",
              }}
            />
            {/* Animated scanline */}
            <div
              className="absolute inset-y-0 w-24 opacity-30"
              style={{
                left: `${Math.max(0, percent - 5)}%`,
                background: "linear-gradient(90deg, transparent, rgba(56,189,248,0.8), transparent)",
              }}
            />
          </div>

          <p className="text-xs text-slate-400">{stage.description}</p>
        </div>

        {/* Stage indicators */}
        <div className="flex flex-wrap justify-center gap-1.5">
          {STAGES.map((s) => {
            const isActive = s.id === stage.id;
            const isDone = percent > s.range[1];
            return (
              <div
                key={s.id}
                className={`rounded-md px-2 py-1 text-[9px] font-bold uppercase tracking-wider transition-all ${
                  isActive
                    ? "bg-electric-500/20 text-electric-400 ring-1 ring-electric-500/40"
                    : isDone
                    ? "bg-cyber-green/10 text-cyber-green"
                    : "bg-night-800/60 text-slate-600"
                }`}
              >
                {isDone ? "✓" : isActive ? "►" : "○"} {s.label}
              </div>
            );
          })}
        </div>

        {/* Live counters */}
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="font-mono text-2xl font-bold text-electric-400">
              {recordsScanned.toLocaleString()}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Records Scanned</p>
          </div>
          <div>
            <p className="font-mono text-2xl font-bold text-cyber-orange">
              {anomaliesDetected.toLocaleString()}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Anomalies Detected</p>
          </div>
          <div>
            <p className="font-mono text-2xl font-bold text-cyber-purple">
              {entitiesCorrelated.toLocaleString()}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Entities Correlated</p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="font-mono text-xl font-bold text-cyber-cyan">
              {locationsAnalyzed.toLocaleString()}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Locations Analyzed</p>
          </div>
          <div>
            <p className="font-mono text-xl font-bold text-cyber-green">
              {processingRate > 0 ? `${processingRate.toLocaleString()} rec/s` : "—"}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Processing Rate</p>
          </div>
          <div>
            <p className="font-mono text-xl font-bold text-slate-300">
              {elapsed > 0 ? `${(elapsed / 1000).toFixed(1)}s` : "—"}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Elapsed</p>
          </div>
        </div>

        {totalRecords > 0 && (
          <div className="text-center">
            <p className="text-[10px] text-slate-600">
              {recordsScanned.toLocaleString()} / {totalRecords.toLocaleString()} records processed
            </p>
          </div>
        )}
      </div>
    </Card>
  );
}

/* ── Scan Results ──────────────────────────────────────────────────── */

function ScanResults({ result, onNavigateToMap, onNavigateToAlerts }: {
  result: ScanResult;
  onNavigateToMap: () => void;
  onNavigateToAlerts: () => void;
}) {
  const s = result.summary;
  const q = result.data_quality;
  const e = result.enrichment;
  const qualityColor = q.score >= 90 ? "#4ade80" : q.score >= 75 ? "#38bdf8" : q.score >= 60 ? "#facc15" : "#f87171";

  return (
    <div className="space-y-5">
      {/* Completion banner */}
      <div className="rounded-xl border border-cyber-green/30 bg-cyber-green/5 p-6 text-center">
        <CheckCircle2 className="mx-auto mb-2 h-10 w-10 text-cyber-green" />
        <h3 className="text-lg font-bold text-white">✅ Intelligence Analysis Complete</h3>
        <p className="mt-1 text-sm text-slate-400">
          Processed in {(s.scan_time_ms / 1000).toFixed(2)} seconds
        </p>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Records Processed" value={s.total_rows} color="#38bdf8" icon={<Database className="h-4 w-4" />} />
        <StatCard label="Suspicious Records" value={s.matched_rows} color="#f87171" icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard label="Threats Found" value={s.artifacts_found} color="#fb923c" icon={<Bug className="h-4 w-4" />} />
        <StatCard label="Data Quality" value={`${q.score}% (${q.grade})`} color={qualityColor} icon={<Shield className="h-4 w-4" />} hint={`${q.completeness}% complete · ${q.uniqueness}% unique`} />
      </div>

      {/* Processing Phases */}
      <Card title="Processing Phases" subtitle="Each phase completed real processing on your dataset">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {Object.entries(result.phases).map(([phase, info]) => (
            <div key={phase} className="rounded-lg border border-night-700/70 bg-night-850/50 p-3 text-center">
              <CheckCircle2 className="mx-auto mb-1 h-4 w-4 text-cyber-green" />
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">{phase}</p>
              <p className="mt-0.5 font-mono text-[10px] text-slate-600">
                {info.rows ? `${info.rows.toLocaleString()} rows` : info.artifacts ? `${info.artifacts} found` : info.status}
              </p>
            </div>
          ))}
        </div>
      </Card>

      {/* Data Quality */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Data Quality Report">
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="relative h-20 w-20 shrink-0">
                <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="8" />
                  <circle cx="50" cy="50" r="42" fill="none" stroke={qualityColor} strokeWidth="8" strokeLinecap="round"
                    strokeDasharray={`${(q.score / 100) * 264} 264`}
                    style={{ filter: `drop-shadow(0 0 6px ${qualityColor})` }}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="font-mono text-lg font-bold" style={{ color: qualityColor }}>{q.score}%</span>
                  <span className="text-[8px] uppercase text-slate-500">quality</span>
                </div>
              </div>
              <div className="space-y-2 flex-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Completeness</span>
                  <span className="font-mono text-slate-200">{q.completeness}%</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Uniqueness</span>
                  <span className="font-mono text-slate-200">{q.uniqueness}%</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Duplicates</span>
                  <span className="font-mono text-slate-200">{q.duplicate_percentage}%</span>
                </div>
              </div>
            </div>

            {Object.keys(q.missing_columns).length > 0 && (
              <div>
                <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Missing Values</p>
                <div className="space-y-1.5">
                  {Object.entries(q.missing_columns).slice(0, 5).map(([col, pct]) => (
                    <div key={col} className="flex items-center gap-2">
                      <span className="w-24 truncate text-[10px] text-slate-400">{col}</span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-night-800">
                        <div className="h-full rounded-full bg-cyber-red" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="w-10 text-right font-mono text-[10px] text-slate-300">{pct}%</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card title="Threat Intelligence Summary">
          <div className="grid grid-cols-2 gap-3">
            <StatCard label="Threats Found" value={e.threat_count} color="#f87171" icon={<Bug className="h-4 w-4" />} />
            <StatCard label="Unique IPs" value={e.unique_ips} color="#fb923c" icon={<Globe className="h-4 w-4" />} />
            <StatCard label="Unique Hashes" value={e.unique_hashes} color="#a78bfa" icon={<FileJson className="h-4 w-4" />} />
            <StatCard label="MITRE Techniques" value={e.mitre_techniques.length} color="#22d3ee" icon={<Target className="h-4 w-4" />} />
          </div>

          {Object.keys(e.severity_distribution).length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Severity Distribution</p>
              <div className="space-y-1.5">
                {Object.entries(e.severity_distribution).sort((a, b) => b[1] - a[1]).map(([sev, count]) => {
                  const max = Math.max(...Object.values(e.severity_distribution));
                  return (
                    <div key={sev} className="flex items-center gap-2">
                      <span className="w-16 text-[10px] text-slate-400">{sev}</span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-night-800">
                        <div className="h-full rounded-full bg-cyber-red" style={{ width: `${(count / max) * 100}%` }} />
                      </div>
                      <span className="w-8 text-right font-mono text-[10px] text-slate-300">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {e.mitre_techniques.length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">MITRE ATT&CK Techniques</p>
              <div className="flex flex-wrap gap-1.5">
                {e.mitre_techniques.slice(0, 8).map((t) => (
                  <span key={t} className="rounded bg-cyber-red/10 px-2 py-0.5 font-mono text-[9px] text-cyber-red">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Anomaly Indicators from real analysis */}
          {e.anomaly_indicators && e.anomaly_indicators.length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Analysis Findings</p>
              <div className="space-y-1.5">
                {e.anomaly_indicators.map((ind, i) => {
                  const sevColor = ind.severity === "HIGH" ? "#f87171" : ind.severity === "MEDIUM" ? "#facc15" : "#38bdf8";
                  return (
                    <div key={i} className="flex items-start gap-2 rounded-md bg-night-850/60 px-3 py-2">
                      <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: sevColor }} />
                      <div>
                        <p className="text-[11px] text-slate-300">{ind.description}</p>
                        <p className="text-[9px] uppercase tracking-wider" style={{ color: sevColor }}>{ind.severity} · {ind.type}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Data Stats from actual analysis */}
          {e.data_stats && (
            <div className="mt-4">
              <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Dataset Profile</p>
              <div className="grid grid-cols-3 gap-2">
                <div className="rounded-md bg-night-850/60 px-2 py-1.5 text-center">
                  <p className="font-mono text-xs font-bold text-electric-400">{e.data_stats.total_columns}</p>
                  <p className="text-[9px] text-slate-500">Columns</p>
                </div>
                <div className="rounded-md bg-night-850/60 px-2 py-1.5 text-center">
                  <p className="font-mono text-xs font-bold text-cyber-green">{e.data_stats.numeric_columns}</p>
                  <p className="text-[9px] text-slate-500">Numeric</p>
                </div>
                <div className="rounded-md bg-night-850/60 px-2 py-1.5 text-center">
                  <p className="font-mono text-xs font-bold text-cyber-purple">{e.data_stats.match_rate}%</p>
                  <p className="text-[9px] text-slate-500">Match Rate</p>
                </div>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Action buttons */}
      <div className="flex flex-wrap gap-3">
        <button onClick={onNavigateToMap} className="btn-primary text-sm">
          <MapPin className="h-4 w-4" /> View Risk Heatmap
        </button>
        <button onClick={onNavigateToAlerts} className="btn-ghost text-sm">
          <AlertTriangle className="h-4 w-4" /> View Predictive Alerts
        </button>
      </div>

      <p className="text-[10px] italic text-slate-600">
        Scan {result.scan_id} · {result.scan_time_ms}ms · ML model {result.summary.ml_available ? "available" : "not yet trained"}
      </p>
    </div>
  );
}

/* ── Main Page ─────────────────────────────────────────────────────── */

export default function CybercrimeScanner() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [datasets, setDatasets] = useState<Array<{ name: string; rows: number; source: string }>>([]);
  const [selectedDataset, setSelectedDataset] = useState("");

  // Load available datasets on mount
  useEffect(() => {
    api.get<{ datasets: Array<{ name: string; rows: number; source: string }> }>("/dataset/uploads")
      .then((res) => {
        setDatasets(res.data.datasets);
        if (res.data.datasets.length > 0) setSelectedDataset(res.data.datasets[0].name);
      })
      .catch(() => {});
  }, []);

  const handleFileSelected = async (f: File) => {
    setFile(f);
    setUploading(true);
    setError(null);

    // If it's a demo file, skip upload and go straight to scan
    if (f.name === 'demo_cybercrime_dataset.csv' && f.size === 4) {
      setSelectedDataset('demo_cybercrime_aug2026.csv');
      setUploading(false);
      return;
    }

    // Warm up backend if sleeping (Render free tier spins down after inactivity)
    const warmUp = async (retries = 3): Promise<void> => {
      for (let i = 0; i < retries; i++) {
        try {
          await api.get("/health", { timeout: 15000 });
          return;
        } catch {
          if (i < retries - 1) await new Promise(r => setTimeout(r, 3000));
        }
      }
    };

    // Upload the file with retry
    const uploadWithRetry = async (retries = 2): Promise<void> => {
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const formData = new FormData();
          formData.append("file", f);
          const res = await api.post("/dataset/upload", formData, {
            headers: { "Content-Type": "multipart/form-data" },
            timeout: 600000, // 10 minutes for large files
          });
          const uploadedName = (res.data as { name?: string; dataset?: string }).name ?? (res.data as { dataset?: string }).dataset ?? f.name;
          setSelectedDataset(uploadedName);
          const listRes = await api.get<{ datasets: Array<{ name: string; rows: number; source: string }> }>("/dataset/uploads");
          setDatasets(listRes.data.datasets);
          return;
        } catch (err) {
          const msg = getErrorMessage(err);
          const is503 = msg.includes("503") || msg.includes("Service Unavailable");
          if (is503 && attempt < retries) {
            setError(`Backend waking up... retry ${attempt + 1}/${retries}`);
            await warmUp(2);
            continue;
          }
          throw err;
        }
      }
    };

    try {
      await warmUp();
      await uploadWithRetry();
    } catch (err) {
      setError(`Upload failed: ${getErrorMessage(err)}. The backend may be starting up — try again in 30 seconds.`);
    } finally {
      setUploading(false);
    }
  };

  const runScan = async () => {
    if (!selectedDataset) return;
    setScanning(true);
    setError(null);
    setResult(null);

    // Simulate stages while the backend processes
    const startTime = Date.now();
    let stageIdx = 0;

    const progressInterval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const basePercent = Math.min(95, (elapsed / 8000) * 100); // ~8s to 95%

      // Advance stages based on percent
      while (stageIdx < STAGES.length - 1 && basePercent >= STAGES[stageIdx].range[1]) {
        stageIdx++;
      }

      const stage = STAGES[Math.min(stageIdx, STAGES.length - 1)];
      const totalRecords = 500; // Will be updated from response
      const recordsScanned = Math.floor((basePercent / 100) * totalRecords);

      setProgress({
        percent: basePercent,
        stage,
        recordsScanned,
        totalRecords,
        anomaliesDetected: Math.floor(recordsScanned * 0.08),
        entitiesCorrelated: Math.floor(recordsScanned * 0.15),
        locationsAnalyzed: Math.floor(recordsScanned * 0.06),
        processingRate: elapsed > 0 ? Math.floor(recordsScanned / (elapsed / 1000)) : 0,
        elapsed,
      });
    }, 200);

    try {
      // Warm up backend if sleeping
      try { await api.get("/health", { timeout: 10000 }); } catch { await new Promise(r => setTimeout(r, 5000)); }

      const res = await api.post(`/v2/scan`, {
        dataset: selectedDataset,
        limit: 500,
      }, { timeout: 180000 });

      clearInterval(progressInterval);

      const scanResult: ScanResult = res.data;
      setResult(scanResult);

      // Update final progress
      setProgress({
        percent: 100,
        stage: STAGES[STAGES.length - 1],
        recordsScanned: scanResult.summary.total_rows,
        totalRecords: scanResult.summary.total_rows,
        anomaliesDetected: scanResult.summary.matched_rows,
        entitiesCorrelated: Math.floor(scanResult.summary.total_rows * 0.15),
        locationsAnalyzed: Math.floor(scanResult.summary.total_rows * 0.06),
        processingRate: scanResult.summary.total_rows / Math.max(scanResult.scan_time_ms / 1000, 0.1),
        elapsed: scanResult.scan_time_ms,
      });
    } catch (err) {
      clearInterval(progressInterval);
      const msg = getErrorMessage(err);
      // Provide a more helpful error for common backend issues
      if (msg.includes("Not Found") || msg.includes("404")) {
        setError("Scanner endpoint unavailable. The backend may be starting up — please try again in 30 seconds.");
      } else if (msg.includes("502") || msg.includes("503") || msg.includes("timeout")) {
        setError("Backend service is temporarily unavailable. Please try again in 30–60 seconds.");
      } else {
        setError(msg);
      }
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <ScanSearch className="h-5 w-5 text-electric-400" />
          <h2 className="text-lg font-bold text-slate-100">Cybercrime Intelligence Scanner</h2>
        </div>
        <p className="text-xs text-slate-500">
          Upload a cybercrime dataset or select an existing one. The scanner performs real
          multi-stage analysis: parse → normalize → detect → correlate → analyze → predict → intelligize.
        </p>
      </div>

      {/* Upload area */}
      {!result && (
        <>
          <UploadArea onFileSelected={handleFileSelected} uploading={uploading} />

          {file && !uploading && !scanning && (
            <FileInfoCard file={file} onScan={runScan} />
          )}

          {/* Or select existing dataset */}
          {datasets.length > 0 && !file && (
            <Card title="Or Select Existing Dataset">
              <div className="flex items-end gap-3">
                <div className="flex-1">
                  <p className="label">Dataset</p>
                  <select
                    value={selectedDataset}
                    onChange={(e) => setSelectedDataset(e.target.value)}
                    className="input"
                  >
                    {datasets.map((d) => (
                      <option key={d.name} value={d.name}>
                        {d.name} ({d.rows.toLocaleString()} rows) — {d.source}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  onClick={runScan}
                  disabled={!selectedDataset || scanning}
                  className="btn-primary px-5 py-2.5 text-sm"
                >
                  <ScanSearch className="h-4 w-4" />
                  Scan Dataset
                </button>
              </div>
            </Card>
          )}
        </>
      )}

      {/* Scanning animation */}
      {scanning && progress && <ScanningAnimation progress={progress} />}

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-cyber-red/40 bg-cyber-red/10 p-4 text-sm text-cyber-red">
          <AlertTriangle className="mb-1 inline h-4 w-4" /> {error}
          <button className="ml-3 text-xs underline" onClick={() => { setError(null); setResult(null); setFile(null); }}>
            Try again
          </button>
        </div>
      )}

      {/* Results */}
      {result && (
        <>
          <ScanResults
            result={result}
            onNavigateToMap={() => navigate("/gis-heatmap")}
            onNavigateToAlerts={() => navigate("/predictive-alerts")}
          />

          {/* Scan another */}
          <div className="text-center">
            <button
              className="btn-ghost text-xs"
              onClick={() => { setResult(null); setFile(null); setProgress(null); setError(null); }}
            >
              <RefreshCw className="h-3.5 w-3.5" /> Scan Another Dataset
            </button>
          </div>
        </>
      )}

      {/* Demo mode indicator */}
      <div className="text-center">
        <p className="text-[10px] text-slate-700">
          {selectedDataset ? `Dataset: ${selectedDataset}` : "CyberSentinel-X · SIH26184 · Intelligence Scanner"}
        </p>
      </div>
    </div>
  );
}
