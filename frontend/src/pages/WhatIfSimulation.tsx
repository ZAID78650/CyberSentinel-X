import { useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  AlertTriangle, Brain, Cpu, FileJson, FileText, Plus, Play, RefreshCcw, Target, TrendingUp, Trash2, Upload,
} from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { Card, EmptyState, Skeleton, StatCard } from "../components/ui";

/* ── Types ─────────────────────────────────────────────────────────────── */

interface Complaint {
  complaint_id: string;
  state: string;
  district: string;
  fraud_type: string;
  amount: number;
  risk_score: number;
  risk_level?: string;
  complaint_time?: string;
  latitude?: number;
  longitude?: number;
  status?: string;
  description?: string;
  bank?: string;
}

interface Scenario {
  name: string;
  description: string;
  modifications: Record<string, number>;
}

interface PredictionResult {
  complaint_id: string;
  risk_level: string;
  probability: number;
  confidence: number;
  explanation?: string;
  scenario: string;
  description: string;
}

/* ── Helpers ───────────────────────────────────────────────────────────── */

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#4ade80",
};

function parseCSV(text: string): Complaint[] {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map((h) => h.trim().toLowerCase().replace(/[^a-z0-9_]/g, "_"));
  const results: Complaint[] = [];
  for (let i = 1; i < lines.length && results.length < 500; i++) {
    const values = lines[i].split(",");
    if (values.length < 3) continue;
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => { row[h] = (values[idx] ?? "").trim().replace(/^"|"$/g, ""); });

    const id = row.complaint_id || row.id || row.case_id || row.incident_id || `CSV-${Date.now().toString(36)}-${i}`;
    const state = row.state || row.region || row.province || "Unknown";
    const district = row.district || row.city || row.area || "Unknown";
    const fraudType = row.fraud_type || row.type || row.category || row.attack_type || row.event_type || "Unknown";
    const amount = parseFloat(row.amount || row.value || row.loss || row.money || row.total || "0") || Math.round(Math.random() * 200000 + 10000);
    const riskScore = parseFloat(row.risk_score || row.risk || row.score || "0") || Math.random() * 0.8 + 0.2;
    const lat = parseFloat(row.latitude || row.lat || "0") || (20 + Math.random() * 10);
    const lng = parseFloat(row.longitude || row.lng || row.lon || "0") || (75 + Math.random() * 10);

    results.push({
      complaint_id: id, state, district, fraud_type: fraudType,
      amount, risk_score: Math.min(1, Math.max(0, riskScore)),
      latitude: lat, longitude: lng,
      status: row.status || "OPEN",
      description: row.description || row.details || "",
      bank: row.bank || row.institution || "",
    });
  }
  return results;
}

function parseJSON(text: string): Complaint[] {
  try {
    const parsed = JSON.parse(text);
    const arr = Array.isArray(parsed) ? parsed : parsed.complaints || parsed.data || parsed.records || parsed.items || [parsed];
    return arr.slice(0, 500).map((r: any, i: number) => ({
      complaint_id: r.complaint_id || r.id || r.case_id || `JSON-${Date.now().toString(36)}-${i}`,
      state: r.state || r.region || "Unknown",
      district: r.district || r.city || "Unknown",
      fraud_type: r.fraud_type || r.type || r.category || "Unknown",
      amount: Number(r.amount || r.value || r.loss) || Math.round(Math.random() * 200000 + 10000),
      risk_score: Math.min(1, Math.max(0, Number(r.risk_score || r.risk || r.score) || Math.random() * 0.8 + 0.2)),
      latitude: Number(r.latitude || r.lat) || (20 + Math.random() * 10),
      longitude: Number(r.longitude || r.lng) || (75 + Math.random() * 10),
      status: r.status || "OPEN",
      description: r.description || "",
      bank: r.bank || "",
    }));
  } catch {
    return [];
  }
}

/* ── File Upload Component ─────────────────────────────────────────────── */

function FileUploadCard({ onFileLoaded }: { onFileLoaded: (complaints: Complaint[], fileName: string) => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [parsing, setParsing] = useState(false);

  const handleFile = async (file: File) => {
    setParsing(true);
    try {
      const text = await file.text();
      let complaints: Complaint[];
      if (file.name.endsWith(".json")) {
        complaints = parseJSON(text);
      } else {
        complaints = parseCSV(text);
      }
      if (complaints.length > 0) {
        onFileLoaded(complaints, file.name);
      } else {
        alert("Could not parse any records from this file. Please check the format.");
      }
    } catch (err) {
      alert(`Failed to parse file: ${getErrorMessage(err)}`);
    } finally {
      setParsing(false);
    }
  };

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
      onClick={() => fileRef.current?.click()}
      className={`cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-all ${
        dragOver ? "border-electric-400 bg-electric-500/10" : "border-night-700 hover:border-electric-500/40"
      }`}
    >
      <input ref={fileRef} type="file" accept=".csv,.json" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
      {parsing ? (
        <div className="flex items-center justify-center gap-3">
          <RefreshCcw className="h-6 w-6 animate-spin text-electric-400" />
          <span className="text-sm text-slate-300">Parsing file…</span>
        </div>
      ) : (
        <>
          <Upload className="mx-auto mb-3 h-8 w-8 text-electric-400" />
          <p className="text-sm font-bold text-slate-200">Upload CSV or JSON Dataset</p>
          <p className="mt-1 text-[11px] text-slate-500">
            Drop a file here or click to browse. Supports CSV and JSON formats with complaint/transaction data.
          </p>
          <div className="mt-3 flex items-center justify-center gap-4 text-[10px] text-slate-600">
            <span className="flex items-center gap-1"><FileText className="h-3 w-3" /> CSV</span>
            <span className="flex items-center gap-1"><FileJson className="h-3 w-3" /> JSON</span>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Main Component ────────────────────────────────────────────────────── */

export default function WhatIfSimulation() {
  const [selectedComplaint, setSelectedComplaint] = useState<string>("");
  const [allComplaints, setAllComplaints] = useState<Complaint[]>([]);
  const [uploadedFileName, setUploadedFileName] = useState<string>("");
  const [scenarios, setScenarios] = useState<Scenario[]>([
    { name: "Double Velocity", description: "Transaction velocity doubles", modifications: { velocity_24h: 1.0 } },
    { name: "Mule Account", description: "Account flagged as mule", modifications: { is_mule_suspected: 1.0 } },
  ]);
  const [showNewScenario, setShowNewScenario] = useState(false);
  const [newScenario, setNewScenario] = useState<Scenario>({ name: "", description: "", modifications: {} });

  // Fetch complaints from backend
  const { data: backendComplaints, isLoading: complaintsLoading } = useQuery({
    queryKey: ["whatif-complaints"],
    queryFn: async () => {
      const res = await api.get("/financial/complaints", { params: { limit: 200 } });
      return (res.data?.complaints || []) as Complaint[];
    },
  });

  // Merge: uploaded file complaints + backend complaints
  const complaints: Complaint[] = [
    ...allComplaints,
    ...(backendComplaints ?? []).filter((bc) => !allComplaints.find((ac) => ac.complaint_id === bc.complaint_id)),
  ];

  const warmUp = async () => {
    try { await api.get("/health", { timeout: 15000 }); } catch { /* wake Render */ }
  };

  // Run simulation mutation
  const { mutate, data: simResult, isPending, error } = useMutation({
    mutationFn: async (params: { base_complaint_id: string; scenarios: Scenario[] }) => {
      await warmUp();
      return (await api.post("/v2/what-if", {
        base_complaint_id: params.base_complaint_id,
        scenarios: params.scenarios,
      }, { timeout: 120000 })).data;
    },
  });

  const handleRun = () => {
    if (!selectedComplaint || scenarios.length === 0) return;
    mutate({ base_complaint_id: selectedComplaint, scenarios });
  };

  const handleFileLoaded = (loadedComplaints: Complaint[], fileName: string) => {
    setAllComplaints((prev) => [...loadedComplaints, ...prev]);
    setUploadedFileName(fileName);
    if (loadedComplaints.length > 0 && !selectedComplaint) {
      setSelectedComplaint(loadedComplaints[0].complaint_id);
    }
  };

  const addScenario = () => {
    if (!newScenario.name) return;
    setScenarios([...scenarios, { ...newScenario, modifications: { ...newScenario.modifications } }]);
    setNewScenario({ name: "", description: "", modifications: {} });
    setShowNewScenario(false);
  };

  const removeScenario = (idx: number) => {
    setScenarios(scenarios.filter((_, i) => i !== idx));
  };

  const presetScenarios: Scenario[] = [
    { name: "Velocity Spike", description: "3x transaction velocity increase", modifications: { velocity_24h: 1.0 } },
    { name: "High Value Transfer", description: "10x normal transaction amount", modifications: { fraud_amount_ratio: 1.0 } },
    { name: "New Beneficiary Network", description: "Connected to 8 suspect accounts", modifications: { linked_complaints: 0.8, connected_components: 0.8 } },
    { name: "Weekend Night Attack", description: "Weekend + nighttime activity", modifications: { is_weekend: 1.0, is_night: 1.0 } },
    { name: "Same-District Cluster", description: "High local complaint density", modifications: { complaint_density: 0.9, district_risk: 0.8 } },
    { name: "Full Escalation", description: "All risk factors maximized", modifications: { velocity_24h: 1.0, fraud_amount_ratio: 1.0, linked_complaints: 1.0, complaint_density: 0.9, is_night: 1.0 } },
  ];

  const selectedObj = complaints.find((c) => c.complaint_id === selectedComplaint);

  return (
    <div className="space-y-5">
      {/* Header KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Simulations Run" value={simResult?.scenarios?.length || 0} color="#a78bfa" icon={<Cpu className="h-4 w-4" />} />
        <StatCard
          label="Baseline Risk"
          value={simResult?.scenarios?.[0]?.probability != null ? `${(simResult.scenarios[0].probability * 100).toFixed(0)}%` : "—"}
          color="#38bdf8" icon={<Target className="h-4 w-4" />}
        />
        <StatCard
          label="Max Predicted"
          value={simResult?.scenarios?.length ? `${(Math.max(...simResult.scenarios.map((s: PredictionResult) => s.probability)) * 100).toFixed(0)}%` : "—"}
          color="#f87171" icon={<AlertTriangle className="h-4 w-4" />}
        />
        <StatCard
          label="Risk Delta"
          value={simResult?.scenarios && simResult.scenarios.length >= 2
            ? `+${((Math.max(...simResult.scenarios.map((s: PredictionResult) => s.probability)) - simResult.scenarios[0].probability) * 100).toFixed(0)}%`
            : "—"}
          color="#fb923c" icon={<TrendingUp className="h-4 w-4" />}
        />
      </div>

      {/* File Upload */}
      <FileUploadCard onFileLoaded={handleFileLoaded} />

      {/* Scenario Builder */}
      <Card
        title="🔮 What-If Scenario Simulator"
        subtitle="Hypothesize and test different fraud scenarios — see how risk predictions change"
      >
        <div className="space-y-4">
          {/* Data source info */}
          {uploadedFileName && (
            <div className="flex items-center gap-2 rounded-lg border border-cyber-green/30 bg-cyber-green/5 px-3 py-2 text-xs">
              <FileText className="h-4 w-4 text-cyber-green" />
              <span className="text-cyber-green font-semibold">Loaded {allComplaints.length} records from {uploadedFileName}</span>
            </div>
          )}

          {/* Base complaint selector */}
          <div>
            <label className="label">Base Complaint ({complaints.length} available)</label>
            {complaintsLoading && complaints.length === 0 ? (
              <Skeleton className="h-10" />
            ) : complaints.length === 0 ? (
              <p className="text-xs text-slate-500 py-2">No complaints available. Upload a CSV/JSON file above to get started.</p>
            ) : (
              <select
                className="input"
                value={selectedComplaint}
                onChange={(e) => setSelectedComplaint(e.target.value)}
              >
                <option value="">Select a complaint to analyze…</option>
                {complaints.map((c) => (
                  <option key={c.complaint_id} value={c.complaint_id}>
                    {c.complaint_id} — {c.district}, {c.state} (₹{(c.amount || 0).toLocaleString()}) [{c.fraud_type}]
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Selected complaint details */}
          {selectedObj && (
            <div className="rounded-lg border border-night-700/70 bg-night-850/50 p-3">
              <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
                <div><span className="text-slate-500">State:</span> <span className="text-slate-200">{selectedObj.state}</span></div>
                <div><span className="text-slate-500">District:</span> <span className="text-slate-200">{selectedObj.district}</span></div>
                <div><span className="text-slate-500">Amount:</span> <span className="font-mono text-cyber-red">₹{selectedObj.amount.toLocaleString()}</span></div>
                <div><span className="text-slate-500">Type:</span> <span className="text-slate-200">{selectedObj.fraud_type}</span></div>
                <div><span className="text-slate-500">Risk:</span> <span className="font-mono" style={{ color: RISK_COLORS[selectedObj.risk_level ?? (selectedObj.risk_score >= 0.85 ? "CRITICAL" : selectedObj.risk_score >= 0.6 ? "HIGH" : "MEDIUM")] }}>{(selectedObj.risk_score * 100).toFixed(0)}%</span></div>
                {selectedObj.status && <div><span className="text-slate-500">Status:</span> <span className="text-slate-200">{selectedObj.status}</span></div>}
                {selectedObj.bank && <div><span className="text-slate-500">Bank:</span> <span className="text-slate-200">{selectedObj.bank}</span></div>}
                {selectedObj.description && <div className="col-span-2"><span className="text-slate-500">Description:</span> <span className="text-slate-300">{selectedObj.description.slice(0, 100)}{selectedObj.description.length > 100 ? "…" : ""}</span></div>}
              </div>
            </div>
          )}

          {/* Scenarios */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="label !mb-0">Scenarios</label>
              <button className="btn-ghost text-xs" onClick={() => setShowNewScenario(!showNewScenario)}>
                <Plus className="h-3.5 w-3.5" /> Add
              </button>
            </div>
            <div className="space-y-2">
              {scenarios.map((s, i) => (
                <div key={i} className="flex items-center gap-3 rounded-lg border border-night-700/70 bg-night-850/50 px-3 py-2">
                  <span className="flex-1">
                    <span className="text-sm font-medium text-slate-200">{s.name}</span>
                    <span className="ml-2 text-[11px] text-slate-500">{s.description}</span>
                  </span>
                  <span className="font-mono text-[10px] text-slate-400">
                    {Object.entries(s.modifications).map(([k, v]) => `${k}=${v}`).join(', ')}
                  </span>
                  <button onClick={() => removeScenario(i)} className="text-slate-600 hover:text-red-400">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>

            {showNewScenario && (
              <div className="mt-3 rounded-lg border border-electric-500/30 bg-electric-500/5 p-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="label">Name</label>
                    <input className="input" value={newScenario.name} onChange={e => setNewScenario({ ...newScenario, name: e.target.value })} placeholder="Scenario name" />
                  </div>
                  <div>
                    <label className="label">Description</label>
                    <input className="input" value={newScenario.description} onChange={e => setNewScenario({ ...newScenario, description: e.target.value })} placeholder="What happens?" />
                  </div>
                </div>
                <div className="mt-3">
                  <label className="label">Parameters</label>
                  <div className="grid grid-cols-3 gap-2">
                    {["velocity_multiplier", "amount_multiplier", "fraud_amount_ratio", "complaint_density", "linked_complaints", "is_night"].map(key => (
                      <div key={key}>
                        <label className="text-[10px] text-slate-500">{key.replace(/_/g, ' ')}</label>
                        <input
                          type="number" className="input text-xs" placeholder="0.0-1.0" min="0" max="10" step="0.1"
                          value={newScenario.modifications[key] ?? ''}
                          onChange={e => setNewScenario({
                            ...newScenario,
                            modifications: { ...newScenario.modifications, [key]: parseFloat(e.target.value) || 0 }
                          })}
                        />
                      </div>
                    ))}
                  </div>
                </div>
                <button className="btn-ghost mt-2" onClick={addScenario}>Add Scenario</button>
              </div>
            )}
          </div>

          {/* Presets */}
          <div>
            <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Quick Presets</p>
            <div className="flex flex-wrap gap-2">
              {presetScenarios.map((preset) => (
                <button
                  key={preset.name}
                  onClick={() => { if (!scenarios.find(s => s.name === preset.name)) setScenarios([...scenarios, preset]); }}
                  className="rounded-md border border-night-700 bg-night-850 px-3 py-1.5 text-[11px] text-slate-300 hover:border-electric-500/50 hover:text-white transition-colors"
                >
                  + {preset.name}
                </button>
              ))}
            </div>
          </div>

          {/* Run button */}
          <div className="flex justify-end">
            <button
              className="btn-primary"
              onClick={handleRun}
              disabled={isPending || !selectedComplaint || scenarios.length === 0}
            >
              {isPending ? (
                <><RefreshCcw className="h-4 w-4 animate-spin" /> Simulating…</>
              ) : (
                <><Play className="h-4 w-4" /> Run Simulation</>
              )}
            </button>
          </div>

          {error && (
            <div className="rounded-lg border border-cyber-red/30 bg-cyber-red/10 p-3 text-sm text-cyber-red">
              {getErrorMessage(error)}
            </div>
          )}
        </div>
      </Card>

      {/* Results */}
      {simResult && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {simResult.scenarios.map((result: PredictionResult, i: number) => {
              const color = RISK_COLORS[result.risk_level] || "#64748b";
              const isBase = i === 0;
              return (
                <div
                  key={i}
                  className="relative rounded-xl border p-4 transition-all hover:shadow-lg"
                  style={{ borderColor: isBase ? '#334155' : `${color}50`, background: isBase ? 'rgba(56,189,248,0.03)' : 'rgba(0,0,0,0.1)' }}
                >
                  {isBase && (
                    <span className="absolute right-2 top-2 badge border border-electric-500/40 bg-electric-500/10 text-electric-400 text-[9px]">BASE</span>
                  )}
                  <div className="flex items-center gap-3 mb-3">
                    <div className="relative h-12 w-12 shrink-0">
                      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                        <circle cx="50" cy="50" r="40" fill="none" stroke="#1a2540" strokeWidth="8" />
                        <circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
                          strokeDasharray={`${result.probability * 251} 251`}
                          style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="font-mono text-sm font-bold" style={{ color }}>{(result.probability * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                    <div>
                      <p className="text-xs font-bold text-slate-200">{result.scenario}</p>
                      <p className="text-[10px] text-slate-500">{result.description}</p>
                    </div>
                  </div>
                  <div className="flex gap-2 text-[10px]">
                    <span className="rounded px-1.5 py-0.5 font-bold" style={{ color, background: `${color}20` }}>{result.risk_level}</span>
                    <span className="text-slate-500">conf: {(result.confidence * 100).toFixed(1)}%</span>
                  </div>
                  {result.explanation && (
                    <p className="mt-2 text-[10px] leading-relaxed text-slate-500 border-t border-night-700/50 pt-2">{result.explanation}</p>
                  )}
                </div>
              );
            })}
          </div>

          {/* Sensitivity Analysis */}
          {simResult.sensitivity_analysis && (
            <Card title="📊 Sensitivity Analysis" subtitle="How each factor independently affects risk">
              <div className="grid gap-4 md:grid-cols-2">
                {Object.entries(simResult.sensitivity_analysis as Record<string, unknown[]>).map(([feature, points]) => (
                  <div key={feature} className="rounded-lg border border-night-700/70 p-3">
                    <p className="mb-2 text-xs font-bold text-slate-300">{feature.replace(/_/g, ' ')}</p>
                    <div className="flex items-end gap-1 h-20">
                      {points.map((pt: any, i: number) => {
                        const h = Math.max(8, pt.risk * 80);
                        const c = RISK_COLORS[pt.level] || '#64748b';
                        return (
                          <div key={i} className="flex flex-1 flex-col items-center gap-1">
                            <span className="text-[8px] font-mono" style={{ color: c }}>{(pt.risk * 100).toFixed(0)}%</span>
                            <div className="w-full rounded-t" style={{ height: `${h}px`, background: c, minHeight: 4 }} />
                            <span className="text-[8px] text-slate-500">{pt.value}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <div className="rounded-lg border border-electric-500/20 bg-electric-500/5 p-3 text-[11px] text-slate-400">
            <strong className="text-electric-400">Disclaimer:</strong> {simResult.note || "All predictions are probabilistic estimates, not certainties. Scenarios are hypothetical simulations."}
          </div>
        </>
      )}

      {!simResult && !isPending && (
        <Card>
          <EmptyState
            icon={<Brain className="h-8 w-8" />}
            title="No simulation results yet"
            description="Upload a CSV/JSON file or select a base complaint, configure scenarios, then click Run Simulation."
          />
        </Card>
      )}
    </div>
  );
}
