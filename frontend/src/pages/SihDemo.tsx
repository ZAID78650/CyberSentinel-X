import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle, ArrowRight, Brain, CheckCircle2, FileText, Globe, Layers, Loader2, MapPin,
  Play, Radar, Shield, ShieldCheck, Target, Zap,
} from "lucide-react";
import { api } from "../services/api";
import { Card } from "../components/ui";

/* ── Types ─────────────────────────────────────────────────────────── */

interface DemoStep {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  status: "pending" | "running" | "complete";
  detail?: string;
  duration?: number;
}

interface DemoResult {
  complaint: { id: string; state: string; district: string; amount: number; fraud_type: string };
  prediction: { risk_score: number; risk_level: string; predicted_zone: string; predicted_time: string; confidence: number; explanation: string };
  alert: { id: string; severity: string; title: string };
  case: { id: string; status: string };
}

/* ── Demo Steps ────────────────────────────────────────────────────── */

const DEMO_STEPS: DemoStep[] = [
  { id: "complaint", title: "Cybercrime Complaint Arrives", description: "Synthetic complaint ingested into the system", icon: <FileText className="h-4 w-4" />, color: "#38bdf8", status: "pending" },
  { id: "transaction", title: "Transaction Pattern Detected", description: "Analyzing financial transaction patterns", icon: <Target className="h-4 w-4" />, color: "#a78bfa", status: "pending" },
  { id: "anomaly", title: "Anomaly Detected", description: "Statistical anomaly identified in transaction behavior", icon: <AlertTriangle className="h-4 w-4" />, color: "#fb923c", status: "pending" },
  { id: "correlate", title: "Related Accounts Found", description: "Entity correlation reveals connected accounts", icon: <Radar className="h-4 w-4" />, color: "#22d3ee", status: "pending" },
  { id: "risk", title: "Geographic Risk Increases", description: "Zone risk score elevated based on clustering", icon: <MapPin className="h-4 w-4" />, color: "#f87171", status: "pending" },
  { id: "predict", title: "ML Prediction Runs", description: "Multi-model ensemble prediction executed", icon: <Brain className="h-4 w-4" />, color: "#a78bfa", status: "pending" },
  { id: "hotspot", title: "Predicted Withdrawal Zone", description: "High-risk ATM withdrawal location identified", icon: <Globe className="h-4 w-4" />, color: "#f87171", status: "pending" },
  { id: "heatmap", title: "Risk Heatmap Updates", description: "GIS heatmap layer updated with new prediction", icon: <Layers className="h-4 w-4" />, color: "#4ade80", status: "pending" },
  { id: "alert", title: "Intelligence Alert Generated", description: "Actionable intelligence alert created", icon: <Zap className="h-4 w-4" />, color: "#facc15", status: "pending" },
  { id: "case", title: "Investigation Case Opened", description: "Case created with full evidence package", icon: <ShieldCheck className="h-4 w-4" />, color: "#38bdf8", status: "pending" },
  { id: "explain", title: "Explanation Generated", description: "XAI explanation with feature contributions", icon: <Brain className="h-4 w-4" />, color: "#a78bfa", status: "pending" },
  { id: "audit", title: "Audit Record Created", description: "Tamper-evident audit trail recorded", icon: <Shield className="h-4 w-4" />, color: "#4ade80", status: "pending" },
];

/* ── Demo Visualization ────────────────────────────────────────────── */

function DemoVisualization({ steps, currentIdx, result }: {
  steps: DemoStep[];
  currentIdx: number;
  result: DemoResult | null;
}) {
  return (
    <div className="space-y-4">
      {/* Pipeline visualization */}
      <div className="flex flex-wrap items-center gap-1.5">
        {steps.map((step, i) => {
          const isActive = i === currentIdx;
          const isDone = step.status === "complete";
          return (
            <div key={step.id} className="flex items-center gap-1">
              <div
                className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wider transition-all duration-300 ${
                  isActive
                    ? "bg-electric-500/20 text-electric-400 ring-1 ring-electric-500/40 shadow-[0_0_12px_rgba(56,189,248,0.2)]"
                    : isDone
                    ? "bg-cyber-green/10 text-cyber-green"
                    : "bg-night-800/60 text-slate-600"
                }`}
                style={isActive ? { borderColor: step.color } : undefined}
              >
                {isDone ? <CheckCircle2 className="h-3 w-3" /> : isActive ? <Loader2 className="h-3 w-3 animate-spin" /> : step.icon}
                <span className="hidden sm:inline">{step.title.split(" ").slice(0, 2).join(" ")}</span>
              </div>
              {i < steps.length - 1 && <ArrowRight className="h-3 w-3 text-slate-700" />}
            </div>
          );
        })}
      </div>

      {/* Current step detail */}
      {currentIdx >= 0 && currentIdx < steps.length && (
        <Card>
          <div className="flex items-center gap-4">
            <div
              className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl"
              style={{ background: `${steps[currentIdx].color}1a`, color: steps[currentIdx].color }}
            >
              {steps[currentIdx].status === "running" ? (
                <Loader2 className="h-6 w-6 animate-spin" />
              ) : (
                steps[currentIdx].icon
              )}
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">{steps[currentIdx].title}</h3>
              <p className="text-xs text-slate-400">{steps[currentIdx].description}</p>
              {steps[currentIdx].detail && (
                <p className="mt-1 font-mono text-[11px] text-electric-400">{steps[currentIdx].detail}</p>
              )}
            </div>
          </div>
        </Card>
      )}

      {/* Results */}
      {result && (
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Complaint */}
          <Card title="📋 Complaint Ingested">
            <div className="space-y-2 text-xs">
              <div className="flex justify-between"><span className="text-slate-500">ID</span><span className="font-mono text-electric-400">{result.complaint.id}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">State</span><span className="text-slate-200">{result.complaint.state}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">District</span><span className="text-slate-200">{result.complaint.district}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Amount</span><span className="font-mono text-cyber-red">₹{result.complaint.amount.toLocaleString()}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Fraud Type</span><span className="text-slate-200">{result.complaint.fraud_type}</span></div>
            </div>
          </Card>

          {/* Prediction */}
          <Card title="🧠 ML Prediction">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="relative h-16 w-16 shrink-0">
                  <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                    <circle cx="50" cy="50" r="42" fill="none" stroke="#111a30" strokeWidth="8" />
                    <circle
                      cx="50" cy="50" r="42" fill="none"
                      stroke={result.prediction.risk_level === "CRITICAL" ? "#f87171" : result.prediction.risk_level === "HIGH" ? "#fb923c" : "#facc15"}
                      strokeWidth="8" strokeLinecap="round"
                      strokeDasharray={`${result.prediction.risk_score * 264} 264`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="font-mono text-sm font-bold text-cyber-red">{result.prediction.risk_score}%</span>
                    <span className="text-[7px] uppercase text-slate-500">{result.prediction.risk_level}</span>
                  </div>
                </div>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between gap-4"><span className="text-slate-500">Location</span><span className="text-slate-200">{result.prediction.predicted_zone}</span></div>
                  <div className="flex justify-between gap-4"><span className="text-slate-500">Time</span><span className="text-slate-200">{result.prediction.predicted_time}</span></div>
                  <div className="flex justify-between gap-4"><span className="text-slate-500">Confidence</span><span className="font-mono text-electric-400">{result.prediction.confidence}%</span></div>
                </div>
              </div>
              <p className="text-[10px] leading-relaxed text-slate-400">{result.prediction.explanation}</p>
            </div>
          </Card>

          {/* Alert + Case */}
          <Card title="⚡ Alert & Case">
            <div className="space-y-3">
              <div className="rounded-lg border border-cyber-red/30 bg-cyber-red/5 p-3">
                <p className="text-[10px] font-bold uppercase tracking-wider text-cyber-red">Intelligence Alert</p>
                <p className="mt-1 font-mono text-xs text-electric-400">{result.alert.id}</p>
                <p className="text-xs text-slate-300">{result.alert.title}</p>
                <span className="mt-1 inline-block rounded-full border border-cyber-red/40 bg-cyber-red/10 px-2 py-0.5 text-[9px] font-bold text-cyber-red">
                  {result.alert.severity}
                </span>
              </div>
              <div className="rounded-lg border border-night-700 bg-night-850/50 p-3">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Case Created</p>
                <p className="mt-1 font-mono text-xs text-electric-400">{result.case.id}</p>
                <span className="mt-1 inline-block rounded-full border border-electric-500/30 bg-electric-500/10 px-2 py-0.5 text-[9px] font-bold text-electric-400">
                  {result.case.status}
                </span>
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

/* ── Main Page ─────────────────────────────────────────────────────── */

export default function SihDemo() {
  const navigate = useNavigate();
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<DemoStep[]>(DEMO_STEPS.map((s) => ({ ...s, status: "pending" as const })));
  const [currentIdx, setCurrentIdx] = useState(-1);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runScenario = async () => {
    setRunning(true);
    setError(null);
    setResult(null);
    setSteps(DEMO_STEPS.map((s) => ({ ...s, status: "pending" as const, detail: undefined })));
    setCurrentIdx(-1);

    const stepDetails: Record<string, string> = {
      complaint: "CMP-SIH2026-DEMO-001 · Maharashtra · ₹87,500 · Phishing",
      transaction: "12 transactions detected across 3 accounts · velocity spike",
      anomaly: "Isolation Forest score: 0.87 · LOF score: 0.82",
      correlate: "4 connected accounts · 2 devices · 3 IPs",
      risk: "Zone risk: 87% → CRITICAL · 18 related complaints",
      predict: "Ensemble: RF=0.89 GB=0.84 LR=0.81 · avg=0.85",
      hotspot: "ATM Zone 14, Mumbai · 87% risk · 18:00–21:00 window",
      heatmap: "3 new hotspots added · 1 CRITICAL, 2 HIGH",
      alert: "CRITICAL: Potential Withdrawal Risk · Zone 14, Mumbai",
      case: "INV-2026-DEMO-001 · Under Investigation · 12 evidence items",
      explain: "+18 related complaints · +42% velocity · +geographic hotspot",
      audit: "SHA-256: a7f3b2c1... · Blockchain anchor: block #48291",
    };

    // Animate through steps
    for (let i = 0; i < DEMO_STEPS.length; i++) {
      setCurrentIdx(i);
      setSteps((prev) => prev.map((s, idx) =>
        idx === i ? { ...s, status: "running", detail: stepDetails[s.id] } :
        idx < i ? { ...s, status: "complete" } : s
      ));
      await new Promise((r) => setTimeout(r, 600 + Math.random() * 400));
    }

    // Mark all complete
    setSteps((prev) => prev.map((s) => ({ ...s, status: "complete" })));

    // Try to get real prediction from backend
    try {
      const predRes = await api.post("/v2/predict", {
        complaint: {
          state: "Maharashtra",
          district: "Mumbai",
          fraud_type: "Phishing",
          amount: 87500,
          latitude: 19.076,
          longitude: 72.8777,
          description: "SIH Demo scenario — phishing complaint with suspicious ATM withdrawal pattern",
        },
        include_explanation: true,
      }, { timeout: 30000 });

      const pred = predRes.data;
      setResult({
        complaint: {
          id: "CMP-SIH2026-DEMO-001",
          state: "Maharashtra",
          district: "Mumbai",
          amount: 87500,
          fraud_type: "Phishing",
        },
        prediction: {
          risk_score: Math.round((pred.risk_probability ?? 0.85) * 100),
          risk_level: pred.risk_level ?? "HIGH",
          predicted_zone: pred.geospatial_risk?.risk_level ? `Mumbai Zone (Risk: ${pred.geospatial_risk.risk_level})` : "Mumbai Zone 14",
          predicted_time: "18:00 – 21:00",
          confidence: Math.round((pred.confidence ?? 0.84) * 100),
          explanation: pred.explanation?.summary ?? "Model detected high risk based on transaction velocity, geographic clustering, and related complaint patterns.",
        },
        alert: { id: "ALERT-2026-DEMO-001", severity: "CRITICAL", title: "Potential Withdrawal Risk — Mumbai Zone 14" },
        case: { id: "INV-2026-DEMO-001", status: "Under Investigation" },
      });
    } catch {
      // Fallback to demo data
      setResult({
        complaint: { id: "CMP-SIH2026-DEMO-001", state: "Maharashtra", district: "Mumbai", amount: 87500, fraud_type: "Phishing" },
        prediction: { risk_score: 87, risk_level: "HIGH", predicted_zone: "Mumbai Zone 14", predicted_time: "18:00 – 21:00", confidence: 84, explanation: "Model detected high risk based on 18 related complaints, 42% transaction velocity increase, geographic hotspot correlation, and connected suspicious entities." },
        alert: { id: "ALERT-2026-DEMO-001", severity: "CRITICAL", title: "Potential Withdrawal Risk — Mumbai Zone 14" },
        case: { id: "INV-2026-DEMO-001", status: "Under Investigation" },
      });
    }

    setRunning(false);
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Zap className="h-5 w-5 text-cyber-yellow" />
            <h2 className="text-lg font-bold text-slate-100">SIH Demo Mode</h2>
          </div>
          <p className="text-xs text-slate-500">
            End-to-end demonstration of the SIH26184 predictive cybercrime intelligence pipeline.
            Runs a complete SCAN → UNDERSTAND → PREDICT → LOCATE → ALERT → INTERVENE flow.
          </p>
          <p className="mt-1 text-[10px] text-slate-700">
            Uses controlled synthetic data · Not real government statistics
          </p>
        </div>
        <button
          onClick={runScenario}
          disabled={running}
          className="btn-primary px-5 py-2.5 text-sm"
        >
          {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {running ? "Running Scenario…" : "Run Live Cybercrime Scenario"}
        </button>
      </div>

      {/* Pipeline banner */}
      <div className="flex flex-wrap items-center justify-center gap-2 rounded-xl border border-night-700 bg-night-850/40 px-4 py-3">
        {["SCAN", "UNDERSTAND", "PREDICT", "LOCATE", "ALERT", "INTERVENE"].map((step, i) => (
          <div key={step} className="flex items-center gap-2">
            <span className="rounded-md bg-night-800/70 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400">
              {step}
            </span>
            {i < 5 && <ArrowRight className="h-3 w-3 text-electric-500/30" />}
          </div>
        ))}
      </div>

      {/* Demo visualization */}
      <DemoVisualization steps={steps} currentIdx={currentIdx} result={result} />

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-cyber-red/40 bg-cyber-red/10 p-3 text-xs text-cyber-red">
          {error}
        </div>
      )}

      {/* Navigation buttons after completion */}
      {result && !running && (
        <div className="flex flex-wrap gap-3">
          <button onClick={() => navigate("/gis-heatmap")} className="btn-primary text-sm">
            <MapPin className="h-4 w-4" /> View Risk Heatmap
          </button>
          <button onClick={() => navigate("/predictive-alerts")} className="btn-ghost text-sm">
            <AlertTriangle className="h-4 w-4" /> View Alerts
          </button>
          <button onClick={() => navigate("/cybercrime-scanner")} className="btn-ghost text-sm">
            <Layers className="h-4 w-4" /> Open Scanner
          </button>
          <button onClick={() => navigate("/financial-intelligence")} className="btn-ghost text-sm">
            <Brain className="h-4 w-4" /> Financial Intelligence
          </button>
        </div>
      )}

      {/* Educational note */}
      <Card title="About This Demo">
        <div className="space-y-2 text-xs text-slate-400">
          <p>
            This demonstration showcases the complete SIH26184 pipeline for <strong className="text-slate-200">
            Predictive Analytics Framework for Cybercrime Complaints</strong>.
          </p>
          <p>
            When the ML engine is available, it runs a real prediction using the multi-model ensemble
            (Random Forest + Gradient Boosting + Logistic Regression). The prediction includes
            geospatial risk assessment and full XAI explanation.
          </p>
          <p className="text-[10px] text-slate-600">
            All data shown is synthetic / demonstration data. Predictions are model-generated
            probabilistic intelligence, not guaranteed future events.
          </p>
        </div>
      </Card>
    </div>
  );
}
