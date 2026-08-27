import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowRight, Brain, Database, Layers, MapPin, Play, Radar, Shield, ShieldCheck, Target, Moon, Sun,
} from "lucide-react";
import { Logo } from "../components/Logo";
import { useTheme } from "../contexts/ThemeContext";

/* ── Animated Network Background ───────────────────────────────────── */

interface Node {
  x: number; y: number; vx: number; vy: number; r: number; pulse: number;
}

function NetworkCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const nodesRef = useRef<Node[]>([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let w = (canvas.width = window.innerWidth);
    let h = (canvas.height = window.innerHeight);

    // Create nodes
    const count = Math.min(60, Math.floor((w * h) / 20000));
    nodesRef.current = Array.from({ length: count }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 2 + 1,
      pulse: Math.random() * Math.PI * 2,
    }));

    let raf: number;
    const draw = () => {
      ctx.clearRect(0, 0, w, h);
      const nodes = nodesRef.current;

      // Update positions
      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        n.pulse += 0.02;
        if (n.x < 0 || n.x > w) n.vx *= -1;
        if (n.y < 0 || n.y > h) n.vy *= -1;
        n.x = Math.max(0, Math.min(w, n.x));
        n.y = Math.max(0, Math.min(h, n.y));
      }

      // Draw connections
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 150) {
            const alpha = (1 - dist / 150) * 0.15;
            ctx.strokeStyle = `rgba(56,189,248,${alpha})`;
            ctx.lineWidth = 0.5;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      for (const n of nodes) {
        const glow = 0.4 + Math.sin(n.pulse) * 0.3;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(56,189,248,${glow})`;
        ctx.fill();
      }

      raf = requestAnimationFrame(draw);
    };

    draw();

    const onResize = () => {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-0"
      style={{ opacity: 0.6 }}
    />
  );
}

/* ── Rotating Globe SVG ────────────────────────────────────────────── */

function GlobeViz() {
  const [rotation, setRotation] = useState(0);

  useEffect(() => {
    let raf: number;
    const spin = () => {
      setRotation((r) => (r + 0.15) % 360);
      raf = requestAnimationFrame(spin);
    };
    raf = requestAnimationFrame(spin);
    return () => cancelAnimationFrame(raf);
  }, []);

  // Generate some "data points" on the globe
  const points = [
    { lat: 28.6, lng: 77.2, label: "Delhi" },
    { lat: 19.1, lng: 72.9, label: "Mumbai" },
    { lat: 13.0, lng: 80.3, label: "Chennai" },
    { lat: 22.6, lng: 88.4, label: "Kolkata" },
    { lat: 12.97, lng: 77.6, label: "Bangalore" },
    { lat: 17.4, lng: 78.5, label: "Hyderabad" },
    { lat: 23.0, lng: 72.6, label: "Ahmedabad" },
    { lat: 26.9, lng: 75.8, label: "Jaipur" },
  ];

  const cx = 140, cy = 140, r = 100;
  const toRad = (d: number) => (d * Math.PI) / 180;

  return (
    <svg viewBox="0 0 280 280" className="w-full max-w-[320px]">
      <defs>
        <radialGradient id="globeGrad" cx="40%" cy="35%">
          <stop offset="0%" stopColor="#1a2540" />
          <stop offset="100%" stopColor="#060a14" />
        </radialGradient>
        <radialGradient id="globeGlow" cx="50%" cy="50%">
          <stop offset="70%" stopColor="transparent" />
          <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.08" />
        </radialGradient>
        <clipPath id="globeClip">
          <circle cx={cx} cy={cy} r={r} />
        </clipPath>
      </defs>

      {/* Outer glow */}
      <circle cx={cx} cy={cy} r={r + 15} fill="none" stroke="#38bdf8" strokeWidth="0.5" opacity="0.3">
        <animate attributeName="r" values={`${r + 12};${r + 18};${r + 12}`} dur="4s" repeatCount="indefinite" />
      </circle>

      {/* Globe body */}
      <circle cx={cx} cy={cy} r={r} fill="url(#globeGrad)" stroke="#38bdf8" strokeWidth="1" opacity="0.8" />
      <circle cx={cx} cy={cy} r={r} fill="url(#globeGlow)" />

      {/* Grid lines */}
      <g clipPath="url(#globeClip)" opacity="0.15">
        {[0, 1, 2, 3, 4, 5].map((i) => {
          const offset = (rotation * 0.5 + i * 30) % 360;
          const xPos = cx + r * Math.cos(toRad(offset));
          return (
            <ellipse
              key={`v${i}`}
              cx={xPos}
              cy={cy}
              rx={r * Math.abs(Math.sin(toRad(offset))) * 0.3}
              ry={r}
              fill="none"
              stroke="#38bdf8"
              strokeWidth="0.5"
            />
          );
        })}
        {[-2, -1, 0, 1, 2].map((i) => (
          <ellipse
            key={`h${i}`}
            cx={cx}
            cy={cy + i * 25}
            rx={r}
            ry={r * Math.cos(toRad(i * 15)) * 0.5}
            fill="none"
            stroke="#38bdf8"
            strokeWidth="0.5"
          />
        ))}
      </g>

      {/* Data points */}
      <g clipPath="url(#globeClip)">
        {points.map((pt, i) => {
          const angle = toRad(pt.lng + rotation);
          const visible = Math.cos(angle) > -0.3;
          if (!visible) return null;

          const xPos = cx + r * 0.8 * Math.sin(angle);
          const yPos = cy - r * 0.6 * Math.sin(toRad(pt.lat));
          const depth = (Math.cos(angle) + 1) / 2;

          return (
            <g key={pt.label} opacity={0.3 + depth * 0.7}>
              <circle cx={xPos} cy={yPos} r={3} fill="#f87171" opacity={0.8}>
                <animate attributeName="r" values="2;4;2" dur={`${2 + i * 0.3}s`} repeatCount="indefinite" />
              </circle>
              <circle cx={xPos} cy={yPos} r={8} fill="none" stroke="#f87171" strokeWidth="0.5" opacity={0.3}>
                <animate attributeName="r" values="6;12;6" dur={`${2 + i * 0.3}s`} repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.3;0;0.3" dur={`${2 + i * 0.3}s`} repeatCount="indefinite" />
              </circle>
              <text x={xPos + 8} y={yPos + 3} fill="#f87171" fontSize="7" fontFamily="monospace" opacity={depth}>
                {pt.label}
              </text>
            </g>
          );
        })}
      </g>

      {/* Scanning line */}
      <line
        x1={cx - r}
        y1={cy}
        x2={cx + r}
        y2={cy}
        stroke="#22d3ee"
        strokeWidth="1"
        opacity="0.4"
        clipPath="url(#globeClip)"
      >
        <animateTransform
          attributeName="transform"
          type="rotate"
          from={`0 ${cx} ${cy}`}
          to={`360 ${cx} ${cy}`}
          dur="6s"
          repeatCount="indefinite"
        />
      </line>
    </svg>
  );
}

/* ── Feature Cards ─────────────────────────────────────────────────── */

const FEATURES = [
  { icon: <Brain className="h-5 w-5" />, title: "Predictive AI", desc: "ML-powered withdrawal location & time prediction with explainability", color: "#a78bfa" },
  { icon: <MapPin className="h-5 w-5" />, title: "Geospatial Intelligence", desc: "Live risk heatmaps with DBSCAN clustering and ML-enhanced scoring", color: "#f87171" },
  { icon: <Radar className="h-5 w-5" />, title: "Entity Correlation", desc: "Network analysis connecting complaints, accounts, devices, and IPs", color: "#22d3ee" },
  { icon: <Target className="h-5 w-5" />, title: "Anomaly Detection", desc: "Isolation Forest + LOF ensemble for suspicious pattern detection", color: "#fb923c" },
  { icon: <Database className="h-5 w-5" />, title: "Real Data Pipeline", desc: "Upload CSV/XLSX — scan, analyze, predict, alert in real-time", color: "#4ade80" },
  { icon: <ShieldCheck className="h-5 w-5" />, title: "Evidence Integrity", desc: "SHA-256 hashed audit trail with tamper-evident ledger", color: "#38bdf8" },
];

/* ── Pipeline Flow ─────────────────────────────────────────────────── */

const PIPELINE = ["SCAN", "UNDERSTAND", "PREDICT", "LOCATE", "ALERT", "INTERVENE"];

/* ── Landing Page ──────────────────────────────────────────────────── */

export default function Home() {
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="relative min-h-screen overflow-hidden" style={{ background: "var(--surface)" }}>
      <NetworkCanvas />

      {/* Top bar */}
      <nav className="relative z-10 flex items-center justify-between px-6 py-4 lg:px-12">
        <Logo size={32} />
        <div className="flex items-center gap-3">
          <button onClick={toggleTheme} className="rounded-lg p-2 transition-colors" style={{ color: "var(--on-surface-muted)" }}>
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <Link to="/login" className="btn-ghost text-xs">
            Sign In
          </Link>
          <Link to="/register" className="btn-primary text-xs">
            Get Started
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative z-10 mx-auto max-w-7xl px-6 pt-16 pb-24 lg:px-12 lg:pt-24">
        <div className="grid items-center gap-12 lg:grid-cols-2">
          {/* Left — Text */}
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-electric-500/30 bg-electric-500/10 px-4 py-1.5">
              <Shield className="h-3.5 w-3.5 text-electric-400" />
              <span className="text-[11px] font-semibold uppercase tracking-wider text-electric-400">
                SIH 2026 · SIH26184
              </span>
            </div>

            <h1 className="text-4xl font-black leading-tight tracking-tight text-white lg:text-5xl xl:text-6xl">
              <span className="bg-gradient-to-r from-electric-400 via-cyber-cyan to-cyber-purple bg-clip-text text-transparent">
                CYBERSENTINEL
              </span>
              <span className="bg-gradient-to-r from-cyber-cyan to-cyber-purple bg-clip-text text-transparent">
                {" "}X
              </span>
            </h1>

            <h2 className="mt-4 text-lg font-semibold lg:text-xl" style={{ color: "var(--on-surface)" }}>
              Predict Cybercrime. Locate Risk. Enable Proactive Intervention.
            </h2>

            <p className="mt-4 max-w-xl text-sm leading-relaxed" style={{ color: "var(--on-surface-muted)" }}>
              AI-powered cybercrime intelligence that transforms complaints and financial signals
              into predictive, geospatial, and actionable intelligence. Built for the Smart India
              Hackathon 2026 under problem statement SIH26184.
            </p>

            {/* Pipeline flow */}
            <div className="mt-8 flex flex-wrap items-center gap-2">
              {PIPELINE.map((step, i) => (
                <div key={step} className="flex items-center gap-2">
                  <span className="rounded-lg border px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider" style={{ borderColor: "var(--surface-border)", background: "var(--surface-raised)", color: "var(--on-surface-muted)" }}>
                    {step}
                  </span>
                  {i < PIPELINE.length - 1 && (
                    <ArrowRight className="h-3 w-3 text-electric-500/50" />
                  )}
                </div>
              ))}
            </div>

            {/* CTAs */}
            <div className="mt-8 flex flex-wrap gap-4">
              <button
                onClick={() => navigate("/dashboard")}
                className="btn-primary px-6 py-3 text-sm"
              >
                <Layers className="h-4 w-4" />
                Launch Intelligence Center
              </button>
              <button
                onClick={() => navigate("/login?demo=1")}
                className="btn-ghost px-6 py-3 text-sm"
              >
                <Play className="h-4 w-4" />
                Run Demo Scenario
              </button>
            </div>

            {/* Stats */}
            <div className="mt-10 grid grid-cols-3 gap-6">
              {[
                { value: "Multi-Model", label: "ML Ensemble" },
                { value: "Real-Time", label: "Event Pipeline" },
                { value: "< 100ms", label: "Prediction Latency" },
              ].map((s) => (
                <div key={s.label}>
                  <p className="font-mono text-lg font-bold text-electric-400">{s.value}</p>
                  <p className="text-[11px]" style={{ color: "var(--on-surface-faint)" }}>{s.label}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Right — Globe */}
          <div className="flex justify-center lg:justify-end">
            <GlobeViz />
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="relative z-10 mx-auto max-w-7xl px-6 pb-24 lg:px-12">
        <h3 className="mb-8 text-center text-sm font-bold uppercase tracking-[0.3em]" style={{ color: "var(--on-surface-faint)" }}>
          Core Capabilities
        </h3>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="glass glass-hover group cursor-default p-5"
            >
              <div
                className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg"
                style={{ background: `${f.color}1a`, color: f.color }}
              >
                {f.icon}
              </div>
              <h4 className="text-sm font-bold" style={{ color: "var(--on-surface)" }}>
                {f.title}
              </h4>
              <p className="mt-1.5 text-xs leading-relaxed" style={{ color: "var(--on-surface-faint)" }}>
                {f.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 border-t px-6 py-6 text-center" style={{ borderColor: "var(--surface-border)" }}>
        <p className="text-[11px]" style={{ color: "var(--on-surface-faint)" }}>
          CyberSentinel-X · Predictive Financial Cybercrime Intelligence · Smart India Hackathon 2026 · SIH26184
        </p>
        <p className="mt-1 text-[10px]" style={{ color: "var(--on-surface-faint)" }}>
          Synthetic / Demo Data — Not real government statistics
        </p>
      </footer>
    </div>
  );
}
