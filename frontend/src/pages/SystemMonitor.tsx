import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Cpu, HardDrive, RefreshCcw, Server, Zap } from "lucide-react";
import { api } from "../services/api";
import { Card, Skeleton, StatCard } from "../components/ui";

interface SystemData {
  status: string;
  uptime: string;
  system: {
    platform: string;
    python_version: string;
    cpu_percent: number;
    memory_percent: number;
    memory_total_gb: number;
    memory_used_gb: number;
    disk_percent: number;
  };
  ml_engine: {
    loaded: boolean;
    feature_version: string;
    models: string[];
    total_predictions: number;
    avg_latency_ms: number;
    p50_latency_ms: number;
    p95_latency_ms: number;
    p99_latency_ms: number;
  };
  dataset: {
    total_complaints: number;
    total_transactions: number;
  };
  timestamp: string;
}

function MeterBar({ value, color, label }: { value: number; color: string; label: string }) {
  const pct = Math.min(100, Math.max(0, value));
  const barColor = pct > 85 ? '#f87171' : pct > 60 ? '#facc15' : color;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-[11px] text-slate-400">{label}</span>
        <span className="font-mono text-xs" style={{ color: barColor }}>{pct.toFixed(1)}%</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-night-800">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: barColor, boxShadow: `0 0 8px ${barColor}` }} />
      </div>
    </div>
  );
}

export default function SystemMonitor() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['system-monitor'],
    queryFn: async () => (await api.get('/api/v2/monitoring/system')).data as SystemData,
    refetchInterval: 30000,
  });

  const { data: perfData, isLoading: perfLoading } = useQuery({
    queryKey: ['perf-monitor'],
    queryFn: async () => (await api.get('/api/v2/monitoring/performance')).data,
    refetchInterval: 60000,
  });

  if (isLoading || !data) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <div className="grid gap-5 lg:grid-cols-2">
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
        </div>
      </div>
    );
  }

  const { system, ml_engine, status, uptime } = data;

  return (
    <div className="space-y-5">
      {/* Status Banner */}
      <div className={`flex items-center gap-3 rounded-xl border p-4 ${
        status === 'healthy'
          ? 'border-cyber-green/30 bg-cyber-green/5'
          : 'border-cyber-red/30 bg-cyber-red/5'
      }`}>
        <div className={`flex h-10 w-10 items-center justify-center rounded-full ${
          status === 'healthy' ? 'bg-cyber-green/20' : 'bg-cyber-red/20'
        }`}>
          <Activity className={`h-5 w-5 ${status === 'healthy' ? 'text-cyber-green' : 'text-cyber-red'}`} />
        </div>
        <div>
          <h2 className={`text-sm font-bold ${status === 'healthy' ? 'text-cyber-green' : 'text-cyber-red'}`}>
            System {status === 'healthy' ? 'Healthy' : 'Unhealthy'}
          </h2>
          <p className="text-xs text-slate-500">Uptime: {uptime} | Python {system.python_version}</p>
        </div>
        <button onClick={() => refetch()} className="ml-auto btn-ghost">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="System CPU" value={`${system.cpu_percent}%`} color={system.cpu_percent > 80 ? "#f87171" : "#38bdf8"} icon={<Cpu className="h-4 w-4" />} />
        <StatCard label="Memory Usage" value={`${system.memory_used_gb}GB / ${system.memory_total_gb}GB`} color={system.memory_percent > 80 ? "#f87171" : "#a78bfa"} icon={<MemoryStick className="h-4 w-4" />} />
        <StatCard label="Disk Usage" value={`${system.disk_percent}%`} color={system.disk_percent > 80 ? "#f87171" : "#22d3ee"} icon={<HardDrive className="h-4 w-4" />} />
        <StatCard label="ML Predictions" value={ml_engine.total_predictions} color="#4ade80" icon={<Zap className="h-4 w-4" />} />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* System Resources */}
        <Card title="🖥️ System Resources" subtitle={`Running on ${system.platform}`}>
          <div className="space-y-4">
            <MeterBar value={system.cpu_percent} color="#38bdf8" label="CPU Usage" />
            <MeterBar value={system.memory_percent} color="#a78bfa" label="Memory Usage" />
            <MeterBar value={system.disk_percent} color="#22d3ee" label="Disk Usage" />
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="rounded-lg bg-night-850/50 p-3">
                <p className="text-[10px] uppercase text-slate-500">Memory Total</p>
                <p className="font-mono text-sm text-slate-200">{system.memory_total_gb} GB</p>
              </div>
              <div className="rounded-lg bg-night-850/50 p-3">
                <p className="text-[10px] uppercase text-slate-500">Available</p>
                <p className="font-mono text-sm text-slate-200">{(system.memory_total_gb - system.memory_used_gb).toFixed(1)} GB</p>
              </div>
            </div>
          </div>
        </Card>

        {/* ML Engine Status */}
        <Card title="🤖 ML Engine Status" subtitle={`Feature version: ${ml_engine.feature_version}`}>
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <span className={`h-2.5 w-2.5 rounded-full ${ml_engine.loaded ? 'bg-green-400' : 'bg-red-400'}`} />
              <span className="text-sm font-medium text-slate-200">
                {ml_engine.loaded ? 'Models Loaded' : 'Not Loaded'}
              </span>
            </div>
            {ml_engine.loaded && (
              <>
                <div className="flex flex-wrap gap-2">
                  {ml_engine.models.map((m) => (
                    <span key={m} className="badge border border-electric-500/30 bg-electric-500/10 text-electric-400 text-[10px]">
                      {m}
                    </span>
                  ))}
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: 'Avg Latency', value: `${ml_engine.avg_latency_ms}ms`, color: '#4ade80' },
                    { label: 'P95 Latency', value: `${ml_engine.p95_latency_ms}ms`, color: '#38bdf8' },
                    { label: 'P99 Latency', value: `${ml_engine.p99_latency_ms}ms`, color: '#f87171' },
                    { label: 'Total Predictions', value: ml_engine.total_predictions.toLocaleString(), color: '#a78bfa' },
                  ].map(item => (
                    <div key={item.label} className="rounded-lg bg-night-850/50 p-3">
                      <p className="text-[10px] uppercase text-slate-500">{item.label}</p>
                      <p className="font-mono text-sm font-bold" style={{ color: item.color }}>{item.value}</p>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </Card>
      </div>

      {/* Performance Benchmarks */}
      <Card title="⚡ Performance Benchmarks" subtitle="P50, P90, P95, P99 latency percentiles">
        {perfLoading ? (
          <Skeleton className="h-40" />
        ) : perfData?.latency_ms ? (
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            {[
              { label: 'Minimum', value: perfData.latency_ms.min, color: '#4ade80' },
              { label: 'P50 (Median)', value: perfData.latency_ms.median, color: '#38bdf8' },
              { label: 'P90', value: perfData.latency_ms.p90, color: '#22d3ee' },
              { label: 'P95', value: perfData.latency_ms.p95, color: '#facc15' },
              { label: 'P99', value: perfData.latency_ms.p99, color: '#fb923c' },
            ].map(m => (
              <div key={m.label} className="rounded-lg border border-night-700/70 bg-night-850/50 p-4 text-center">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">{m.label}</p>
                <p className="mt-1 font-mono text-2xl font-bold" style={{ color: m.color }}>{m.value}<span className="text-xs font-normal">ms</span></p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-center text-sm text-slate-500">Performance data not available</p>
        )}
        {perfData && (
          <div className="mt-4 flex items-center justify-between rounded-lg border border-night-700/50 bg-night-850/30 p-3">
            <span className="text-xs text-slate-400">Throughput</span>
            <span className="font-mono text-lg font-bold text-cyber-green">
              {perfData.throughput_per_second} <span className="text-xs">predictions/second</span>
            </span>
          </div>
        )}
      </Card>

      {/* Dataset & API Status */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="📊 Dataset Statistics" subtitle="Synthetic cybercrime intelligence data">
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg bg-night-850/50 p-4 text-center">
              <p className="text-[10px] uppercase text-slate-500">Total Complaints</p>
              <p className="font-mono text-2xl font-bold text-electric-400">{data.dataset.total_complaints.toLocaleString()}</p>
            </div>
            <div className="rounded-lg bg-night-850/50 p-4 text-center">
              <p className="text-[10px] uppercase text-slate-500">Total Transactions</p>
              <p className="font-mono text-2xl font-bold text-cyber-purple">{data.dataset.total_transactions.toLocaleString()}</p>
            </div>
          </div>
        </Card>

        <Card title="🔗 API Endpoints" subtitle="CyberSentinel V2 API">
          <div className="space-y-2">
            {[
              { method: 'POST', path: '/api/v2/scan', desc: 'Cybercrime Scanner' },
              { method: 'POST', path: '/api/v2/predict', desc: 'Predictive Engine' },
              { method: 'POST', path: '/api/v2/analyze/anomaly', desc: 'Anomaly Detection' },
              { method: 'GET',  path: '/api/v2/model/info', desc: 'Model Info' },
              { method: 'GET',  path: '/api/v2/geospatial/hotspots', desc: 'Geo Hotspots' },
              { method: 'POST', path: '/api/v2/what-if', desc: 'Scenario Simulator' },
              { method: 'GET',  path: '/api/v2/monitoring/system', desc: 'System Monitor' },
            ].map((ep, i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg bg-night-850/50 px-3 py-2">
                <span className={`w-12 text-center font-mono text-[10px] font-bold ${
                  ep.method === 'POST' ? 'text-cyber-green' : 'text-electric-400'
                }`}>{ep.method}</span>
                <span className="flex-1 font-mono text-xs text-slate-300">{ep.path}</span>
                <span className="text-[10px] text-slate-500">{ep.desc}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <p className="text-center text-[11px] text-slate-600">
        System metrics refresh every 30 seconds · Performance benchmarks refresh every 60 seconds
      </p>
    </div>
  );
}
