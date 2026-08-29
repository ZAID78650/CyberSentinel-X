import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import AppLayout from "./layouts/AppLayout";
import { useAuth } from "./contexts/AuthContext";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { useKeepAlive } from "./hooks/useKeepAlive";

// ── Lazy-loaded pages (code-split into separate chunks) ───────────────
const Home = lazy(() => import("./pages/Home"));
const Login = lazy(() => import("./pages/Login"));
const Register = lazy(() => import("./pages/Register"));
const ForgotPassword = lazy(() => import("./pages/ForgotPassword"));
const OAuthCallback = lazy(() => import("./pages/OAuthCallback"));

// Command Center
const Dashboard = lazy(() => import("./pages/Dashboard"));
const CybercrimeScanner = lazy(() => import("./pages/CybercrimeScanner"));
const SihDemo = lazy(() => import("./pages/SihDemo"));

// Financial Intelligence
const FinancialIntelligence = lazy(() => import("./pages/FinancialIntelligence"));
const PredictiveAlerts = lazy(() => import("./pages/PredictiveAlerts"));
const GisHeatmap = lazy(() => import("./pages/GisHeatmap"));
const ThreatGlobe = lazy(() => import("./pages/ThreatGlobe"));
const EntityNetwork = lazy(() => import("./pages/EntityNetwork"));

// Alerts & Incidents
const Alerts = lazy(() => import("./pages/Alerts"));
const Incidents = lazy(() => import("./pages/Incidents"));
const LeaDashboard = lazy(() => import("./pages/LeaDashboard"));
const LiveEvents = lazy(() => import("./pages/LiveEvents"));

// Investigation & Cases
const Investigation = lazy(() => import("./pages/Investigation"));
const EvidenceLedger = lazy(() => import("./pages/EvidenceLedger"));
const IncidentReports = lazy(() => import("./pages/IncidentReports"));

// ML & Analytics
const ModelPerformance = lazy(() => import("./pages/ModelPerformance"));
const WhatIfSimulation = lazy(() => import("./pages/WhatIfSimulation"));
const Analytics = lazy(() => import("./pages/Analytics"));
const SystemMonitor = lazy(() => import("./pages/SystemMonitor"));

// Advanced Modules
const ThreatIntelligence = lazy(() => import("./pages/ThreatIntelligence"));
const RiskOverview = lazy(() => import("./pages/RiskOverview"));
const AttackDna = lazy(() => import("./pages/AttackDna"));
const AttackGraph = lazy(() => import("./pages/AttackGraph"));
const Campaigns = lazy(() => import("./pages/Campaigns"));
const CampaignDetail = lazy(() => import("./pages/CampaignDetail"));
const DataSources = lazy(() => import("./pages/DataSources"));
const ResponseCenter = lazy(() => import("./pages/ResponseCenter"));
const MalwareAnalysis = lazy(() => import("./pages/MalwareAnalysis"));

// Other modules
const AssetRisk = lazy(() => import("./pages/AssetRisk"));
const GlobalSearch = lazy(() => import("./pages/GlobalSearch"));
const AttackSimulator = lazy(() => import("./pages/AttackSimulator"));
const ModelCenter = lazy(() => import("./pages/ModelCenter"));
const ComplianceCenter = lazy(() => import("./pages/ComplianceCenter"));
const HumanApprovals = lazy(() => import("./pages/HumanApprovals"));
const ActionsLog = lazy(() => import("./pages/ActionsLog"));
const DefenseCenter = lazy(() => import("./pages/DefenseCenter"));
const Assets = lazy(() => import("./pages/Assets"));
const Playbooks = lazy(() => import("./pages/Playbooks"));
const MitreMatrix = lazy(() => import("./pages/MitreMatrix"));
const JudgeMode = lazy(() => import("./pages/JudgeMode"));
const SBOM = lazy(() => import("./pages/SBOM"));
const ThreatAnalyzer = lazy(() => import("./pages/ThreatAnalyzer"));
const WarRoom = lazy(() => import("./pages/WarRoom"));
const ThreatHunting = lazy(() => import("./pages/ThreatHunting"));
const EntityDetail = lazy(() => import("./pages/EntityDetail"));

// Admin
const AdminUsers = lazy(() => import("./pages/AdminUsers"));
const Settings = lazy(() => import("./pages/Settings"));
const SecuritySettings = lazy(() => import("./pages/SecuritySettings"));

// ── Loading fallback ──────────────────────────────────────────────────
function PageLoader() {
  return (
    <div className="flex h-64 items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-electric-500 border-t-transparent" />
        <p className="text-xs text-slate-500">Loading…</p>
      </div>
    </div>
  );
}

function Protected({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function PublicOnly({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

export default function App() {
  useKeepAlive();

  return (
    <ErrorBoundary>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<PublicOnly><Login /></PublicOnly>} />
          <Route path="/register" element={<PublicOnly><Register /></PublicOnly>} />
          <Route path="/forgot-password" element={<PublicOnly><ForgotPassword /></PublicOnly>} />
          <Route path="/oauth/callback" element={<OAuthCallback />} />

          <Route
            element={
              <Protected>
                <AppLayout />
              </Protected>
            }
          >
            {/* Command Center */}
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/cybercrime-scanner" element={<CybercrimeScanner />} />
            <Route path="/sih-demo" element={<SihDemo />} />

            {/* Financial Intelligence */}
            <Route path="/financial-intelligence" element={<FinancialIntelligence />} />
            <Route path="/predictive-alerts" element={<PredictiveAlerts />} />
            <Route path="/gis-heatmap" element={<GisHeatmap />} />
            <Route path="/threat-globe" element={<ThreatGlobe />} />
            <Route path="/entity-network" element={<EntityNetwork />} />

            {/* Alerts & Incidents */}
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<Incidents />} />
            <Route path="/lea-dashboard" element={<LeaDashboard />} />
            <Route path="/live-events" element={<LiveEvents />} />

            {/* Investigation & Cases */}
            <Route path="/investigation" element={<Investigation />} />
            <Route path="/evidence-ledger" element={<EvidenceLedger />} />
            <Route path="/incident-reports" element={<IncidentReports />} />

            {/* ML & Analytics */}
            <Route path="/model-performance" element={<ModelPerformance />} />
            <Route path="/what-if" element={<WhatIfSimulation />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/monitoring" element={<SystemMonitor />} />

            {/* Advanced Modules */}
            <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
            <Route path="/risk-overview" element={<RiskOverview />} />
            <Route path="/attack-dna" element={<AttackDna />} />
            <Route path="/attack-graph" element={<AttackGraph />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/campaigns/:id" element={<CampaignDetail />} />
            <Route path="/data-sources" element={<DataSources />} />
            <Route path="/response-center" element={<ResponseCenter />} />
            <Route path="/malware-analysis" element={<MalwareAnalysis />} />

            {/* Other */}
            <Route path="/asset-risk" element={<AssetRisk />} />
            <Route path="/search" element={<GlobalSearch />} />
            <Route path="/attack-simulator" element={<AttackSimulator />} />
            <Route path="/model-center" element={<ModelCenter />} />
            <Route path="/compliance" element={<ComplianceCenter />} />
            <Route path="/human-approvals" element={<HumanApprovals />} />
            <Route path="/actions-log" element={<ActionsLog />} />
            <Route path="/defense-center" element={<DefenseCenter />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/playbooks" element={<Playbooks />} />
            <Route path="/mitre-matrix" element={<MitreMatrix />} />
            <Route path="/judge-mode" element={<JudgeMode />} />
            <Route path="/sbom" element={<SBOM />} />
            <Route path="/threat-analyzer" element={<ThreatAnalyzer />} />
            <Route path="/incidents/:id/war-room" element={<WarRoom />} />
            <Route path="/threat-hunting" element={<ThreatHunting />} />
            <Route path="/entity/:entityType/:value" element={<EntityDetail />} />

            {/* Admin */}
            <Route path="/admin/users" element={<AdminUsers />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/security-settings" element={<SecuritySettings />} />
          </Route>

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
