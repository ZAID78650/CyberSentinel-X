import { Navigate, Route, Routes } from "react-router-dom";
import AppLayout from "./layouts/AppLayout";
import { useAuth } from "./contexts/AuthContext";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import OAuthCallback from "./pages/OAuthCallback";
import Dashboard from "./pages/Dashboard";
import LiveEvents from "./pages/LiveEvents";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import RiskOverview from "./pages/RiskOverview";
import Investigation from "./pages/Investigation";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import AttackGraph from "./pages/AttackGraph";
import AttackDna from "./pages/AttackDna";
import EvidenceLedger from "./pages/EvidenceLedger";
import WarRoom from "./pages/WarRoom";
import ThreatHunting from "./pages/ThreatHunting";
import Campaigns from "./pages/Campaigns";
import CampaignDetail from "./pages/CampaignDetail";
import AssetRisk from "./pages/AssetRisk";
import GlobalSearch from "./pages/GlobalSearch";
import AttackSimulator from "./pages/AttackSimulator";
import ModelCenter from "./pages/ModelCenter";
import ComplianceCenter from "./pages/ComplianceCenter";
import MalwareAnalysis from "./pages/MalwareAnalysis";
import ResponseCenter from "./pages/ResponseCenter";
import HumanApprovals from "./pages/HumanApprovals";
import ActionsLog from "./pages/ActionsLog";
import IncidentReports from "./pages/IncidentReports";
import Analytics from "./pages/Analytics";
import DataSources from "./pages/DataSources";
import Settings from "./pages/Settings";
import DefenseCenter from "./pages/DefenseCenter";
import Assets from "./pages/Assets";
import Playbooks from "./pages/Playbooks";
import MitreMatrix from "./pages/MitreMatrix";
import JudgeMode from "./pages/JudgeMode";
import SBOM from "./pages/SBOM";
import ThreatAnalyzer from "./pages/ThreatAnalyzer";
import EntityDetail from "./pages/EntityDetail";
import AdminUsers from "./pages/AdminUsers";
import GisHeatmap from "./pages/GisHeatmap";
import PredictiveAlerts from "./pages/PredictiveAlerts";
import FinancialIntelligence from "./pages/FinancialIntelligence";
import LeaDashboard from "./pages/LeaDashboard";

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
  return (
    <Routes>
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
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/live-events" element={<LiveEvents />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<Incidents />} />
        <Route path="/risk-overview" element={<RiskOverview />} />
        <Route path="/investigation" element={<Investigation />} />
        <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
        <Route path="/attack-graph" element={<AttackGraph />} />
        <Route path="/attack-dna" element={<AttackDna />} />
        <Route path="/evidence-ledger" element={<EvidenceLedger />} />
        <Route path="/incidents/:id/war-room" element={<WarRoom />} />
        <Route path="/threat-hunting" element={<ThreatHunting />} />
        <Route path="/campaigns" element={<Campaigns />} />
        <Route path="/campaigns/:id" element={<CampaignDetail />} />
        <Route path="/asset-risk" element={<AssetRisk />} />
        <Route path="/search" element={<GlobalSearch />} />
        <Route path="/attack-simulator" element={<AttackSimulator />} />
        <Route path="/model-center" element={<ModelCenter />} />
        <Route path="/compliance" element={<ComplianceCenter />} />
        <Route path="/malware-analysis" element={<MalwareAnalysis />} />
        <Route path="/response-center" element={<ResponseCenter />} />
        <Route path="/human-approvals" element={<HumanApprovals />} />
        <Route path="/actions-log" element={<ActionsLog />} />
        <Route path="/incident-reports" element={<IncidentReports />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/data-sources" element={<DataSources />} />
        <Route path="/defense-center" element={<DefenseCenter />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/playbooks" element={<Playbooks />} />
        <Route path="/mitre-matrix" element={<MitreMatrix />} />
        <Route path="/judge-mode" element={<JudgeMode />} />
        <Route path="/sbom" element={<SBOM />} />
        <Route path="/threat-analyzer" element={<ThreatAnalyzer />} />
        <Route path="/entity/:entityType/:value" element={<EntityDetail />} />
        <Route path="/admin/users" element={<AdminUsers />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/gis-heatmap" element={<GisHeatmap />} />
        <Route path="/predictive-alerts" element={<PredictiveAlerts />} />
        <Route path="/financial-intelligence" element={<FinancialIntelligence />} />
        <Route path="/lea-dashboard" element={<LeaDashboard />} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
