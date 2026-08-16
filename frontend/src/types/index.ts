// Shared API types mirroring the backend schemas

export interface User {
  id: string;
  email: string;
  full_name: string;
  organization?: string | null;
  is_active: boolean;
  is_verified: boolean;
  last_login_at?: string | null;
  oauth_provider?: string | null;
  has_password?: boolean;
  created_at?: string | null;
  roles: string[];
}

export interface Tokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthResponse {
  user: User;
  tokens: Tokens;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface SecurityEvent {
  id: string;
  event_id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  user_id?: string | null;
  device_id?: string | null;
  asset_id?: string | null;
  source: string;
  metadata?: Record<string, unknown> | null;
  anomaly_score?: number | null;
  is_anomalous: boolean;
  detection_reason?: string | null;
}

export interface Alert {
  id: string;
  alert_id: string;
  title: string;
  description?: string | null;
  severity: string;
  status: string;
  category: string;
  confidence: number;
  anomaly_score?: number | null;
  detection_reason?: string | null;
  source_event_ids: string[];
  created_at: string;
}

export interface Incident {
  id: string;
  incident_id: string;
  title: string;
  description?: string | null;
  severity: string;
  status: string;
  confidence: number;
  risk_score?: number | null;
  risk_label?: string | null;
  category: string;
  alert_id?: string | null;
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
}

export interface EvidenceItem {
  category: string;
  description: string;
  source: string;
  detail?: Record<string, unknown> | null;
}

export interface Investigation {
  id: string;
  incident_id: string;
  status: string;
  started_at: string;
  completed_at?: string | null;
  summary?: string | null;
  verdict?: string | null;
  confidence: number;
  timeline: Array<Record<string, unknown>>;
  evidence_summary: Array<Record<string, unknown>>;
  agent_run_id?: string | null;
}

export interface InvestigationDetail {
  investigation: Investigation;
  evidence: EvidenceItem[];
  mitre_mappings: Array<{
    technique_id: string;
    name: string;
    tactic: string;
    confidence: number;
    evidence?: string | null;
  }>;
}

export interface AttackNode {
  id: string;
  node_key: string;
  node_type: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface AttackEdge {
  id: string;
  source_key: string;
  target_key: string;
  edge_type: string;
  properties: Record<string, unknown>;
}

export interface GraphStats {
  total_nodes: number;
  total_edges: number;
  node_types: Record<string, number>;
  edge_types: Record<string, number>;
  density: number;
  max_depth: number;
  crown_jewel?: string | null;
  crown_jewel_risk?: number | null;
  events_analyzed?: number;
  attackers?: number;
  users?: number;
  techniques?: number;
  assets?: number;
}

export interface CriticalPath {
  nodes: string[];
  node_labels: string[];
  edge_types: string[];
  total_risk: number;
}

export interface AttackGraph {
  incident_id: string;
  nodes: AttackNode[];
  edges: AttackEdge[];
  stats?: GraphStats | null;
  critical_path?: CriticalPath | null;
}

export interface GraphValidationCheck {
  name: string;
  pass_rate: number;
  weight: number;
  detail: string;
}

export interface GraphFinding {
  item: string;
  issue: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  check: string;
}

export interface MalwareArtifact {
  family: string;
  category: string;
  capability: string;
  aliases: string[];
  severity: string;
  confidence: number;
  detection_count: number;
  hashes: string[];
  c2_domains: string[];
  cves: string[];
  processes: string[];
  mitre_techniques: string[];
  affected_assets: string[];
  affected_users: string[];
  affected_devices: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  block_actions: Array<{ indicator: string; kind: string; action: string }>;
}

export interface MalwareScan {
  scanned_at: string;
  artifacts: MalwareArtifact[];
  summary: {
    artifacts_detected: number;
    families: number;
    unique_hashes: number;
    c2_domains: number;
    cves: number;
    detection_events: number;
    severity_distribution: Record<string, number>;
  };
  intel_sources: string[];
  note: string;
}

export interface UploadedDataset {
  name: string;
  source: "uploaded" | "unsw";
  path: string;
  size_bytes: number;
  rows: number;
  columns: string[];
  uploaded_at?: string | null;
}

export interface DatasetScanMatch {
  kind: string;
  value: string;
  confidence: number;
  severity: string;
  source: string;
  count: number;
}

export interface DatasetScanArtifact {
  family: string;
  category: string;
  capability: string;
  severity: string;
  confidence: number;
  detection_count: number;
  hashes: string[];
  c2_domains: string[];
  cves: string[];
  ips: string[];
  processes: string[];
  mitre_techniques: string[];
  matched_indicators: DatasetScanMatch[];
  detection_basis: string;
}

export interface DatasetScanResult {
  dataset: string;
  scanned_at: string;
  rows_scanned: number;
  columns: string[];
  matched_rows: number;
  artifacts: DatasetScanArtifact[];
  summary: {
    artifacts_detected: number;
    families: number;
    indicator_matches: number;
    matched_rows: number;
    indicator_types: Record<string, number>;
  };
  note: string;
}

export interface PreventionLayer {
  layer: string;
  stage: string;
  controls: string[];
}

export interface PreventionTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  detection: string;
  severity_hint: string;
}

export interface RemediationPhase {
  phase: string;
  actions: string[];
}

export interface MalwarePrevention {
  family: string;
  category: string;
  capability: string;
  kill_chain_attack: string[];
  layered_defense: PreventionLayer[];
  mitre_techniques: PreventionTechnique[];
  remediation_runbook: RemediationPhase[];
  indicators_to_block: Array<{ indicator: string; kind: string; action: string }>;
  how_it_gets_in: string[];
  provenance: string;
}

export interface GraphValidation {
  incident_id: string;
  accuracy_score: number;
  label: "HIGH" | "GOOD" | "MODERATE" | "WEAK";
  method: string;
  checks: GraphValidationCheck[];
  findings: GraphFinding[];
  counts: {
    nodes: number;
    edges: number;
    grounded_nodes: number;
    phantom_nodes: number;
    mapped_techniques: number;
    technique_nodes: number;
  };
  scanned_at: string;
}

export interface RiskFactor {
  name: string;
  weight: number;
  score: number;
  contribution: number;
  evidence: string;
}

export interface Risk {
  incident_id: string;
  score: number;
  severity_label: string;
  confidence: number;
  factors: RiskFactor[];
  reason: string;
  computed_at: string;
}

export interface Recommendation {
  id: string;
  incident_id: string;
  action: string;
  impact: string;
  reason?: string | null;
  evidence?: string | null;
  requires_approval: boolean;
  status: string;
  created_at: string;
  executed_at?: string | null;
  execution_summary?: string | null;
}

export interface Approval {
  id: string;
  incident_id: string;
  recommendation_id: string;
  requested_by: string;
  status: string;
  decision_by?: string | null;
  decision_at?: string | null;
  reason?: string | null;
  created_at: string;
  recommendation_action?: string | null;
  incident_title?: string | null;
  incident_severity?: string | null;
}

export interface ThreatIndicator {
  id: string;
  indicator_type: string;
  value: string;
  confidence: number;
  severity: string;
  source: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  description?: string | null;
}

export interface MitreTechnique {
  id: string;
  technique_id: string;
  name: string;
  tactic: string;
  description?: string | null;
  detection?: string | null;
  severity_hint: string;
  platforms: string[];
  url?: string | null;
}

export interface Report {
  id: string;
  incident_id: string;
  report_id: string;
  title: string;
  created_at: string;
  created_by?: string | null;
}

export interface ReportDetail {
  report: Report;
  content: Record<string, unknown>;
  pdf_available: boolean;
  pdf_url?: string | null;
}

export interface KpiCard {
  label: string;
  value: number;
  change?: number | null;
  trend?: string | null;
  color?: string | null;
}

export interface AgentStatus {
  name: string;
  status: string;
  last_run?: string | null;
  detail?: string | null;
}

export interface DashboardSummary {
  kpis: KpiCard[];
  alerts_by_severity: Record<string, number>;
  alerts_by_category: Record<string, number>;
  risk_over_time: Array<{ date: string; avg_risk: number }>;
  top_threat_sources: Array<{ source: string; count: number }>;
  recent_events: Array<Record<string, unknown>>;
  recent_incidents: Incident[];
  agent_statuses: AgentStatus[];
  ai_investigation_summary?: {
    incident_id: string;
    incident_title: string;
    summary: string;
    verdict: string;
    confidence: number;
  } | null;
  response_recommendation?: {
    incident_id: string;
    action: string;
    impact: string;
    status: string;
  } | null;
}

export interface DetectionAccuracy {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  total_events: number;
  attack_events: number;
  benign_events: number;
  method: string;
  evaluated_at: string;
}

export interface Analytics {
  events_total: number;
  events_by_type: Record<string, number>;
  alerts_total: number;
  alerts_by_severity: Record<string, number>;
  alerts_by_category: Record<string, number>;
  incidents_total: number;
  incidents_by_status: Record<string, number>;
  risk_over_time: Array<{ date: string; avg_risk: number }>;
  top_threat_sources: Array<{ source: string; count: number }>;
  top_attack_techniques: Array<{ technique_id: string; name: string; tactic: string; count: number }>;
  actions_executed: number;
  approvals_pending: number;
  detection_accuracy?: DetectionAccuracy | null;
}

export interface FirewallLayer {
  layer: string;
  name: string;
  description: string;
  color: string;
  status: string;
  blocked: number;
  passed: number;
}

export interface FirewallSummary {
  layers: FirewallLayer[];
  total_blocked: number;
  total_passed: number;
  total_requests: number;
  protection_level: string;
}

export interface FirewallBlock {
  ts: number;
  layer: string;
  method: string;
  path: string;
  source_ip: string;
  indicator?: string | null;
  detail: string;
}

export interface FirewallBlockLog {
  blocks: FirewallBlock[];
}

export interface EntityDetail {
  entity: string;
  entity_type: string;
  events: number;
  risk: number;
  band: string;
  components: Record<string, number>;
  ueba: {
    risk: number;
    status: string;
    factors: Array<{ name: string; score: number; evidence: string }>;
    baseline_events: number;
    current_events: number;
    note: string;
  };
  features: {
    off_hours_ratio: number;
    failed_ratio: number;
    distinct_devices: number;
    distinct_ips: number;
    anomaly_ratio: number;
    rate_per_hour: number;
  };
  intel_hits: number;
  intel: Array<{ value: string; indicator_type: string; severity: string; confidence: number; source: string; match_reason: string }>;
  related_incidents: Array<{ id: string; incident_id: string; title: string; severity: string; status: string; risk_score?: number | null }>;
  asset?: {
    name: string;
    asset_type: string;
    ip_address?: string | null;
    hostname?: string | null;
    criticality: number;
    owner?: string | null;
  } | null;
  recent_events: Array<{
    event_id: string;
    timestamp: string | null;
    event_type: string;
    severity: string;
    is_anomalous: boolean;
    detection_reason?: string | null;
  }>;
  note: string;
}

export interface PlaybookSimulation {
  simulation: boolean;
  playbook: { id: string; title: string; doc_type: string; source: string };
  affected_assets: Array<{
    name: string;
    asset_type: string;
    criticality: number;
    ip_address?: string | null;
    exposure: number;
    exposure_after: number;
    reduction_points: number;
    reduction_pct: number;
    anomalous_events: number;
    intel_hits: number;
    observed: boolean;
  }>;
  asset_count: number;
  exposure_before: number;
  exposure_after: number;
  projected_reduction_pct: number;
  reduction_ratio: number;
  control_signals: string[];
  provenance: { mode: string; basis: string };
  note: string;
}

export interface AssetItem {
  id: string;
  name: string;
  asset_type: string;
  ip_address?: string | null;
  hostname?: string | null;
  criticality: number;
  owner?: string | null;
  description?: string | null;
}

export interface PlaybookDoc {
  id: string;
  title: string;
  source: string;
  doc_type: string;
  chunk_count: number;
  tags: string[];
  content_preview: string;
}

export interface OAuthProviderStatus {
  provider: string;
  name: string;
  configured: boolean;
}

export interface SimulationResult {
  scenario: string;
  events_ingested: number;
  suspicious_count: number;
  alert_id: string | null;
  incident_id: string | null;
  severity: string | null;
  pipeline: string;
  message: string;
}

export interface ActionLogEntry {
  id: string;
  actor: string;
  action: string;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown> | null;
  ip_address?: string | null;
  created_at: string;
}

export interface DatasetFileInfo {
  name: string;
  path: string;
  exists: boolean;
}

export interface DatasetStatus {
  configured: boolean;
  dataset_dir: string;
  files: DatasetFileInfo[];
  ingest_limit: number;
  stats: {
    events_total: number;
    unsw_events: number;
    attack_flows: number;
    normal_flows: number;
    alerts: number;
    incidents: number;
    by_category: Record<string, number>;
    by_severity: Record<string, number>;
  };
  progress: {
    running: boolean;
    total_rows: number;
    processed_rows: number;
    inserted_rows: number;
    attack_flows: number;
    alerts_created: number;
    incidents_created: number;
    started_at?: string | null;
    finished_at?: string | null;
    last_error?: string | null;
  };
}

export interface ThreatPoint {
  x: number;
  y: number;
  z: number;
  spkts?: number;
  dpkts?: number;
  category: string;
  severity: string;
  is_anomalous: boolean;
  anomaly_score?: number | null;
  event_type: string;
  source_ip?: string | null;
  timestamp?: string | null;
}

export type DataProvenance = "LIVE" | "DATASET" | "SIMULATED" | "LOCAL" | "MODEL" | "UNKNOWN";

export interface EvidenceRecordItem {
  id: string;
  evidence_id: string;
  incident_id?: string | null;
  evidence_type: string;
  title: string;
  description?: string | null;
  chain_index: number;
  prev_hash: string;
  content_hash: string;
  record_hash: string;
  status: string;
  data_source: string;
  created_by: string;
  verified_at?: string | null;
  created_at: string;
  meta?: Record<string, unknown> | null;
}

export interface LedgerBlockItem {
  block_index: number;
  prev_block_hash: string;
  records_digest: string;
  nonce: number;
  block_hash: string;
  record_count: number;
  mined_at: string;
  evidence_ids: string[];
  difficulty?: number | null;
}

export interface LedgerVerifyReport {
  integrity: string;
  valid: boolean;
  evidence_records: number;
  evidence_verified: number;
  evidence_tampered: string[];
  ledger_blocks: number;
  ledger_blocks_valid: number;
  issues: string[];
  audited_at: string;
  method: string;
}

export interface AttackDnaItem {
  id: string;
  dna_id: string;
  incident_id: string;
  fingerprint: string;
  family: string;
  confidence: number;
  severity: string;
  risk_score?: number | null;
  techniques: Array<{ id: string; name: string }>;
  behaviors: string[];
  features: {
    vector?: number[];
    event_count?: number;
    source_ips?: string[];
    dest_ips?: string[];
    anomaly_mean?: number;
  };
  historical_similarity?: number | null;
  similar_to?: string | null;
  created_at: string;
  similar_attacks?: Array<{
    dna_id: string;
    incident_id: string;
    family: string;
    severity: string;
    confidence: number;
    risk_score?: number | null;
    fingerprint: string;
    behaviors: string[];
    techniques: string[];
    similarity: number;
    created_at: string;
  }>;
}

export interface AttackPredictionItem {
  id: string;
  incident_id: string;
  current_stage: string;
  predicted_stage: string;
  probability: number;
  confidence: number;
  recommended_control?: string | null;
  rationale?: string | null;
  model_version: string;
  is_prediction: boolean;
  created_at: string;
}

export interface HuntResult {
  query: string;
  generated_filters: string[];
  confidence: number;
  scope: string;
  counts: { events: number; alerts: number; incidents: number };
  results: {
    events: Array<{
      event_id: string; timestamp: string; event_type: string; severity: string;
      source_ip?: string | null; destination_ip?: string | null; user_id?: string | null;
      asset_id?: string | null; anomaly_score?: number | null; is_anomalous: boolean; detection_reason?: string | null;
    }>;
    alerts: Array<{ id: string; alert_id: string; title: string; severity: string; status: string; category: string; confidence: number; created_at: string }>;
    incidents: Array<{ id: string; incident_id: string; title: string; severity: string; status: string; category: string; risk_score?: number | null; created_at: string }>;
  };
}

export interface BlastRadius {
  incident_id: string;
  blast_radius: string;
  affected_assets: number;
  affected_users: number;
  affected_databases: number;
  critical_services: number;
  assets: string[];
  users: string[];
  path: Array<{ node: string; type: string }>;
  estimate: boolean;
  method: string;
}

export interface Campaign {
  campaign_id: string;
  source: string;
  category: string;
  incidents: string[];
  incident_count: number;
  event_count: number;
  techniques: string[];
  severity: string;
  first_seen: string;
  last_seen: string;
  duration_hours: number;
  risk_score: number;
}

export interface CampaignsResponse {
  campaigns: Campaign[];
  funnel: {
    events: number; alerts: number; incidents: number; campaigns: number;
    dedup_ratio: number; alerts_per_incident: number;
  };
  note: string;
}

export interface AssetRiskRow {
  id: string;
  name: string;
  asset_type: string;
  ip_address?: string | null;
  criticality: number;
  risk_score: number;
  risk_label: string;
  active_alerts: number;
  anomalous_events: number;
  incident_count: number;
  last_seen?: string | null;
}

export interface AssetRiskResponse {
  assets: AssetRiskRow[];
  average_risk: number;
  critical_assets_at_risk: number;
  method: string;
}

export interface GlobalSearchResult {
  query: string;
  total: number;
  results: {
    incidents: Array<{ id: string; incident_id: string; title: string; severity: string; status: string; risk_score?: number | null }>;
    alerts: Array<{ id: string; alert_id: string; title: string; severity: string; status: string; category: string }>;
    events: Array<{ event_id: string; timestamp: string; event_type: string; severity: string; source_ip?: string | null; destination_ip?: string | null; user_id?: string | null; anomaly_score?: number | null }>;
    dna: Array<{ id: string; dna_id: string; family: string; incident_id: string; confidence: number; fingerprint: string }>;
    techniques: Array<{ id: string; technique_id: string; name: string; tactic: string; severity_hint: string }>;
    evidence: Array<{ id: string; evidence_id: string; title: string; evidence_type: string; status: string }>;
  };
}

export interface SimStage {
  stage: string;
  state: "SIMULATED";
  probability: number;
  exposure: string;
  controls: string[];
}

export interface AttackSimulation {
  simulation: boolean;
  asset: { name: string; type: string; criticality: number; ip?: string | null };
  scenario: string;
  starting_stage: string;
  kill_chain: SimStage[];
  risk_before: number;
  risk_after: number;
  affected_assets_before: number;
  affected_assets_after: number;
  incidents_on_asset: number;
  note: string;
}

export interface LiveTimelineEvent {
  event_type: string;
  severity: string;
  is_anomalous: boolean;
  stage?: string | null;
  reason?: string | null;
  timestamp: string;
}

export interface LiveScenarioResult {
  simulation: boolean;
  asset: { name: string; type: string; ip?: string | null };
  starting_stage: string;
  chain: string[];
  events_ingested: number;
  anomalous_count: number;
  alert_id?: string | null;
  incident_id?: string | null;
  incident?: string | null;
  severity?: string | null;
  pipeline: "started" | "not-started";
  timeline: LiveTimelineEvent[];
  note: string;
}

export interface ResilienceFactor {
  name: string;
  score: number;
  weight: number;
  evidence: string;
}

export interface CyberResilience {
  resilience_score: number;
  label: "STRONG" | "MODERATE" | "WEAK";
  factors: ResilienceFactor[];
  explanation: string;
  computed_at: string;
}

export interface ComplianceGap {
  control: string;
  techniques: string[];
  missing: string[];
}

export interface ComplianceFramework {
  framework: string;
  posture: number;
  controls_covered: number;
  controls_total: number;
  gaps: ComplianceGap[];
}

export interface CompliancePosture {
  overall_posture: number;
  observed_techniques: string[];
  frameworks: ComplianceFramework[];
  method: string;
  computed_at: string;
}
