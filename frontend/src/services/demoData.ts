/**
 * Demo mock data for all API endpoints.
 * Used when the backend server is unreachable (demo mode).
 */

export function getDemoData(url: string): unknown | null {
  // Dashboard summary
  if (url.includes("/dashboard/summary")) {
    return {
      kpis: [
        { label: "Complaints Analyzed", value: 8421, color: "#38bdf8" },
        { label: "Transactions Processed", value: "1.84M", color: "#a78bfa" },
        { label: "High-Risk Cases", value: 1274, color: "#f87171" },
        { label: "Predicted Hotspots", value: 342, color: "#fb923c" },
        { label: "Active Alerts", value: 87, color: "#facc15" },
        { label: "Prediction Confidence", value: "91.4%", color: "#4ade80" },
      ],
      alerts_by_severity: { CRITICAL: 12, HIGH: 34, MEDIUM: 28, LOW: 13 },
      alerts_by_category: { "Phishing": 42, "Account Takeover": 23, "UPI Fraud": 18, "Card Skimming": 12, "Identity Theft": 8, "Money Mule": 5 },
      risk_over_time: [
        { date: "Mon", avg_risk: 45 }, { date: "Tue", avg_risk: 52 },
        { date: "Wed", avg_risk: 68 }, { date: "Thu", avg_risk: 72 },
        { date: "Fri", avg_risk: 61 }, { date: "Sat", avg_risk: 48 },
        { date: "Sun", avg_risk: 55 },
      ],
      top_threat_sources: [
        { source: "103.25.48.12", count: 47 },
        { source: "49.36.128.77", count: 34 },
        { source: "182.75.96.41", count: 28 },
        { source: "106.207.143.8", count: 21 },
        { source: "202.88.241.15", count: 16 },
      ],
      recent_events: [],
      recent_incidents: [
        { id: "1", incident_id: "INC-2026-0841", title: "Suspicious ATM Withdrawal Cluster — Mumbai Zone 14", severity: "CRITICAL", status: "INVESTIGATING", confidence: 0.91, risk_score: 87, risk_label: "HIGH", category: "Financial Fraud", created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
        { id: "2", incident_id: "INC-2026-0839", title: "Phishing Campaign — SBI Customers Targeted", severity: "HIGH", status: "OPEN", confidence: 0.84, risk_score: 72, risk_label: "HIGH", category: "Phishing", created_at: new Date(Date.now() - 3600000).toISOString(), updated_at: new Date().toISOString() },
        { id: "3", incident_id: "INC-2026-0835", title: "UPI Fraud Ring — Delhi NCR", severity: "HIGH", status: "RESOLVED", confidence: 0.79, risk_score: 65, risk_label: "MEDIUM", category: "UPI Fraud", created_at: new Date(Date.now() - 7200000).toISOString(), updated_at: new Date().toISOString() },
      ],
      agent_statuses: [
        { name: "Detection Agent", status: "ONLINE" },
        { name: "Investigation Agent", status: "ONLINE" },
        { name: "Threat Intel Agent", status: "ONLINE" },
        { name: "Risk Engine", status: "RUNNING" },
        { name: "Response Agent", status: "ONLINE" },
      ],
      ai_investigation_summary: {
        incident_id: "INC-2026-0841",
        incident_title: "Suspicious ATM Withdrawal Cluster — Mumbai Zone 14",
        summary: "ML analysis identified a pattern of 18 related complaints in Mumbai Zone 14, with transaction velocity spikes and geographic clustering. Model predicts high probability of cash withdrawal within the next 3 hours.",
        verdict: "HIGH RISK",
        confidence: 91,
      },
      response_recommendation: null,
    };
  }

  // Detection accuracy
  if (url.includes("/security/detection-accuracy")) {
    return { accuracy: 94.2, precision: 92.8, recall: 95.1, f1: 93.9 };
  }

  // Financial dashboard
  if (url.includes("/financial/dashboard")) {
    return {
      summary: {
        total_complaints: 8421,
        total_amount: 18700000,
        avg_complaint_amount: 22212,
        high_risk_zones: 12,
        total_zones: 34,
        suspicious_transactions: 3821,
        active_alerts: 87,
        unique_accounts: 1247,
      },
      time_series: [
        { month: "Jan", complaints: 520, amount: 1200000 }, { month: "Feb", complaints: 610, amount: 1450000 },
        { month: "Mar", complaints: 780, amount: 1890000 }, { month: "Apr", complaints: 850, amount: 2100000 },
        { month: "May", complaints: 920, amount: 2350000 }, { month: "Jun", complaints: 1100, amount: 2800000 },
        { month: "Jul", complaints: 1280, amount: 3200000 }, { month: "Aug", complaints: 1361, amount: 3710000 },
      ],
      fraud_breakdown: [
        { type: "Phishing", count: 2100, percentage: 24.9 }, { type: "UPI Fraud", count: 1680, percentage: 20.0 },
        { type: "Account Takeover", count: 1260, percentage: 15.0 }, { type: "Card Skimming", count: 1010, percentage: 12.0 },
        { type: "Identity Theft", count: 842, percentage: 10.0 }, { type: "Money Mule", count: 674, percentage: 8.0 },
      ],
      state_breakdown: [
        { state: "Maharashtra", count: 1850 }, { state: "Delhi", count: 1420 }, { state: "Karnataka", count: 1180 },
        { state: "Tamil Nadu", count: 980 }, { state: "Uttar Pradesh", count: 870 },
      ],
      risk_distribution: { CRITICAL: 4, HIGH: 8, MEDIUM: 14, LOW: 8 },
      top_alerts: [
        { alert_id: "ALT-0841", risk_level: "CRITICAL", risk_probability: 0.91, predicted_zone: "Mumbai Zone 14", crime_pattern: "ATM Withdrawal Cluster", confidence: 0.87, related_complaints: 18 },
        { alert_id: "ALT-0839", risk_level: "HIGH", risk_probability: 0.84, predicted_zone: "Delhi Zone 3", crime_pattern: "Phishing Campaign", confidence: 0.81, related_complaints: 14 },
      ],
    };
  }

  // Financial predictions
  if (url.includes("/financial/predictions")) {
    return {
      alerts: [
        { alert_id: "ALT-0841", risk_probability: 0.91, predicted_zone: "Mumbai Zone 14", crime_pattern: "ATM Withdrawal Cluster", confidence: 0.87, related_complaints: 18 },
        { alert_id: "ALT-0839", risk_probability: 0.84, predicted_zone: "Delhi Zone 3", crime_pattern: "Phishing Campaign", confidence: 0.81, related_complaints: 14 },
        { alert_id: "ALT-0835", risk_probability: 0.79, predicted_zone: "Bangalore Zone 7", crime_pattern: "UPI Fraud Ring", confidence: 0.76, related_complaints: 11 },
      ],
    };
  }

  // GIS Heatmap
  if (url.includes("/financial/heatmap")) {
    return {
      zones: [
        { zone_id: "Z14", name: "Mumbai Zone 14", lat: 19.076, lng: 72.8777, risk: 0.91, level: "CRITICAL", complaints: 18, amount: 875000, confidence: 0.87, time_window: "18:00–21:00", features: {} },
        { zone_id: "Z03", name: "Delhi Zone 3", lat: 28.6139, lng: 77.209, risk: 0.84, level: "HIGH", complaints: 14, amount: 654000, confidence: 0.81, time_window: "20:00–23:00", features: {} },
        { zone_id: "Z07", name: "Bangalore Zone 7", lat: 12.9716, lng: 77.5946, risk: 0.79, level: "HIGH", complaints: 11, amount: 523000, confidence: 0.76, time_window: "16:00–19:00", features: {} },
        { zone_id: "Z22", name: "Chennai Zone 22", lat: 13.0827, lng: 80.2707, risk: 0.72, level: "HIGH", complaints: 9, amount: 412000, confidence: 0.72, time_window: "19:00–22:00", features: {} },
        { zone_id: "Z11", name: "Hyderabad Zone 11", lat: 17.385, lng: 78.4867, risk: 0.65, level: "MEDIUM", complaints: 7, amount: 321000, confidence: 0.68, time_window: "17:00–20:00", features: {} },
      ],
      total_zones: 34,
      high_risk_count: 12,
    };
  }

  // Alerts
  if (url.includes("/alerts") && url.includes("page=")) {
    return {
      items: [
        { id: "1", alert_id: "ALT-0841", title: "Potential ATM Withdrawal Risk — Mumbai Zone 14", severity: "CRITICAL", status: "OPEN", category: "Financial Fraud", confidence: 0.91, source_event_ids: ["evt-1", "evt-2"], created_at: new Date().toISOString() },
        { id: "2", alert_id: "ALT-0839", title: "Phishing Campaign Detected — SBI Domain", severity: "HIGH", status: "OPEN", category: "Phishing", confidence: 0.84, source_event_ids: ["evt-3"], created_at: new Date(Date.now() - 3600000).toISOString() },
        { id: "3", alert_id: "ALT-0835", title: "Suspicious UPI Transaction Velocity", severity: "HIGH", status: "INVESTIGATING", category: "UPI Fraud", confidence: 0.79, source_event_ids: ["evt-4", "evt-5"], created_at: new Date(Date.now() - 7200000).toISOString() },
      ],
      total: 87,
      page: 1,
      page_size: 20,
      pages: 5,
    };
  }

  // Incidents
  if (url.includes("/incidents")) {
    return {
      items: [
        { id: "1", incident_id: "INC-2026-0841", title: "Suspicious ATM Withdrawal Cluster", severity: "CRITICAL", status: "INVESTIGATING", confidence: 0.91, risk_score: 87, risk_label: "HIGH", category: "Financial Fraud", created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
        { id: "2", incident_id: "INC-2026-0839", title: "Phishing Campaign — SBI Customers", severity: "HIGH", status: "OPEN", confidence: 0.84, risk_score: 72, risk_label: "HIGH", category: "Phishing", created_at: new Date(Date.now() - 3600000).toISOString(), updated_at: new Date().toISOString() },
      ],
      total: 47,
      page: 1,
      page_size: 10,
      pages: 5,
    };
  }

  // Events live
  if (url.includes("/events/live")) {
    return [];
  }

  // Feedback stats
  if (url.includes("/analytics/feedback-stats")) {
    return {
      signals_before_correlation: 847,
      alerts_after_correlation: 87,
      correlation_ratio: 9.7,
      labeled_alerts: 24,
      label_counts: { TRUE_POSITIVE: 18, FALSE_POSITIVE: 4, BENIGN: 2 },
      false_positive_rate: 0.167,
      precision: 0.818,
      category_stats: [],
      applied_settings: [],
      provenance: { mode: "demo", basis: "synthetic" },
    };
  }

  // Model performance
  if (url.includes("/api/v2/model/info")) {
    return {
      models: { classifier: { version: "1.0.0", trained: true }, regressor: { version: "1.0.0", trained: true } },
      performance: { total_predictions: 1247, avg_latency_ms: 84, p50_latency_ms: 72, p95_latency_ms: 126, p99_latency_ms: 198 },
      feature_importance: { top_features: [{ name: "velocity_24h", importance: 0.23 }, { name: "zone_risk", importance: 0.19 }, { name: "amount", importance: 0.15 }], total_features: 42 },
      model_info: {},
      data_leakage_prevention: {},
      evaluation_metrics: {},
      timestamp: new Date().toISOString(),
    };
  }

  // Threat Space 3D
  if (url.includes("/dashboard/threat-space")) {
    const categories = ["Reconnaissance", "Fuzzers", "Analysis", "Backdoor", "DoS", "Exploits", "Generic", "Shellcode", "Worms"];
    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const points = Array.from({ length: 200 }, (_, i) => ({
      x: Math.random() * 8,
      y: Math.random() * 8,
      z: Math.random() * 6,
      category: categories[i % categories.length],
      severity: severities[i % severities.length],
      is_anomalous: i % 7 === 0,
      anomaly_score: i % 7 === 0 ? 0.7 + Math.random() * 0.3 : Math.random() * 0.4,
      event_type: ["UDP", "TCP", "ICMP"][i % 3],
      source_ip: `103.${i % 255}.${(i * 3) % 255}.${(i * 7) % 255}`,
      spkts: Math.floor(Math.random() * 1000),
      dpkts: Math.floor(Math.random() * 5000),
      timestamp: new Date(Date.now() - i * 60000).toISOString(),
    }));
    return points;
  }

  // Attack Distribution 3D
  if (url.includes("/dashboard/attack-distribution")) {
    const categories = ["Reconnaissance", "Fuzzers", "Analysis", "Backdoor", "DoS", "Exploits", "Generic", "Shellcode", "Worms"];
    const cells: Array<{ category: string; hour: number; count: number }> = [];
    for (const cat of categories) {
      for (let h = 0; h < 24; h++) {
        const peak = cat === "DoS" ? 14 : cat === "Exploits" ? 3 : 10;
        const count = Math.max(0, Math.floor(50 * Math.exp(-0.5 * Math.pow((h - peak) / 4, 2)) + Math.random() * 20));
        cells.push({ category: cat, hour: h, count });
      }
    }
    return cells;
  }

  // Events Time Series
  if (url.includes("/dashboard/events-timeseries")) {
    return Array.from({ length: 48 }, (_, i) => {
      const d = new Date(Date.now() - (47 - i) * 3600_000);
      d.setMinutes(0, 0, 0);
      return { time: d.toISOString(), total: Math.floor(Math.random() * 80 + 10), anomalous: Math.floor(Math.random() * 15 + 1) };
    });
  }

  // Dashboard v2
  if (url.includes("/api/v2/dashboard/v2")) {
    return getDemoData("/dashboard/summary");
  }

  // Dataset uploads list
  if (url.includes("/dataset/uploads")) {
    return {
      datasets: [
        { name: "demo_cybercrime_aug2026.csv", rows: 48294, source: "SIH Demo" },
      ],
    };
  }

  // Health
  if (url.includes("/health") || url.includes("/ready")) {
    return { status: "healthy", version: "1.0.0", demo_mode: true };
  }

  // Default — return null to indicate no demo data available
  return null;
}

/**
 * Demo data for POST endpoints (matched by URL substring).
 */
export function getDemoPostData(url: string, _body?: unknown): unknown | null {
  if (url.includes("/v2/scan")) {
    return {
      scan_id: "SCAN-" + Date.now().toString(36).toUpperCase(),
      status: "completed",
      summary: {
        total_rows: 48294,
        matched_rows: 3821,
        artifacts_found: 247,
        data_quality_score: 91,
        scan_time_ms: 1820,
        ml_available: true,
      },
      phases: {
        ingestion: { status: "completed", rows: 48294 },
        normalization: { status: "completed", rows: 48294 },
        quality: { status: "completed", rows: 48294 },
        transaction: { status: "completed", rows: 41832 },
        anomaly: { status: "completed", rows: 3821 },
        correlation: { status: "completed", artifacts: 8421 },
        geospatial: { status: "completed", rows: 412 },
        prediction: { status: "completed", rows: 34 },
        intelligence: { status: "completed", artifacts: 87 },
      },
      data_quality: {
        score: 91,
        grade: "A",
        completeness: 95.8,
        uniqueness: 97.2,
        missing_columns: { "location": 4.2, "account_id": 1.1, "timestamp": 0.3 },
        duplicate_percentage: 0.7,
      },
      enrichment: {
        threat_count: 247,
        severity_distribution: { "CRITICAL": 12, "HIGH": 34, "MEDIUM": 28, "LOW": 13 },
        unique_hashes: 89,
        unique_ips: 156,
        unique_domains: 43,
        mitre_techniques: ["T1566", "T1078", "T1059", "T1021", "T1048", "T1098"],
      },
      ml_analysis: {},
      scan_time_ms: 1820,
    };
  }
  return null;
}
