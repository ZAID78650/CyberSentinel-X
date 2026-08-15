"""Full pipeline test: simulation -> detection -> investigation -> risk ->
attack graph -> recommendations -> approval -> report."""
import json

from sqlalchemy import select

from app.core.utils import to_uuid
from app.agents.detection_agent import DetectionAgent
from app.agents.investigation_agent import InvestigationAgent
from app.agents.threat_intel_agent import ThreatIntelAgent
from app.attack_graph.builder import build_attack_graph, build_attack_graph_full
from app.attack_graph.validate import validate_attack_graph
from app.core.database import SessionLocal
from app.models.security import Incident
from app.reports.generator import generate_report
from app.response.engine import decide_approval, generate_recommendations
from app.risk.engine import compute_risk
from app.services.event_service import ingest_batch
from app.services.simulator import build_scenario_events


def _run_scenario(scenario: str):
    db = SessionLocal()
    try:
        payloads = build_scenario_events(scenario)
        events = ingest_batch(db, payloads, source="test-sim")
        detection = DetectionAgent(db)
        result = detection.evaluate_batch(events, actor="pytest")
        assert result["incident"], f"scenario {scenario} did not create an incident"
        incident_id = result["incident"]
        incident = db.get(Incident, to_uuid(incident_id))
        assert incident is not None
        return db, incident
    except Exception:
        db.close()
        raise


def test_account_takeover_full_pipeline():
    db, incident = _run_scenario("account-takeover")
    try:
        # Investigation
        agent = InvestigationAgent(db, str(incident.id))
        inv_result = agent.investigate(str(incident.id))
        assert inv_result["verdict"] is not None
        assert inv_result["confidence"] > 50
        assert len(inv_result["evidence"]) >= 4
        assert len(inv_result["mitre_mappings"]) >= 2
        assert any("T1110" in m or "T1078" in m for m in inv_result["mitre_mappings"])

        # Threat intel enrichment
        intel = ThreatIntelAgent(db, str(incident.id)).enrich(str(incident.id))
        assert len(intel["hits"]) >= 1  # 45.155.205.233 is in the local feed

        # Risk
        risk = compute_risk(db, str(incident.id))
        assert 0 <= risk["score"] <= 100
        assert risk["severity_label"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(risk["factors"]) == 5
        assert abs(sum(f["weight"] for f in risk["factors"]) - 1.0) < 0.01

        # Attack graph
        nodes, edges = build_attack_graph(db, str(incident.id))
        assert len(nodes) >= 4
        assert len(edges) >= 3
        assert any(n["node_type"] == "USER" for n in nodes)

        # Recommendations + approvals
        recs = generate_recommendations(db, str(incident.id))
        assert len(recs) >= 3
        assert any(r.action == "Revoke active user sessions" for r in recs)
        approvals = list(db.scalars(select(__import__("app.models.investigation", fromlist=["ApprovalRequest"]).ApprovalRequest)
                                    .where(__import__("app.models.investigation", fromlist=["ApprovalRequest"]).ApprovalRequest.incident_id == incident.id)))
        assert len(approvals) >= 1

        # Approval -> simulated execution
        first_approval = approvals[0]
        result = decide_approval(db, str(first_approval.id), "APPROVED", "pytest@test.io", "approved by test")
        assert result["status"] == "APPROVED"
        assert result["execution_summary"]

        # Report generation with PDF
        report = generate_report(db, str(incident.id), actor="pytest")
        assert report.report_id.startswith("RPT-")
        assert report.pdf_path
        assert json.loads(json.dumps(report.content))  # JSON serializable
        assert report.content["incident"]["incident_id"] == incident.incident_id

        # Reject flow
        second = [a for a in approvals if a.status == "PENDING"]
        if second:
            r2 = decide_approval(db, str(second[0].id), "REJECTED", "pytest@test.io")
            assert r2["status"] == "REJECTED"
    finally:
        db.close()


def test_attack_graph_enrichment_stats_and_critical_path():
    """Enriched graph: risk-weighted nodes, stats, and a critical path."""
    db, incident = _run_scenario("data-exfiltration")
    try:
        nodes, edges, stats, path = build_attack_graph_full(db, str(incident.id))
        assert stats["total_nodes"] == len(nodes) >= 4
        assert stats["total_edges"] == len(edges) >= 3
        assert stats["node_types"]["USER"] >= 1
        assert stats["density"] >= 0.0
        assert stats["crown_jewel"]
        assert stats["crown_jewel_risk"] > 0

        # Risk + timestamps on every node
        for n in nodes:
            props = n["properties"]
            assert 0 <= props.get("risk_score", 0) <= 100
            assert props.get("risk_label") in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert "event_count" in props
            if n["node_type"] in ("ASSET", "DATABASE"):
                assert props.get("criticality", 0) >= 1

        # Critical path reaches the crown jewel with explicit risk
        assert path["nodes"]
        assert path["node_labels"]
        assert path["total_risk"] > 0
        assert path["nodes"][-1] == stats["crown_jewel"]
    finally:
        db.close()


def test_attack_graph_accuracy_audit():
    """Validator scans: evidence grounding, schema, MITRE, timeline, determinism."""
    db, incident = _run_scenario("brute-force")
    try:
        # Run an investigation so MITRE mappings exist (technique nodes grounded)
        from app.agents.investigation_agent import InvestigationAgent
        InvestigationAgent(db, str(incident.id)).investigate(str(incident.id))

        audit = validate_attack_graph(db, str(incident.id))
        assert 0 <= audit["accuracy_score"] <= 100
        assert audit["label"] in ("HIGH", "GOOD", "MODERATE", "WEAK")
        assert len(audit["checks"]) == 5
        assert {c["name"] for c in audit["checks"]} == {
            "Evidence grounding", "Edge schema validity", "MITRE consistency",
            "Timeline consistency", "Determinism",
        }
        assert abs(sum(c["weight"] for c in audit["checks"]) - 1.0) < 0.01
        assert audit["counts"]["nodes"] >= 4
        assert audit["counts"]["grounded_nodes"] >= 3
        assert all(f["check"] for f in audit["findings"])  # findings carry their check
        assert audit["method"].startswith("Weighted audit")
    finally:
        db.close()


def test_all_scenarios_create_incidents():
    for scenario in ["brute-force", "malware", "data-exfiltration", "privilege-escalation"]:
        db, incident = _run_scenario(scenario)
        assert incident.severity in ("HIGH", "CRITICAL"), f"{scenario}: {incident.severity}"
        db.close()


def test_response_agent_recommend_end_to_end():
    """The Response Agent's recommend() must work with a plain incident-id string
    (regression: UUID column compared to str raised 'str' has no attribute 'hex')."""
    db, incident = _run_scenario("brute-force")
    try:
        from app.agents.response_agent import ResponseAgent
        agent = ResponseAgent(db, str(incident.id))
        result = agent.recommend(str(incident.id))
        assert result["recommendations"] >= 3
        assert result["pending_approvals"] >= 1
    finally:
        db.close()


def test_incident_status_progression():
    db, incident = _run_scenario("malware")
    try:
        InvestigationAgent(db, str(incident.id)).investigate(str(incident.id))
        incident.status = "CONTAINED"
        db.commit()
        assert incident.status == "CONTAINED"
    finally:
        db.close()
