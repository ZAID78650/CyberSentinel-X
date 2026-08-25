"""Automated incident report generation (HTML + PDF)."""
import html
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.utils import to_uuid

from app.models.investigation import (
    ActionLog,
    AIAgentRun,
    ApprovalRequest,
    IncidentReport,
    Investigation,
    ResponseRecommendation,
)
from app.models.security import Incident, IncidentEvent, SecurityEvent
from app.risk.engine import get_latest_risk
from app.services.mitre_service import list_incident_mappings

logger = logging.getLogger(__name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "reports")


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "—"


def _resolve_incident(db: Session, incident_id: str) -> Incident:
    """Resolve an incident by UUID pk, incident_id string, or partial match."""
    # 1. Try UUID primary key first
    uid = to_uuid(incident_id)
    if uid is not None:
        incident = db.scalar(select(Incident).where(Incident.id == uid))
        if incident is not None:
            return incident
    # 2. Try incident_id string field (what the dashboard sends)
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is not None:
        return incident
    # 3. Try partial match on incident_id (escape SQL wildcards to prevent injection)
    if len(incident_id) >= 8:
        escaped = incident_id.replace('%', '\\%').replace('_', '\\_')
        safe_pattern = '%' + escaped + '%'
        incident = db.scalar(
            select(Incident).where(Incident.incident_id.ilike(safe_pattern))
        )
        if incident is not None:
            return incident
    # 4. Fallback: get the most recent incident (for demo/single-incident scenarios)
    incident = db.scalar(select(Incident).order_by(Incident.created_at.desc()))
    if incident is not None:
        return incident
    raise ValueError(f"Incident not found: {incident_id}")


def build_report_content(db: Session, incident: Incident) -> Dict[str, Any]:
    uid = incident.id
    incident_events = list(db.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == uid)
    ).all())
    event_ids = [ie.event_id for ie in incident_events]
    events: List[SecurityEvent] = []
    if event_ids:
        events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))).all())

    risk = get_latest_risk(db, str(incident.id))
    mappings = list_incident_mappings(db, str(incident.id))
    recommendations = list(db.scalars(
        select(ResponseRecommendation).where(ResponseRecommendation.incident_id == uid)
    ).all())
    approvals = list(db.scalars(
        select(ApprovalRequest).where(ApprovalRequest.incident_id == uid)
    ).all())
    investigation = db.scalar(
        select(Investigation).where(Investigation.incident_id == uid).order_by(Investigation.created_at.desc())
    )
    agent_runs = list(db.scalars(
        select(AIAgentRun).where(AIAgentRun.incident_id == str(incident.id)).order_by(AIAgentRun.created_at.desc())
    ).all())
    audit = list(db.scalars(
        select(ActionLog).order_by(ActionLog.created_at.desc()).limit(50)
    ).all())

    timeline = []
    for e in sorted(events, key=lambda x: x.timestamp):
        timeline.append({
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "severity": e.severity,
            "source_ip": e.source_ip,
            "user_id": e.user_id,
            "detail": (e.metadata_ or {}),
        })

    return {
        "incident": {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity or "MEDIUM",
            "status": incident.status or "OPEN",
            "category": incident.category or "GENERIC",
            "confidence": incident.confidence or 0.5,
            "created_at": _fmt(incident.created_at),
            "resolved_at": _fmt(incident.resolved_at),
        },
        "risk": risk or {"score": 0, "severity_label": "LOW", "confidence": 0.5, "factors": [], "reason": "N/A"},
        "affected": {
            "users": sorted({e.user_id for e in events if e.user_id}),
            "devices": sorted({e.device_id for e in events if e.device_id}),
            "ips": sorted({e.source_ip for e in events if e.source_ip}),
            "assets": sorted({e.asset_id for e in events if e.asset_id}),
        },
        "timeline": timeline,
        "mitre": mappings or [],
        "investigation": {
            "summary": investigation.summary if investigation else None,
            "verdict": investigation.verdict if investigation else None,
            "confidence": investigation.confidence if investigation else 0.0,
        },
        "recommendations": [
            {"action": r.action, "impact": r.impact, "status": r.status, "evidence": r.evidence} for r in recommendations
        ],
        "approvals": [
            {"requested_by": a.requested_by, "status": a.status, "decision_by": a.decision_by, "reason": a.reason}
            for a in approvals
        ],
        "agent_runs": [
            {"agent_name": r.agent_name, "status": r.status, "tools_used": r.tools_used,
             "result_summary": r.result_summary} for r in agent_runs
        ],
        "audit": [
            {"actor": a.actor, "action": a.action, "created_at": a.created_at.isoformat()} for a in audit[:30]
        ],
    }


def build_html(content: Dict[str, Any]) -> str:
    inc = content["incident"]
    risk = content["risk"]
    inv = content["investigation"]
    rows = []
    for t in content["timeline"]:
        rows.append(
            f"<tr><td>{html.escape(t['timestamp'])}</td><td>{html.escape(t['event_type'])}</td>"
            f"<td>{html.escape(t['severity'])}</td><td>{html.escape(t.get('source_ip') or '—')}</td>"
            f"<td>{html.escape(t.get('user_id') or '—')}</td></tr>"
        )
    mitre_rows = "".join(
        f"<li><strong>{html.escape(m['technique_id'])}</strong> — {html.escape(m['name'])} "
        f"(<em>{html.escape(m['tactic'])}</em>, confidence {m['confidence']:.0%})</li>"
        for m in content["mitre"]
    ) or "<li>None mapped</li>"
    rec_list = "".join(
        f"<li><strong>{html.escape(r['action'])}</strong> [{html.escape(r['impact'])}] — "
        f"{html.escape(r['status'])}</li>" for r in content["recommendations"]
    ) or "<li>None</li>"
    aff = content["affected"]

    risk_score = risk.get('score', 0) or 0
    risk_label = risk.get('severity_label', 'LOW') or 'LOW'
    risk_conf = risk.get('confidence', 0.5) or 0.5

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CyberSentinel X — Security Incident Report</title>
<style>
body {{ font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 40px; }}
h1 {{ font-size: 26px; color: #0ea5e9; margin-bottom: 4px; }}
h2 {{ font-size: 18px; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin-top: 28px; }}
.meta {{ color: #64748b; font-size: 13px; }}
.grid {{ display: flex; gap: 24px; flex-wrap: wrap; }}
.card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; min-width: 180px; }}
.card .label {{ font-size: 11px; text-transform: uppercase; color: #64748b; }}
.card .value {{ font-size: 20px; font-weight: 700; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th, td {{ border: 1px solid #e2e8f0; padding: 6px 10px; text-align: left; }}
th {{ background: #f1f5f9; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
.badge.CRITICAL {{ background: #fee2e2; color: #b91c1c; }}
.badge.HIGH {{ background: #ffedd5; color: #c2410c; }}
.badge.MEDIUM {{ background: #fef9c3; color: #a16207; }}
.badge.LOW {{ background: #dcfce7; color: #15803d; }}
</style></head><body>
<h1>🛡️ CYBERSENTINEL X</h1>
<p class="meta">SECURITY INCIDENT REPORT — generated {html.escape(_fmt(datetime.now(timezone.utc)))}</p>
<h2>Incident Overview</h2>
<div class="grid">
  <div class="card"><div class="label">Incident ID</div><div class="value">{html.escape(inc['incident_id'])}</div></div>
  <div class="card"><div class="label">Severity</div><div class="value"><span class="badge {html.escape(str(risk_label))}">{html.escape(str(inc.get('severity','MEDIUM')))}</span></div></div>
  <div class="card"><div class="label">Status</div><div class="value">{html.escape(str(inc.get('status','OPEN')))}</div></div>
  <div class="card"><div class="label">Risk Score</div><div class="value">{risk_score} <span class="badge {html.escape(str(risk_label))}">{html.escape(str(risk_label))}</span></div></div>
  <div class="card"><div class="label">Confidence</div><div class="value">{risk_conf:.0%}</div></div>
</div>
<p><strong>Title:</strong> {html.escape(inc.get('title','N/A'))}</p>
<h2>Affected Entities</h2>
<p>Users: {html.escape(', '.join(aff['users']) or '—')}<br>
Devices: {html.escape(', '.join(aff['devices']) or '—')}<br>
IPs: {html.escape(', '.join(aff['ips']) or '—')}<br>
Assets: {html.escape(', '.join(aff['assets']) or '—')}</p>
<h2>Investigation Summary</h2>
<p>{html.escape(inv.get('summary') or 'No investigation summary available.')}</p>
<p><strong>Verdict:</strong> {html.escape(inv.get('verdict') or '—')} &nbsp; <strong>Confidence:</strong> {(inv.get('confidence') or 0.0):.0%}</p>
<h2>Timeline</h2>
<table><tr><th>Timestamp</th><th>Event</th><th>Severity</th><th>Source IP</th><th>User</th></tr>{''.join(rows)}</table>
<h2>MITRE ATT&CK Mapping</h2>
<ul>{mitre_rows}</ul>
<h2>Response Recommendations</h2>
<ul>{rec_list}</ul>
<h2>Approvals</h2>
<ul>{''.join(f"<li>{html.escape(a.get('requested_by','?'))} → {html.escape(a.get('status','?'))} (decided by {html.escape(a.get('decision_by') or '—')})</li>" for a in content.get('approvals',[])) or '<li>None</li>'}</ul>
<h2>AI Agent Runs</h2>
<ul>{''.join(f"<li><strong>{html.escape(r.get('agent_name','?'))}</strong>: {html.escape(r.get('status','?'))} — {html.escape(r.get('result_summary') or '')}</li>" for r in content.get('agent_runs',[])) or '<li>None</li>'}</ul>
<h2>Audit Log (recent)</h2>
<table><tr><th>Time</th><th>Actor</th><th>Action</th></tr>{''.join(f"<tr><td>{html.escape(a.get('created_at','?'))}</td><td>{html.escape(a.get('actor','?'))}</td><td>{html.escape(a.get('action','?'))}</td></tr>" for a in content.get('audit',[]))}</table>
</body></html>"""


def generate_pdf(content: Dict[str, Any], output_path: str) -> None:
    """Render the report to PDF with reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=colors.HexColor("#0ea5e9"), fontSize=22)
    h2 = ParagraphStyle("H2X", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#0f172a"))
    body = ParagraphStyle("BodyX", parent=styles["BodyText"], fontSize=9, leading=12)

    inc = content["incident"]
    risk = content["risk"]
    inv = content["investigation"]
    risk_score = risk.get('score', 0) or 0
    risk_label = risk.get('severity_label', 'LOW') or 'LOW'

    story = [
        Paragraph("🛡️ CYBERSENTINEL X", title_style),
        Paragraph("SECURITY INCIDENT REPORT", styles["Normal"]),
        Spacer(1, 8),
    ]

    overview = [
        ["Incident ID", inc.get("incident_id", "N/A")],
        ["Title", inc.get("title", "N/A")],
        ["Severity", inc.get("severity", "MEDIUM")],
        ["Status", inc.get("status", "OPEN")],
        ["Category", inc.get("category", "GENERIC")],
        ["Risk Score", f"{risk_score} / 100 ({risk_label})"],
        ["Confidence", f"{(risk.get('confidence', 0.5) or 0.5):.0%}"],
        ["Created", inc.get("created_at", "—")],
        ["Resolved", inc.get("resolved_at", "—")],
    ]
    t = Table(overview, colWidths=[1.4 * inch, 4.8 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)

    aff = content["affected"]
    story.append(Paragraph("Affected Entities", h2))
    story.append(Paragraph(
        f"Users: {', '.join(aff['users']) or '—'}<br/>Devices: {', '.join(aff['devices']) or '—'}"
        f"<br/>IPs: {', '.join(aff['ips']) or '—'}<br/>Assets: {', '.join(aff['assets']) or '—'}", body))

    story.append(Paragraph("Investigation Summary", h2))
    story.append(Paragraph(inv.get("summary") or "No investigation summary available.", body))
    story.append(Paragraph(f"<b>Verdict:</b> {inv.get('verdict') or '—'} &nbsp;&nbsp; <b>Confidence:</b> {(inv.get('confidence') or 0.0):.0%}", body))

    story.append(Paragraph("Timeline", h2))
    tl_rows = [["Timestamp", "Event", "Severity", "Source IP", "User"]]
    for titem in content["timeline"][:30]:
        tl_rows.append([titem.get("timestamp", ""), titem.get("event_type", ""), titem.get("severity", ""),
                        titem.get("source_ip") or "—", titem.get("user_id") or "—"])
    tl = Table(tl_rows, colWidths=[1.7 * inch, 1.5 * inch, 0.8 * inch, 1.1 * inch, 1.1 * inch])
    tl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(tl)

    story.append(Paragraph("MITRE ATT&CK Mapping", h2))
    for m in content.get("mitre", []):
        story.append(Paragraph(
            f"<b>{html.escape(m.get('technique_id',''))}</b> — {html.escape(m.get('name',''))} "
            f"(<em>{html.escape(m.get('tactic',''))}</em>, confidence {(m.get('confidence',0) or 0):.0%})", body))

    story.append(Paragraph("Response Recommendations", h2))
    for r in content.get("recommendations", []):
        story.append(Paragraph(f"<b>{html.escape(r.get('action',''))}</b> [{html.escape(r.get('impact',''))}] — {html.escape(r.get('status',''))}", body))

    story.append(Paragraph("AI Agent Runs", h2))
    for r in content.get("agent_runs", []):
        story.append(Paragraph(f"<b>{html.escape(r.get('agent_name',''))}</b>: {html.escape(r.get('status',''))} — {html.escape(r.get('result_summary') or '')}", body))

    story.append(Paragraph("Audit Log (recent)", h2))
    audit_rows = [["Time", "Actor", "Action"]]
    for a in content.get("audit", [])[:20]:
        audit_rows.append([a.get("created_at", ""), a.get("actor", ""), a.get("action", "")])
    at = Table(audit_rows, colWidths=[1.8 * inch, 1.5 * inch, 2.9 * inch])
    at.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
    ]))
    story.append(at)

    SimpleDocTemplate(output_path, pagesize=letter, rightMargin=0.6 * inch, leftMargin=0.6 * inch,
                      topMargin=0.6 * inch, bottomMargin=0.6 * inch).build(story)


def generate_report(db: Session, incident_id: str, actor: str = "report-agent") -> IncidentReport:
    """Generate the report record, HTML and PDF for an incident."""
    incident = _resolve_incident(db, incident_id)

    # Check if a report already exists for this incident
    existing = db.scalar(
        select(IncidentReport).where(IncidentReport.incident_id == incident.id).order_by(IncidentReport.created_at.desc())
    )
    if existing:
        return existing

    # Build report content with fallback
    try:
        content = build_report_content(db, incident)
    except Exception as exc:
        logger.error("Failed to build report content: %s", exc, exc_info=True)
        content = {
            "incident": {
                "incident_id": incident.incident_id,
                "title": incident.title,
                "severity": incident.severity or "MEDIUM",
                "status": incident.status or "OPEN",
                "category": incident.category or "GENERIC",
                "confidence": incident.confidence or 0.5,
                "created_at": _fmt(incident.created_at),
                "resolved_at": _fmt(incident.resolved_at),
            },
            "risk": {"score": incident.risk_score or 0, "severity_label": incident.risk_label or "LOW", "confidence": 0.5, "factors": [], "reason": "Fallback"},
            "affected": {"users": [], "devices": [], "ips": [], "assets": []},
            "timeline": [],
            "mitre": [],
            "investigation": {"summary": None, "verdict": None, "confidence": 0.0},
            "recommendations": [],
            "approvals": [],
            "agent_runs": [],
            "audit": [],
        }

    # Build HTML with fallback
    try:
        html_content = build_html(content)
    except Exception as exc:
        logger.error("HTML generation failed: %s", exc, exc_info=True)
        safe_id = html.escape(str(incident.incident_id))
        html_content = f"<html><body><h1>Report for {safe_id}</h1><p>HTML generation error occurred.</p></body></html>"

    # Generate PDF — non-critical, failures are tolerated
    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
    pdf_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")
    try:
        generate_pdf(content, pdf_path)
    except Exception as exc:
        logger.error("PDF generation failed (non-critical): %s", exc, exc_info=True)
        pdf_path = None

    report = IncidentReport(
        incident_id=incident.id,
        report_id=report_id,
        title=f"Security Incident Report — {incident.incident_id}",
        content=content,
        html_content=html_content,
        pdf_path=pdf_path,
        created_by=actor,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    from app.services.audit import log_action
    log_action(db, actor=actor, action="REPORT.GENERATED", target_type="incident",
               target_id=str(incident_id), detail={"report_id": report_id, "pdf": bool(pdf_path)})
    return report
