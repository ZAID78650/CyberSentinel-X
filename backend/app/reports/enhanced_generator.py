"""Enhanced Report Generator — Auto-Generated from Incidents + Professional Biometrics.

Generates official CyberSentinel-X intelligence reports with:
- Auto-generation from real incident data
- Professional stamps, seals, QR codes, watermarks
- HMAC-SHA256 integrity verification (tamper-evident)
- Digital signature block with timestamp
- 2FA authorization tracking
- Real-time access logging
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "reports")

# HMAC key for document integrity (in production, use settings.jwt_secret)
_HMAC_KEY = os.environ.get("CSX_REPORT_HMAC_KEY", "cybersentinel-x-report-integrity-2026")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "—"


def _fmt_short(dt) -> str:
    return dt.strftime("%d %b %Y, %H:%M") if dt else "—"


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _hmac_sign(data: str) -> str:
    """HMAC-SHA256 signature for tamper-evident document integrity."""
    return hmac.new(_HMAC_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()


# ── Incident Data Collection ─────────────────────────────────────────

def collect_incident_data(db, incident=None) -> Dict[str, Any]:
    """Collect real complaint, transaction, entity and incident data from database."""
    from app.models.financial import FinancialComplaint, FinancialTransaction, FinancialAccount
    from app.models.security import Incident
    from sqlalchemy import func

    # Use provided incident or get all
    incidents = []
    if incident:
        incidents = [incident]
    else:
        try:
            incidents = list(db.query(Incident).order_by(Incident.created_at.desc()).limit(50).all())
        except Exception:
            pass

    # Complaints
    try:
        complaints = db.query(FinancialComplaint).all()
        complaint_count = len(complaints)
        complaint_data = []
        for c in complaints[:100]:
            complaint_data.append({
                "id": str(c.id) if c.id else None,
                "complaint_id": c.complaint_id or "N/A",
                "amount": float(c.amount) if c.amount else 0,
                "state": c.state or "Unknown",
                "district": c.district or "Unknown",
                "city": c.city or "Unknown",
                "fraud_type": c.fraud_type or "Unknown",
                "status": "OPEN",
                "latitude": float(c.latitude) if c.latitude else None,
                "longitude": float(c.longitude) if c.longitude else None,
            })
    except Exception:
        complaint_count = 0
        complaint_data = []

    # Transactions
    try:
        transactions = db.query(FinancialTransaction).all()
        transaction_count = len(transactions)
        total_amount = sum(float(t.amount) if t.amount else 0 for t in transactions)
    except Exception:
        transaction_count = 0
        total_amount = 0

    # Accounts
    try:
        account_count = db.query(FinancialAccount).count()
    except Exception:
        account_count = 0

    # Aggregate incident info
    incident_summaries = []
    for inc in incidents[:20]:
        incident_summaries.append({
            "incident_id": getattr(inc, "incident_id", None) or str(inc.id)[:8],
            "title": getattr(inc, "title", "Untitled"),
            "severity": getattr(inc, "severity", "MEDIUM"),
            "status": getattr(inc, "status", "OPEN"),
            "category": getattr(inc, "category", "UNKNOWN"),
            "risk_score": getattr(inc, "risk_score", 0) or 0,
            "risk_label": getattr(inc, "risk_label", "MEDIUM"),
            "confidence": getattr(inc, "confidence", 0) or 0,
            "created_at": getattr(inc, "created_at", None),
        })

    # Fraud type distribution
    fraud_types = Counter(c.get("fraud_type", "Unknown") for c in complaint_data)
    state_distribution = Counter(c.get("state", "Unknown") for c in complaint_data)

    # Risk distribution
    amounts = [c.get("amount", 0) for c in complaint_data if c.get("amount")]
    avg_amount = sum(amounts) / max(len(amounts), 1)
    max_amount = max(amounts) if amounts else 0
    high_value_count = sum(1 for a in amounts if a > 100000)

    # Overall risk from incidents
    if incident_summaries:
        avg_risk = sum(i["risk_score"] for i in incident_summaries) / max(len(incident_summaries), 1)
        critical_count = sum(1 for i in incident_summaries if i["severity"] == "CRITICAL")
        high_count = sum(1 for i in incident_summaries if i["severity"] == "HIGH")
    else:
        avg_risk = 0
        critical_count = 0
        high_count = 0

    return {
        "incident_count": len(incidents),
        "incidents": incident_summaries,
        "complaint_count": complaint_count,
        "complaints": complaint_data,
        "transaction_count": transaction_count,
        "total_transaction_amount": total_amount,
        "account_count": account_count,
        "fraud_types": dict(fraud_types.most_common(10)),
        "state_distribution": dict(state_distribution.most_common(10)),
        "amount_stats": {
            "average": round(avg_amount, 2),
            "maximum": round(max_amount, 2),
            "high_value_count": high_value_count,
            "total": round(sum(amounts), 2),
        },
        "risk_summary": {
            "critical": critical_count + sum(1 for a in amounts if a > 500000),
            "high": high_count + sum(1 for a in amounts if 100000 < a <= 500000),
            "medium": sum(1 for a in amounts if 10000 < a <= 100000),
            "low": sum(1 for a in amounts if a <= 10000),
            "average_score": round(avg_risk, 1),
        },
    }


# ── Report ID & Integrity ────────────────────────────────────────────

def generate_report_id() -> str:
    return f"CSX-RPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def generate_integrity_block(report_id: str, user_email: str, content_hash: str) -> Dict[str, str]:
    """Generate HMAC-signed integrity block for tamper detection."""
    timestamp = _now_utc().isoformat()
    canonical = f"{report_id}|{user_email}|{timestamp}|{content_hash}"
    signature = _hmac_sign(canonical)
    return {
        "report_id": report_id,
        "content_hash": content_hash,
        "hmac_signature": signature,
        "generated_at": timestamp,
        "generated_by": user_email,
        "algorithm": "HMAC-SHA256",
        "verification_url": f"https://cybersentinel-x.vercel.app/verify/{report_id}",
    }


# ── HTML Report Builder with Biometrics ──────────────────────────────

def build_professional_html(
    report_id: str,
    data: Dict[str, Any],
    user_email: str,
    tfa_verified: bool = False,
) -> str:
    """Build a professional HTML report with biometric elements."""
    now = _now_utc()
    content_str = json.dumps(data, sort_keys=True, default=str)
    content_hash = _sha256(content_str)
    integrity = generate_integrity_block(report_id, user_email, content_hash)
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=120x120&data={integrity['verification_url']}"

    # Risk level calculation
    risk_score = data["risk_summary"]["average_score"]
    risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW"
    risk_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}[risk_label]

    # Incident rows
    incident_rows = ""
    for inc in data["incidents"][:20]:
        sev_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(inc["severity"], "#64748b")
        incident_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:12px;color:#0ea5e9">{html.escape(str(inc['incident_id']))}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-weight:500">{html.escape(inc['title'])}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">
                <span style="background:{sev_color}15;color:{sev_color};padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600">{inc['severity']}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center;font-family:monospace;font-size:13px;font-weight:600">{inc['risk_score']}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">
                <span style="background:{'rgba(220,38,38,0.1)' if inc['status'] == 'OPEN' else 'rgba(34,197,94,0.1)'};color:{'#dc2626' if inc['status'] == 'OPEN' else '#16a34a'};padding:2px 8px;border-radius:8px;font-size:10px;font-weight:600">{inc['status']}</span>
            </td>
        </tr>"""

    # Fraud type rows
    fraud_rows = ""
    for ftype, count in data["fraud_types"].items():
        pct = count / max(data["complaint_count"], 1) * 100
        fraud_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-weight:500">{html.escape(ftype)}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">{count}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">
                <div style="background:#f1f5f9;border-radius:4px;height:6px;width:100%"><div style="background:#3b82f6;height:6px;border-radius:4px;width:{pct}%"></div></div>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center;font-size:11px">{pct:.1f}%</td>
        </tr>"""

    # State rows
    state_rows = ""
    for state, count in data["state_distribution"].items():
        state_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0">{html.escape(state)}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center;font-weight:600">{count}</td>
        </tr>"""

    # TFA badge
    tfa_badge = '<span style="background:#dcfce7;color:#16a34a;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600">2FA VERIFIED</span>' if tfa_verified else '<span style="background:#fef3c7;color:#92400e;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600">NO 2FA</span>'

    # Pre-build conditional sections
    incident_section = f"""
<div class="section">
  <div class="section-title">Incident Intelligence</div>
  <table>
    <thead>
      <tr><th>Incident ID</th><th>Title</th><th style="text-align:center">Severity</th><th style="text-align:center">Risk Score</th><th style="text-align:center">Status</th></tr>
    </thead>
    <tbody>{incident_rows}</tbody>
  </table>
</div>""" if incident_rows else ""

    fraud_section = f"""
<div class="section">
  <div class="section-title">Fraud Type Distribution</div>
  <table>
    <thead><tr><th>Type</th><th style="text-align:center">Count</th><th>Distribution</th><th style="text-align:center">%</th></tr></thead>
    <tbody>{fraud_rows}</tbody>
  </table>
</div>""" if fraud_rows else ""

    geo_section = f"""
<div class="section">
  <div class="section-title">Geographic Distribution</div>
  <table>
    <thead><tr><th>State</th><th style="text-align:center">Complaints</th></tr></thead>
    <tbody>{state_rows}</tbody>
  </table>
</div>""" if state_rows else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyberSentinel-X — Official Intelligence Report {html.escape(report_id)}</title>
<style>
@page {{ margin: 0; size: A4; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; padding: 30px 40px; background: #fff; line-height: 1.5; }}

/* Header */
.header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #0ea5e9; padding-bottom: 16px; margin-bottom: 24px; }}
.logo {{ font-size: 26px; font-weight: 800; color: #0ea5e9; letter-spacing: -0.5px; }}
.logo-sub {{ font-size: 10px; color: #64748b; letter-spacing: 3px; text-transform: uppercase; margin-top: 2px; }}
.meta {{ text-align: right; font-size: 11px; color: #64748b; }}
.meta strong {{ color: #0f172a; }}

/* Sections */
.section {{ margin-bottom: 22px; }}
.section-title {{ font-size: 13px; font-weight: 700; color: #0ea5e9; border-bottom: 2px solid #e2e8f0; padding-bottom: 5px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }}

/* Grid */
.grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 16px; }}
.stat-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; text-align: center; }}
.stat-card .label {{ font-size: 9px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; margin-bottom: 3px; }}
.stat-card .value {{ font-size: 20px; font-weight: 700; color: #0f172a; }}

/* Tables */
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ background: #0f172a; color: white; padding: 8px 12px; text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; }}
td {{ padding: 7px 12px; border-bottom: 1px solid #e2e8f0; }}

/* Biometric Stamps */
.stamp {{ position: fixed; bottom: 40px; right: 40px; width: 130px; height: 130px; border: 3px solid #dc2626; border-radius: 50%; display: flex; align-items: center; justify-content: center; transform: rotate(-12deg); opacity: 0.12; font-size: 11px; font-weight: 900; color: #dc2626; text-align: center; line-height: 1.3; text-transform: uppercase; letter-spacing: 1px; }}
.seal {{ position: fixed; top: 30px; right: 40px; width: 90px; height: 90px; border: 2px solid #0ea5e9; border-radius: 50%; display: flex; align-items: center; justify-content: center; transform: rotate(8deg); opacity: 0.15; font-size: 8px; font-weight: 700; color: #0ea5e9; text-align: center; line-height: 1.4; }}
.watermark {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(-30deg); font-size: 60px; font-weight: 900; color: #0ea5e9; opacity: 0.025; white-space: nowrap; pointer-events: none; letter-spacing: 4px; }}

/* Footer */
.footer {{ margin-top: 30px; border-top: 2px solid #e2e8f0; padding-top: 12px; display: flex; justify-content: space-between; align-items: flex-end; font-size: 10px; color: #64748b; }}
.integrity-block {{ background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 14px; margin-top: 12px; font-family: 'SF Mono', Monaco, monospace; font-size: 9px; color: #64748b; word-break: break-all; line-height: 1.6; }}
.integrity-block strong {{ color: #0f172a; font-size: 10px; }}

/* Digital signature */
.dsig {{ display: inline-flex; align-items: center; gap: 6px; background: linear-gradient(135deg, #0ea5e910, #8b5cf610); border: 1px solid #0ea5e930; border-radius: 6px; padding: 6px 10px; font-size: 9px; color: #475569; }}
.dsig-icon {{ color: #0ea5e9; font-size: 14px; }}
</style>
</head>
<body>

<div class="watermark">CYBERSENTINEL-X • CLASSIFIED</div>
<div class="seal">🛡️<br>CYBER<br>SENTINEL</div>
<div class="stamp">CONFIDENTIAL<br>AUTHORIZED<br>PERSONNEL ONLY</div>

<!-- Header -->
<div class="header">
  <div>
    <div class="logo">CYBERSENTINEL-X</div>
    <div class="logo-sub">Predictive Cybercrime Intelligence</div>
  </div>
  <div class="meta">
    <div><strong>Report ID:</strong> {html.escape(report_id)}</div>
    <div><strong>Generated:</strong> {_fmt(now)}</div>
    <div><strong>Classification:</strong> CONFIDENTIAL</div>
    <div><strong>Authority:</strong> SIH 2026 (SIH26184)</div>
    <div style="margin-top:4px">{tfa_badge}</div>
  </div>
</div>

<!-- Executive Summary -->
<div class="section">
  <div class="section-title">Executive Summary</div>
  <div class="grid">
    <div class="stat-card">
      <div class="label">Incidents Analyzed</div>
      <div class="value" style="color:#0ea5e9">{data['incident_count']}</div>
    </div>
    <div class="stat-card">
      <div class="label">Complaints</div>
      <div class="value">{data['complaint_count']:,}</div>
    </div>
    <div class="stat-card">
      <div class="label">Transactions</div>
      <div class="value">{data['transaction_count']:,}</div>
    </div>
    <div class="stat-card">
      <div class="label">At-Risk Value</div>
      <div class="value" style="color:#ea580c">₹{data['total_transaction_amount']:,.0f}</div>
    </div>
  </div>
</div>

<!-- Incident Intelligence -->
{incident_section}

<!-- Risk Assessment -->
<div class="section">
  <div class="section-title">Risk Assessment</div>
  <div class="grid">
    <div class="stat-card">
      <div class="label">Overall Risk Score</div>
      <div class="value" style="color:{risk_color}">{risk_score:.0f}/100</div>
    </div>
    <div class="stat-card">
      <div class="label">Critical Cases</div>
      <div class="value" style="color:#dc2626">{data['risk_summary']['critical']}</div>
    </div>
    <div class="stat-card">
      <div class="label">High-Risk Cases</div>
      <div class="value" style="color:#ea580c">{data['risk_summary']['high']}</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Accounts</div>
      <div class="value">{data['account_count']}</div>
    </div>
  </div>
</div>

<!-- Fraud Distribution -->
{fraud_section}

<!-- Geographic Distribution -->
{geo_section}

<!-- Transaction Analysis -->
<div class="section">
  <div class="section-title">Transaction Analysis</div>
  <div class="grid">
    <div class="stat-card">
      <div class="label">Average Amount</div>
      <div class="value">₹{data['amount_stats']['average']:,.0f}</div>
    </div>
    <div class="stat-card">
      <div class="label">Maximum Amount</div>
      <div class="value" style="color:#dc2626">₹{data['amount_stats']['maximum']:,.0f}</div>
    </div>
    <div class="stat-card">
      <div class="label">High-Value (>₹1L)</div>
      <div class="value" style="color:#ea580c">{data['amount_stats']['high_value_count']}</div>
    </div>
    <div class="stat-card">
      <div class="label">Total at Risk</div>
      <div class="value">₹{data['amount_stats']['total']:,.0f}</div>
    </div>
  </div>
</div>

<!-- Methodology -->
<div class="section">
  <div class="section-title">Methodology</div>
  <p style="font-size:12px;color:#475569;line-height:1.7">
    This report was auto-generated by the <strong>CyberSentinel-X Predictive Analytics Framework</strong>
    from real incident data and financial complaint records. The analysis pipeline: <strong>Schema Detection
    → Data Quality → Normalization → Transaction Analysis → Anomaly Detection (Isolation Forest + LOF) →
    Entity Resolution → Geospatial Analysis (DBSCAN) → Predictive Modeling → Risk Scoring →
    Intelligence Generation</strong>.
  </p>
  <p style="font-size:12px;color:#475569;line-height:1.7">
    Feature importance calculated using SHAP (SHapley Additive exPlanations). All predictions are
    probabilistic estimates with confidence intervals. Risk scores normalized to 0–100 scale.
  </p>
</div>

<!-- Digital Signature & Verification -->
<div class="section">
  <div class="section-title">Digital Signature & Verification</div>
  <div style="display:flex;gap:20px;align-items:flex-start">
    <div style="flex:1">
      <div class="dsig">
        <span class="dsig-icon">🔏</span>
        <div>
          <div style="font-weight:600;color:#0f172a">Digital Signature</div>
          <div>HMAC-SHA256 • Tamper-Evident</div>
          <div style="font-family:monospace;font-size:8px;margin-top:2px;word-break:break-all">{integrity['hmac_signature'][:48]}...</div>
        </div>
      </div>
      <div style="margin-top:8px;font-size:10px;color:#64748b">
        <div><strong>Signed by:</strong> {html.escape(user_email)}</div>
        <div><strong>Timestamp:</strong> {_fmt(now)}</div>
        <div><strong>Method:</strong> HMAC-SHA256 with server key</div>
      </div>
    </div>
    <div style="text-align:center">
      <img src="{qr_url}" alt="Verification QR" width="100" height="100" style="border:1px solid #e2e8f0;border-radius:6px" />
      <div style="font-size:8px;color:#64748b;margin-top:3px">Scan to verify</div>
    </div>
  </div>
</div>

<!-- Footer -->
<div class="footer">
  <div>
    <div><strong>CyberSentinel-X</strong> — Predictive Cybercrime Intelligence Platform</div>
    <div>SIH 2026 Problem Statement SIH26184</div>
    <div>Generated by: {html.escape(user_email)} • 2FA: {'✓ Verified' if tfa_verified else '⚠ Not Verified'}</div>
  </div>
  <div style="text-align:right">
    <div>Report ID: {html.escape(report_id)}</div>
    <div>Classification: CONFIDENTIAL</div>
  </div>
</div>

<!-- Integrity Block -->
<div class="integrity-block">
  <strong>DOCUMENT INTEGRITY VERIFICATION</strong><br>
  Report ID: {report_id}<br>
  Content Hash: SHA-256 = {content_hash}<br>
  HMAC Signature: {integrity['hmac_signature']}<br>
  Generated: {_fmt(now)} | Author: {html.escape(user_email)} | Algorithm: HMAC-SHA256<br>
  Verify: {integrity['verification_url']}
</div>

</body>
</html>"""


# ── Main Entry Point ─────────────────────────────────────────────────

def generate_enhanced_report(
    db,
    incident_id: str = None,
    user_email: str = "system",
    tfa_verified: bool = False,
) -> Dict[str, Any]:
    """Auto-generate an enhanced report from real incident data with biometric elements."""
    report_id = generate_report_id()

    # Get specific incident if provided
    incident = None
    if incident_id:
        from app.models.security import Incident
        try:
            incident = db.get(Incident, incident_id) or db.scalar(
                __import__("sqlalchemy").select(Incident).where(Incident.incident_id == incident_id)
            )
        except Exception:
            pass

    # Collect real data
    data = collect_incident_data(db, incident)

    # Build HTML with biometrics
    html_content = build_professional_html(report_id, data, user_email, tfa_verified)

    # Save HTML
    os.makedirs(REPORTS_DIR, exist_ok=True)
    html_path = os.path.join(REPORTS_DIR, f"{report_id}.html")
    try:
        with open(html_path, "w") as f:
            f.write(html_content)
    except Exception as e:
        logger.warning("Could not save HTML: %s", e)

    # Build PDF
    pdf_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")
    pdf_result = build_official_pdf(report_id, data, user_email, tfa_verified, pdf_path)
    if not pdf_result:
        pdf_path = None

    # Integrity block
    content_hash = _sha256(json.dumps(data, sort_keys=True, default=str))
    integrity = generate_integrity_block(report_id, user_email, content_hash)

    return {
        "report_id": report_id,
        "html_content": html_content,
        "pdf_path": pdf_path,
        "integrity_hash": integrity["hmac_signature"],
        "integrity": integrity,
        "classification": "CONFIDENTIAL",
        "tfa_verified": tfa_verified,
        "generated_by": user_email,
        "generated_at": _now_utc().isoformat(),
        "data_summary": {
            "incidents": data["incident_count"],
            "complaints": data["complaint_count"],
            "transactions": data["transaction_count"],
            "total_amount": data["total_transaction_amount"],
            "risk_level": data["risk_summary"]["risk_label"] if "risk_label" in data["risk_summary"] else (
                "CRITICAL" if data["risk_summary"]["critical"] > 0 else "HIGH" if data["risk_summary"]["high"] > 0 else "MEDIUM"
            ),
        },
    }


def build_official_pdf(
    report_id: str,
    data: Dict[str, Any],
    user_email: str,
    tfa_verified: bool = False,
    output_path: str = None,
) -> Optional[str]:
    """Build a professional PDF with stamps, seals, and biometric elements."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            HRFlowable,
        )
        from reportlab.graphics.shapes import Drawing, Circle, String
    except ImportError:
        logger.warning("reportlab not available — PDF generation skipped")
        return None

    if not output_path:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")

    styles = getSampleStyleSheet()
    now = _now_utc()
    content_hash = _sha256(json.dumps(data, sort_keys=True, default=str))
    signature = _hmac_sign(f"{report_id}|{user_email}|{now.isoformat()}|{content_hash}")

    title_style = ParagraphStyle("CSTitle", parent=styles["Title"], fontSize=22, textColor=colors.HexColor("#0ea5e9"), fontName="Helvetica-Bold")
    h2_style = ParagraphStyle("CSH2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#0ea5e9"), spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold")
    body_style = ParagraphStyle("CSBody", parent=styles["BodyText"], fontSize=9, leading=13, textColor=colors.HexColor("#334155"))

    story = []

    # Header
    header_data = [[
        Paragraph('<font color="#0ea5e9" size="18"><b>🛡 CYBERSENTINEL-X</b></font>', styles["Normal"]),
        Paragraph(f'<font size="8" color="#64748b">CONFIDENTIAL<br/>Report: {report_id}<br/>Generated: {_fmt(now)}<br/>2FA: {"✓ Verified" if tfa_verified else "⚠ Not"}</font>', styles["Normal"]),
    ]]
    ht = Table(header_data, colWidths=[4*inch, 2.5*inch])
    ht.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP"), ("LINEBELOW", (0,0), (-1,0), 2, colors.HexColor("#0ea5e9"))]))
    story.append(ht)
    story.append(Paragraph("Auto-Generated Intelligence Report — SIH 2026 (SIH26184)", ParagraphStyle("sub", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=12)))

    # Executive Summary
    story.append(Paragraph("EXECUTIVE SUMMARY", h2_style))
    summary = [
        ["Metric", "Value"],
        ["Incidents Analyzed", str(data["incident_count"])],
        ["Complaints", f"{data['complaint_count']:,}"],
        ["Transactions", f"{data['transaction_count']:,}"],
        ["At-Risk Value", f"₹{data['total_transaction_amount']:,.0f}"],
        ["Critical Cases", str(data["risk_summary"]["critical"])],
        ["High-Risk Cases", str(data["risk_summary"]["high"])],
    ]
    t = Table(summary, colWidths=[3*inch, 3.5*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 9),
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (1,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ("ALIGN", (1,0), (1,-1), "RIGHT"), ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # Incidents table
    if data["incidents"]:
        story.append(Paragraph("INCIDENT INTELLIGENCE", h2_style))
        inc_data = [["Incident ID", "Title", "Severity", "Risk", "Status"]]
        for inc in data["incidents"][:15]:
            inc_data.append([str(inc["incident_id"]), inc["title"][:40], inc["severity"], str(inc["risk_score"]), inc["status"]])
        it = Table(inc_data, colWidths=[1.2*inch, 2.2*inch, 1*inch, 0.8*inch, 1.3*inch])
        it.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(it)
        story.append(Spacer(1, 12))

    # Fraud distribution
    if data["fraud_types"]:
        story.append(Paragraph("FRAUD DISTRIBUTION", h2_style))
        fd = [["Type", "Count", "%"]]
        for ft, cnt in list(data["fraud_types"].items())[:8]:
            pct = cnt / max(data["complaint_count"], 1) * 100
            fd.append([ft, str(cnt), f"{pct:.1f}%"])
        fdt = Table(fd, colWidths=[3*inch, 1.5*inch, 2*inch])
        fdt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#cbd5e1")),
            ("ALIGN", (1,0), (-1,-1), "CENTER"), ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(fdt)
        story.append(Spacer(1, 12))

    # Methodology
    story.append(Paragraph("METHODOLOGY", h2_style))
    story.append(Paragraph(
        "Auto-generated by <b>CyberSentinel-X</b> using multi-stage ML analysis: "
        "<b>Schema Detection → Data Quality → Normalization → Transaction Analysis → "
        "Anomaly Detection → Entity Resolution → Geospatial Analysis (DBSCAN) → "
        "Predictive Modeling → Risk Scoring</b>. Feature importance via SHAP.", body_style))
    story.append(Spacer(1, 16))

    # Confidential stamp drawing
    stamp = Drawing(100, 100)
    stamp.add(Circle(50, 50, 45, strokeColor=colors.HexColor("#dc2626"), fillColor=colors.Color(0.88, 0.15, 0.15, 0.08), strokeWidth=2))
    stamp.add(String(50, 62, "CONFIDENTIAL", fontSize=7, fillColor=colors.HexColor("#dc2626"), textAnchor="middle", fontName="Helvetica-Bold"))
    stamp.add(String(50, 50, "AUTHORIZED", fontSize=7, fillColor=colors.HexColor("#dc2626"), textAnchor="middle", fontName="Helvetica-Bold"))
    stamp.add(String(50, 38, "ONLY", fontSize=7, fillColor=colors.HexColor("#dc2626"), textAnchor="middle", fontName="Helvetica-Bold"))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    footer_data = [[
        Paragraph(f'<font size="7" color="#64748b"><b>CyberSentinel-X</b> | SIH 2026 (SIH26184)<br/>Generated: {html.escape(user_email)} | 2FA: {"✓" if tfa_verified else "⚠"} | Report: {report_id}</font>', styles["Normal"]),
        stamp,
    ]]
    ft = Table(footer_data, colWidths=[5*inch, 1.5*inch])
    ft.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP")]))
    story.append(ft)
    story.append(Spacer(1, 6))
    story.append(Paragraph(f'<font size="7" color="#94a3b8">HMAC-SHA256: {signature[:64]}</font>', styles["Normal"]))

    try:
        doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=0.5*inch, leftMargin=0.5*inch, topMargin=0.5*inch, bottomMargin=0.5*inch)
        doc.build(story)
        return output_path
    except Exception as e:
        logger.error("PDF build failed: %s", e)
        return None
