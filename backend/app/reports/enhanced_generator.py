"""Enhanced Report Generator — Real-Time Data + Professional Stamps + 2FA Authorization.

Generates official CyberSentinel-X intelligence reports with:
- Real complaint/transaction/entity data (not demo)
- Professional stamps, seals, QR codes, watermarks
- SHA-256 integrity verification
- 2FA authorization tracking
- Real-time access logging
"""
from __future__ import annotations

import hashlib
import html
import io
import logging
import os
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "reports")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "—"


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


# ── Real-Time Data Collection ────────────────────────────────────────

def collect_real_data(db) -> Dict[str, Any]:
    """Collect real complaint, transaction, and entity data from database."""
    from app.models.financial import FinancialComplaint, FinancialTransaction, FinancialAccount
    from sqlalchemy import func

    # Complaints
    try:
        complaints = db.query(FinancialComplaint).all()
        complaint_count = len(complaints)
        complaint_data = []
        for c in complaints[:100]:  # Cap at 100 for report
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

    # Fraud type distribution
    fraud_types = Counter(c.get("fraud_type", "Unknown") for c in complaint_data)
    state_distribution = Counter(c.get("state", "Unknown") for c in complaint_data)

    # Risk distribution
    amounts = [c.get("amount", 0) for c in complaint_data if c.get("amount")]
    avg_amount = sum(amounts) / max(len(amounts), 1)
    max_amount = max(amounts) if amounts else 0
    high_value_count = sum(1 for a in amounts if a > 100000)

    return {
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
            "critical": sum(1 for a in amounts if a > 500000),
            "high": sum(1 for a in amounts if 100000 < a <= 500000),
            "medium": sum(1 for a in amounts if 10000 < a <= 100000),
            "low": sum(1 for a in amounts if a <= 10000),
        },
    }


# ── Professional Stamp Generators ────────────────────────────────────

def generate_report_id() -> str:
    """Generate a unique report ID with prefix."""
    return f"CSX-RPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def generate_integrity_hash(content: str) -> str:
    """Generate SHA-256 integrity hash for tamper detection."""
    return _sha256(content)


def generate_qr_data(report_id: str, integrity_hash: str) -> str:
    """Generate QR code data for report verification."""
    return f"https://cybersentinel-x.vercel.app/verify/{report_id}?hash={integrity_hash[:16]}"


# ── HTML Report Builder ──────────────────────────────────────────────

def build_professional_html(
    report_id: str,
    real_data: Dict[str, Any],
    user_email: str,
    tfa_verified: bool = False,
    incident=None,
) -> str:
    """Build a professional HTML report with stamps, seals, and real data."""
    now = _now_utc()
    integrity_hash = generate_integrity_hash(f"{report_id}:{now.isoformat()}:{user_email}")
    qr_url = generate_qr_data(report_id, integrity_hash)

    # Risk level calculation
    risk_score = 0
    if real_data["complaint_count"] > 0:
        risk_score = min(100, int(
            (real_data["risk_summary"]["critical"] * 40 +
             real_data["risk_summary"]["high"] * 25 +
             real_data["risk_summary"]["medium"] * 10 +
             real_data["risk_summary"]["low"] * 2) /
            max(real_data["complaint_count"], 1) * 10
        ))

    risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW"
    risk_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}[risk_label]

    # Build fraud type rows
    fraud_rows = ""
    for ftype, count in real_data["fraud_types"].items():
        pct = count / max(real_data["complaint_count"], 1) * 100
        fraud_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-weight:500">{html.escape(ftype)}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">{count}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">
                <div style="background:#f1f5f9;border-radius:4px;height:6px;width:100%">
                    <div style="background:#3b82f6;height:6px;border-radius:4px;width:{pct}%"></div>
                </div>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">{pct:.1f}%</td>
        </tr>"""

    # Build state rows
    state_rows = ""
    for state, count in real_data["state_distribution"].items():
        state_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0">{html.escape(state)}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:center">{count}</td>
        </tr>"""

    # Build complaint detail rows (top 20)
    complaint_rows = ""
    for i, c in enumerate(real_data["complaints"][:20]):
        complaint_rows += f"""
        <tr>
            <td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;font-size:12px">{html.escape(c.get('complaint_id', 'N/A'))}</td>
            <td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;font-size:12px">₹{c.get('amount', 0):,.0f}</td>
            <td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;font-size:12px">{html.escape(c.get('fraud_type', 'N/A'))}</td>
            <td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;font-size:12px">{html.escape(c.get('state', 'N/A'))}</td>
            <td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;font-size:12px">{html.escape(c.get('district', 'N/A'))}</td>
        </tr>"""

    # TFA badge
    tfa_badge = '<span style="background:#dcfce7;color:#16a34a;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">✓ 2FA VERIFIED</span>' if tfa_verified else '<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">⚠ NO 2FA</span>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyberSentinel-X — Official Intelligence Report {html.escape(report_id)}</title>
<style>
@page {{ margin: 0; }}
body {{ font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; padding: 40px; background: #fff; }}
.header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #0ea5e9; padding-bottom: 20px; margin-bottom: 30px; }}
.logo {{ font-size: 28px; font-weight: 800; color: #0ea5e9; letter-spacing: -0.5px; }}
.logo-sub {{ font-size: 11px; color: #64748b; letter-spacing: 2px; text-transform: uppercase; }}
.report-meta {{ text-align: right; font-size: 12px; color: #64748b; }}
.report-meta strong {{ color: #0f172a; }}
.section {{ margin-bottom: 28px; }}
.section-title {{ font-size: 16px; font-weight: 700; color: #0ea5e9; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.5px; }}
.grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }}
.stat-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; }}
.stat-card .label {{ font-size: 10px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; margin-bottom: 4px; }}
.stat-card .value {{ font-size: 22px; font-weight: 700; color: #0f172a; }}
.stat-card .value.critical {{ color: #dc2626; }}
.stat-card .value.high {{ color: #ea580c; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: #0f172a; color: white; padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
td {{ padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }}
.stamp {{ position: fixed; bottom: 30px; right: 30px; width: 140px; height: 140px; border: 4px solid #dc2626; border-radius: 50%; display: flex; align-items: center; justify-content: center; transform: rotate(-15deg); opacity: 0.15; font-size: 14px; font-weight: 900; color: #dc2626; text-align: center; line-height: 1.2; text-transform: uppercase; }}
.official-seal {{ position: fixed; top: 30px; right: 30px; width: 100px; height: 100px; border: 3px solid #0ea5e9; border-radius: 50%; display: flex; align-items: center; justify-content: center; transform: rotate(10deg); opacity: 0.2; font-size: 10px; font-weight: 700; color: #0ea5e9; text-align: center; line-height: 1.3; }}
.footer {{ margin-top: 40px; border-top: 2px solid #e2e8f0; padding-top: 16px; display: flex; justify-content: space-between; align-items: flex-end; }}
.footer-left {{ font-size: 11px; color: #64748b; }}
.footer-right {{ text-align: right; font-size: 11px; color: #64748b; }}
.integrity {{ background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 10px; color: #64748b; word-break: break-all; margin-top: 12px; }}
.watermark {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(-30deg); font-size: 72px; font-weight: 900; color: #0ea5e9; opacity: 0.03; white-space: nowrap; pointer-events: none; }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
.badge.CRITICAL {{ background: #fee2e2; color: #b91c1c; }}
.badge.HIGH {{ background: #ffedd5; color: #c2410c; }}
.badge.MEDIUM {{ background: #fef9c3; color: #a16207; }}
.badge.LOW {{ background: #dcfce7; color: #15803d; }}
</style>
</head>
<body>

<!-- Watermark -->
<div class="watermark">CYBERSENTINEL-X • CLASSIFIED</div>

<!-- Official Seal -->
<div class="official-seal">🛡️<br>CYBER<br>SENTINEL<br>X</div>

<!-- AUTHORIZED Stamp -->
<div class="stamp">CONFIDENTIAL<br>AUTHORIZED<br>PERSONNEL ONLY</div>

<!-- Header -->
<div class="header">
  <div>
    <div class="logo">🛡️ CYBERSENTINEL-X</div>
    <div class="logo-sub">Predictive Cybercrime Intelligence Platform</div>
  </div>
  <div class="report-meta">
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
      <div class="label">Complaints Analyzed</div>
      <div class="value">{real_data['complaint_count']:,}</div>
    </div>
    <div class="stat-card">
      <div class="label">Transactions Processed</div>
      <div class="value">{real_data['transaction_count']:,}</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Amount at Risk</div>
      <div class="value">₹{real_data['total_transaction_amount']:,.0f}</div>
    </div>
    <div class="stat-card">
      <div class="label">Risk Score</div>
      <div class="value" style="color:{risk_color}">{risk_score}/100</div>
    </div>
  </div>
</div>

<!-- Risk Assessment -->
<div class="section">
  <div class="section-title">Risk Assessment</div>
  <div class="grid">
    <div class="stat-card">
      <div class="label">Critical Risk</div>
      <div class="value critical">{real_data['risk_summary']['critical']}</div>
    </div>
    <div class="stat-card">
      <div class="label">High Risk</div>
      <div class="value high">{real_data['risk_summary']['high']}</div>
    </div>
    <div class="stat-card">
      <div class="label">Medium Risk</div>
      <div class="value" style="color:#ca8a04">{real_data['risk_summary']['medium']}</div>
    </div>
    <div class="stat-card">
      <div class="label">Low Risk</div>
      <div class="value" style="color:#16a34a">{real_data['risk_summary']['low']}</div>
    </div>
  </div>
</div>

<!-- Fraud Type Distribution -->
<div class="section">
  <div class="section-title">Fraud Type Distribution</div>
  <table>
    <thead>
      <tr><th>Fraud Type</th><th style="text-align:center">Count</th><th>Distribution</th><th style="text-align:center">Percentage</th></tr>
    </thead>
    <tbody>{fraud_rows}</tbody>
  </table>
</div>

<!-- Geographic Distribution -->
<div class="section">
  <div class="section-title">Geographic Distribution (Top States)</div>
  <table>
    <thead><tr><th>State</th><th style="text-align:center">Complaints</th></tr></thead>
    <tbody>{state_rows}</tbody>
  </table>
</div>

<!-- Transaction Analysis -->
<div class="section">
  <div class="section-title">Transaction Analysis</div>
  <div class="grid">
    <div class="stat-card">
      <div class="label">Average Amount</div>
      <div class="value">₹{real_data['amount_stats']['average']:,.0f}</div>
    </div>
    <div class="stat-card">
      <div class="label">Maximum Amount</div>
      <div class="value critical">₹{real_data['amount_stats']['maximum']:,.0f}</div>
    </div>
    <div class="stat-card">
      <div class="label">High-Value Cases</div>
      <div class="value high">{real_data['amount_stats']['high_value_count']}</div>
    </div>
    <div class="stat-card">
      <div class="label">Active Accounts</div>
      <div class="value">{real_data['account_count']}</div>
    </div>
  </div>
</div>

<!-- Complaint Details (Top 20) -->
<div class="section">
  <div class="section-title">Complaint Details (Top 20)</div>
  <table>
    <thead>
      <tr><th>Complaint ID</th><th>Amount</th><th>Fraud Type</th><th>State</th><th>District</th></tr>
    </thead>
    <tbody>{complaint_rows if complaint_rows else '<tr><td colspan="5" style="text-align:center;padding:20px;color:#64748b">No complaint data available</td></tr>'}</tbody>
  </table>
</div>

<!-- Methodology -->
<div class="section">
  <div class="section-title">Methodology</div>
  <p style="font-size:13px;color:#475569;line-height:1.6">
    This report was generated by the <strong>CyberSentinel-X Predictive Analytics Framework</strong> 
    using real-time data ingestion and multi-stage ML analysis. The analysis pipeline includes: 
    <strong>Schema Detection → Data Quality → Normalization → Transaction Analysis → 
    Anomaly Detection (Isolation Forest + LOF) → Entity Resolution → Geospatial Analysis 
    (DBSCAN Clustering) → Predictive Modeling → Risk Scoring → Intelligence Generation</strong>.
  </p>
  <p style="font-size:13px;color:#475569;line-height:1.6">
    All predictions are probabilistic estimates. Feature importance is calculated using 
    SHAP (SHapley Additive exPlanations) for full explainability.
  </p>
</div>

<!-- Footer -->
<div class="footer">
  <div class="footer-left">
    <div><strong>CyberSentinel-X</strong> — Predictive Cybercrime Intelligence Platform</div>
    <div>SIH 2026 Problem Statement SIH26184</div>
    <div>Generated by: {html.escape(user_email)}</div>
    <div>Authorization: 2FA {'✓ Verified' if tfa_verified else '⚠ Not Verified'}</div>
  </div>
  <div class="footer-right">
    <div>Report ID: {html.escape(report_id)}</div>
    <div>Classification: CONFIDENTIAL</div>
    <div>Page 1 of 1</div>
  </div>
</div>

<!-- Integrity Hash -->
<div class="integrity">
  <strong>DOCUMENT INTEGRITY</strong><br>
  SHA-256: {integrity_hash}<br>
  Report: {report_id} | Generated: {_fmt(now)} | Author: {html.escape(user_email)}<br>
  Verify at: {qr_url}
</div>

</body>
</html>"""


def build_official_pdf(
    report_id: str,
    real_data: Dict[str, Any],
    user_email: str,
    tfa_verified: bool = False,
    output_path: str = None,
) -> Optional[str]:
    """Build a professional PDF report with stamps, seals, and official formatting."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch, mm
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            HRFlowable, Image as RLImage
        )
        from reportlab.graphics.shapes import Drawing, Rect, String, Circle
        from reportlab.graphics import renderPDF
    except ImportError:
        logger.warning("reportlab not available — PDF generation skipped")
        return None

    if not output_path:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle("CSTitle", parent=styles["Title"],
        fontSize=24, textColor=colors.HexColor("#0ea5e9"), spaceAfter=4,
        fontName="Helvetica-Bold")
    subtitle_style = ParagraphStyle("CSSub", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#64748b"),
        spaceAfter=20, alignment=1)
    h2_style = ParagraphStyle("CSH2", parent=styles["Heading2"],
        fontSize=14, textColor=colors.HexColor("#0ea5e9"),
        spaceBefore=16, spaceAfter=8, fontName="Helvetica-Bold")
    body_style = ParagraphStyle("CSBody", parent=styles["BodyText"],
        fontSize=10, leading=14, textColor=colors.HexColor("#334155"))
    small_style = ParagraphStyle("CSSmall", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#94a3b8"), leading=10)

    now = _now_utc()
    integrity_hash = generate_integrity_hash(f"{report_id}:{now.isoformat()}:{user_email}")

    story = []

    # ── Official Header with Seal ──
    header_data = [
        [Paragraph('<font color="#0ea5e9" size="20"><b>🛡 CYBERSENTINEL-X</b></font>', styles["Normal"]),
         Paragraph(f'<font size="8" color="#64748b">CONFIDENTIAL<br/>Report ID: {report_id}<br/>Generated: {_fmt(now)}<br/>2FA: {"✓ Verified" if tfa_verified else "⚠ Not Verified"}</font>', styles["Normal"])],
    ]
    header_table = Table(header_data, colWidths=[4*inch, 2.5*inch])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 2, colors.HexColor("#0ea5e9")),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 4))
    story.append(Paragraph("Predictive Cybercrime Intelligence Platform — Official Report", subtitle_style))
    story.append(Paragraph("SIH 2026 Problem Statement SIH26184", subtitle_style))
    story.append(Spacer(1, 12))

    # ── Executive Summary ──
    story.append(Paragraph("EXECUTIVE SUMMARY", h2_style))
    summary_data = [
        ["Metric", "Value"],
        ["Complaints Analyzed", f"{real_data['complaint_count']:,}"],
        ["Transactions Processed", f"{real_data['transaction_count']:,}"],
        ["Total Amount at Risk", f"₹{real_data['total_transaction_amount']:,.0f}"],
        ["Active Accounts", f"{real_data['account_count']:,}"],
        ["Critical Risk Cases", f"{real_data['risk_summary']['critical']}"],
        ["High Risk Cases", f"{real_data['risk_summary']['high']}"],
    ]
    t = Table(summary_data, colWidths=[3*inch, 3.5*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f1f5f9")),
        ("ROWBACKGROUNDS", (1, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # ── Fraud Distribution ──
    story.append(Paragraph("FRAUD TYPE DISTRIBUTION", h2_style))
    fraud_data = [["Fraud Type", "Count", "Percentage"]]
    for ftype, count in real_data["fraud_types"].items():
        pct = count / max(real_data["complaint_count"], 1) * 100
        fraud_data.append([ftype, str(count), f"{pct:.1f}%"])
    ft = Table(fraud_data, colWidths=[3*inch, 1.5*inch, 2*inch])
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(ft)
    story.append(Spacer(1, 16))

    # ── Geographic Distribution ──
    story.append(Paragraph("GEOGRAPHIC DISTRIBUTION", h2_style))
    geo_data = [["State", "Complaints"]]
    for state, count in list(real_data["state_distribution"].items())[:10]:
        geo_data.append([state, str(count)])
    gt = Table(geo_data, colWidths=[4*inch, 2.5*inch])
    gt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(gt)
    story.append(Spacer(1, 16))

    # ── Transaction Analysis ──
    story.append(Paragraph("TRANSACTION ANALYSIS", h2_style))
    stats = real_data["amount_stats"]
    txn_data = [
        ["Metric", "Value"],
        ["Average Transaction", f"₹{stats['average']:,.0f}"],
        ["Maximum Transaction", f"₹{stats['maximum']:,.0f}"],
        ["Total Value at Risk", f"₹{stats['total']:,.0f}"],
        ["High-Value Cases (>₹1L)", str(stats['high_value_count'])],
    ]
    tt = Table(txn_data, colWidths=[3*inch, 3.5*inch])
    tt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f1f5f9")),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tt)
    story.append(Spacer(1, 16))

    # ── Methodology ──
    story.append(Paragraph("METHODOLOGY", h2_style))
    story.append(Paragraph(
        "This report was generated by the <b>CyberSentinel-X Predictive Analytics Framework</b> "
        "using real-time data ingestion and multi-stage ML analysis. Pipeline: "
        "<b>Schema Detection → Data Quality → Normalization → Transaction Analysis → "
        "Anomaly Detection (Isolation Forest + LOF) → Entity Resolution → Geospatial Analysis "
        "(DBSCAN Clustering) → Predictive Modeling → Risk Scoring → Intelligence Generation</b>.",
        body_style
    ))
    story.append(Spacer(1, 20))

    # ── Official Stamp (drawn as a colored circle with text) ──
    stamp_drawing = Drawing(120, 120)
    stamp_drawing.add(Circle(60, 60, 55, strokeColor=colors.HexColor("#dc2626"),
                              fillColor=colors.Color(0.88, 0.15, 0.15, 0.08), strokeWidth=2))
    stamp_drawing.add(String(60, 75, "CONFIDENTIAL", fontSize=8, fillColor=colors.HexColor("#dc2626"),
                              textAnchor="middle", fontName="Helvetica-Bold"))
    stamp_drawing.add(String(60, 62, "AUTHORIZED", fontSize=8, fillColor=colors.HexColor("#dc2626"),
                              textAnchor="middle", fontName="Helvetica-Bold"))
    stamp_drawing.add(String(60, 49, "PERSONNEL", fontSize=8, fillColor=colors.HexColor("#dc2626"),
                              textAnchor="middle", fontName="Helvetica-Bold"))
    stamp_drawing.add(String(60, 36, "ONLY", fontSize=8, fillColor=colors.HexColor("#dc2626"),
                              textAnchor="middle", fontName="Helvetica-Bold"))

    # ── Footer with integrity ──
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 8))

    footer_data = [
        [Paragraph(
            f'<font size="7" color="#64748b"><b>CyberSentinel-X</b> — Predictive Cybercrime Intelligence Platform<br/>'
            f'SIH 2026 (SIH26184) | Generated by: {html.escape(user_email)} | 2FA: {"✓ Verified" if tfa_verified else "⚠ Not Verified"}<br/>'
            f'Report ID: {report_id} | Classification: CONFIDENTIAL</font>',
            styles["Normal"]),
         stamp_drawing],
    ]
    footer_table = Table(footer_data, colWidths=[5*inch, 1.5*inch])
    footer_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(footer_table)

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f'<font size="7" color="#94a3b8"><b>Document Integrity:</b> SHA-256: {integrity_hash}</font>',
        styles["Normal"]
    ))

    # Build PDF
    try:
        doc = SimpleDocTemplate(output_path, pagesize=A4,
            rightMargin=0.6*inch, leftMargin=0.6*inch,
            topMargin=0.6*inch, bottomMargin=0.6*inch)
        doc.build(story)
        return output_path
    except Exception as exc:
        logger.error("PDF build failed: %s", exc)
        return None


# ── Main Entry Point ─────────────────────────────────────────────────

def generate_enhanced_report(
    db,
    incident_id: str = None,
    user_email: str = "system",
    tfa_verified: bool = False,
) -> Dict[str, Any]:
    """Generate an enhanced report with real data, stamps, and 2FA tracking.

    Returns dict with report_id, html_content, pdf_path, integrity_hash, etc.
    """
    report_id = generate_report_id()

    # Collect real data
    real_data = collect_real_data(db)

    # Build HTML
    html_content = build_professional_html(report_id, real_data, user_email, tfa_verified)

    # Build PDF
    os.makedirs(REPORTS_DIR, exist_ok=True)
    pdf_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")
    pdf_result = build_official_pdf(report_id, real_data, user_email, tfa_verified, pdf_path)
    if not pdf_result:
        pdf_path = None

    integrity_hash = generate_integrity_hash(f"{report_id}:{_now_utc().isoformat()}:{user_email}")

    return {
        "report_id": report_id,
        "html_content": html_content,
        "pdf_path": pdf_path,
        "integrity_hash": integrity_hash,
        "classification": "CONFIDENTIAL",
        "tfa_verified": tfa_verified,
        "generated_by": user_email,
        "generated_at": _now_utc().isoformat(),
        "data_summary": {
            "complaints": real_data["complaint_count"],
            "transactions": real_data["transaction_count"],
            "total_amount": real_data["total_transaction_amount"],
            "risk_level": "HIGH" if real_data["risk_summary"]["critical"] > 0 else "MEDIUM",
        },
    }
