from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _text(value: Any, default: str = "Not available") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value) or default
    return str(value)


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _escape(value: Any) -> str:
    text = _text(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_escape(value).replace("\n", "<br/>") , style)


def _section_title(title: str, styles: dict) -> Paragraph:
    return Paragraph(_escape(title), styles["section"])


def _kv_table(rows: list[tuple[str, Any]], styles: dict) -> Table:
    data = []
    for label, value in rows:
        data.append([
            Paragraph(_escape(label), styles["label"]),
            Paragraph(_escape(value), styles["body"]),
        ])

    table = Table(data, colWidths=[48 * mm, 132 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D6DEE8")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _bullet_table(items: list[str], styles: dict) -> list:
    if not items:
        return [Paragraph("No items recorded.", styles["body"])]

    data = [[Paragraph(f"• {_escape(item)}", styles["body"])] for item in items]
    table = Table(data, colWidths=[180 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return [table]


def _risk_value(forensic_result: dict) -> tuple[int, str]:
    explicit = forensic_result.get("risk") or forensic_result.get("risk_assessment") or {}
    if isinstance(explicit, dict) and explicit.get("score") is not None:
        score = int(explicit.get("score", 0))
        severity = _text(explicit.get("severity"), "unknown").upper()
        return max(0, min(score, 100)), severity

    findings = _safe_list(forensic_result.get("forensic_findings"))
    score = min(
        sum(35 for f in findings if f.get("severity") == "critical")
        + sum(15 for f in findings if f.get("severity") == "high")
        + sum(7 for f in findings if f.get("severity") == "medium"),
        100,
    )
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "SAFE"
    return score, severity


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontSize=22,
            leading=26, alignment=TA_CENTER, spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle", parent=base["Normal"], fontSize=10,
            leading=14, alignment=TA_CENTER, textColor=colors.HexColor("#64748B"),
            spaceAfter=18,
        ),
        "section": ParagraphStyle(
            "Section", parent=base["Heading2"], fontSize=14,
            leading=18, spaceBefore=14, spaceAfter=8,
            textColor=colors.HexColor("#0F172A"),
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontSize=8.7,
            leading=12.5, spaceAfter=3,
        ),
        "label": ParagraphStyle(
            "Label", parent=base["BodyText"], fontSize=8.5,
            leading=11, fontName="Helvetica-Bold",
        ),
        "small": ParagraphStyle(
            "Small", parent=base["BodyText"], fontSize=7.5,
            leading=10, textColor=colors.HexColor("#64748B"),
        ),
        "finding": ParagraphStyle(
            "Finding", parent=base["BodyText"], fontSize=8.2,
            leading=11.5, spaceAfter=2,
        ),
    }


def generate_forensic_pdf(
    forensic_result: dict,
    output_path: str | Path,
) -> Path:
    """Generate a professional forensic PDF from one SatGuard JSON result."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = _build_styles()
    case_id = _text(forensic_result.get("case_id"), "UNKNOWN-CASE")
    score, severity = _risk_value(forensic_result)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"SatGuard Forensic Report - {case_id}",
        author="SatGuard Email Forensic Intelligence",
        subject="Email forensic investigation report",
    )

    story = []
    story.append(Paragraph("SATGUARD", styles["title"]))
    story.append(Paragraph("Email Forensic Investigation Report", styles["title"]))
    story.append(Paragraph(
        f"Case ID: {_escape(case_id)} · Generated: {_escape(datetime.now(timezone.utc).isoformat())}",
        styles["subtitle"],
    ))

    risk_table = Table([
        [
            Paragraph("RISK SCORE", styles["label"]),
            Paragraph("SEVERITY", styles["label"]),
            Paragraph("FINDINGS", styles["label"]),
        ],
        [
            Paragraph(f"<b>{score}/100</b>", styles["body"]),
            Paragraph(f"<b>{_escape(severity)}</b>", styles["body"]),
            Paragraph(str(len(_safe_list(forensic_result.get("forensic_findings")))), styles["body"]),
        ],
    ], colWidths=[60 * mm, 60 * mm, 60 * mm])
    risk_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 5 * mm))

    evidence = forensic_result.get("evidence", {}) or {}
    metadata = forensic_result.get("message_metadata", {}) or {}
    sender = forensic_result.get("sender_identity", {}) or {}

    story.append(_section_title("1. Evidence Preservation", styles))
    story.append(_kv_table([
        ("Source file", evidence.get("source_name")),
        ("Evidence SHA-256", evidence.get("evidence_hash_sha256")),
        ("Analysis timestamp", evidence.get("analysis_timestamp_utc")),
    ], styles))

    story.append(_section_title("2. Email Metadata", styles))
    story.append(_kv_table([
        ("Subject", metadata.get("subject")),
        ("Date", metadata.get("date")),
        ("Message-ID", metadata.get("message_id")),
        ("From", (sender.get("from") or {}).get("email_address")),
        ("Reply-To", (sender.get("reply_to") or {}).get("email_address")),
        ("Return-Path", (sender.get("return_path") or {}).get("email_address")),
    ], styles))

    story.append(_section_title("3. Sender Identity Analysis", styles))
    identity_analysis = sender.get("analysis", {}) or {}
    story.extend(_bullet_table(
        _safe_list(identity_analysis.get("risk_flags"))
        + _safe_list(identity_analysis.get("findings")),
        styles,
    ))

    story.append(_section_title("4. SPF / DKIM / DMARC", styles))
    auth = forensic_result.get("email_authentication", {}) or {}
    reported = auth.get("reported_results", {}) or {}
    dmarc = auth.get("dmarc_forensic_assessment", {}) or {}
    story.append(_kv_table([
        ("SPF", reported.get("spf")),
        ("DKIM", reported.get("dkim")),
        ("DMARC", reported.get("dmarc")),
        ("DMARC assessment", dmarc.get("assessment")),
        ("Visible From domain", dmarc.get("visible_from_domain")),
        ("DMARC DNS policy", dmarc.get("dmarc_dns_policy")),
    ], styles))

    story.append(_section_title("5. Relay Path Reconstruction", styles))
    relay = forensic_result.get("relay_analysis", {}) or {}
    source = relay.get("probable_source", {}) or {}
    story.append(_kv_table([
        ("Earliest visible public hop", source.get("earliest_visible_public_hop")),
        ("Source confidence", source.get("confidence")),
        ("Limitation", source.get("limitation")),
    ], styles))

    hops = _safe_list(relay.get("received_hops"))
    if hops:
        rows = [["Hop", "From", "By", "IP", "Scope", "Trusted"]]
        for index, hop in enumerate(hops, 1):
            rows.append([
                str(hop.get("hop_number", index)),
                _text(hop.get("from"), ""),
                _text(hop.get("by"), ""),
                _text(hop.get("ip"), ""),
                _text(hop.get("ip_scope"), ""),
                "YES" if hop.get("trusted") else "NO",
            ])
        table = Table(rows, colWidths=[12*mm, 37*mm, 37*mm, 36*mm, 29*mm, 20*mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(Spacer(1, 2 * mm))
        story.append(table)

    story.append(_section_title("6. Indicators of Compromise", styles))
    indicators = forensic_result.get("indicators", {}) or {}
    domains = _safe_list(indicators.get("domains"))
    urls = _safe_list(indicators.get("urls"))
    ips = _safe_list(indicators.get("ips"))
    attachments = _safe_list(indicators.get("attachments"))

    story.append(_kv_table([
        ("Domains", len(domains)),
        ("URLs", len(urls)),
        ("IP addresses", len(ips)),
        ("Attachments", len(attachments)),
    ], styles))

    if domains:
        story.append(Paragraph("Domains", styles["label"]))
        story.extend(_bullet_table([_text(d) for d in domains], styles))
    if urls:
        story.append(Paragraph("URLs", styles["label"]))
        story.extend(_bullet_table([_text(u.get("url", u)) if isinstance(u, dict) else _text(u) for u in urls], styles))
    if ips:
        story.append(Paragraph("IP intelligence", styles["label"]))
        ip_lines = []
        for item in ips:
            if isinstance(item, dict):
                geo = item.get("geolocation") or {}
                rep = item.get("reputation") or {}
                ip_lines.append(
                    f"{item.get('ip', 'unknown')} · {geo.get('city', '')}, {geo.get('country', '')} · "
                    f"ASN {geo.get('asn', 'unknown')} · Reputation {rep.get('status', 'unknown')}"
                )
            else:
                ip_lines.append(_text(item))
        story.extend(_bullet_table(ip_lines, styles))
    if attachments:
        story.append(Paragraph("Attachments", styles["label"]))
        attachment_lines = []
        for item in attachments:
            if isinstance(item, dict):
                attachment_lines.append(
                    f"{item.get('filename', 'unknown')} · {item.get('content_type', 'unknown')} · "
                    f"risk flags: {_text(item.get('risk_flags'), 'none')}"
                )
            else:
                attachment_lines.append(_text(item))
        story.extend(_bullet_table(attachment_lines, styles))

    story.append(PageBreak())
    story.append(_section_title("7. Forensic Findings", styles))
    findings = _safe_list(forensic_result.get("forensic_findings"))
    if findings:
        rows = [["Severity", "Finding", "Evidence / Detail"]]
        for finding in findings:
            if isinstance(finding, dict):
                rows.append([
                    _text(finding.get("severity"), "unknown").upper(),
                    _text(finding.get("title") or finding.get("finding") or finding.get("root_cause")),
                    _text(finding.get("evidence") or finding.get("detail") or finding.get("description")),
                ])
            else:
                rows.append(["INFO", _text(finding), ""])
        table = Table(rows, colWidths=[25*mm, 65*mm, 90*mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.2),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No forensic findings were recorded.", styles["body"]))

    story.append(_section_title("8. Forensic Limitations", styles))
    story.extend(_bullet_table(
        [_text(item) for item in _safe_list(forensic_result.get("forensic_limitations"))],
        styles,
    ))

    story.append(_section_title("9. Investigator Summary", styles))
    summary = (
        f"SatGuard analyzed case <b>{_escape(case_id)}</b> using preserved email evidence, "
        "authentication results, sender identity indicators, relay headers, extracted IOCs, "
        "and available threat-intelligence context. The result is an evidence-based forensic "
        "assessment and should not be interpreted as proof of the human identity or exact physical "
        "location of an attacker."
    )
    story.append(Paragraph(summary, styles["body"]))

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        "Human review is recommended before any containment, blocking, or other operational action.",
        styles["label"],
    ))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(
        "Generated by SatGuard Email Forensic Intelligence · For investigative use",
        styles["small"],
    ))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(15 * mm, 9 * mm, f"SatGuard · Case {case_id}")
        canvas.drawRightString(195 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output_path
