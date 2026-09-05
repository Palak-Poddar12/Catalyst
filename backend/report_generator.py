from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from weasyprint import HTML, CSS


def _risk_level_label(score: int | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _format_datetime(dt_str: str | None) -> str:
    if not dt_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return dt_str


def _escape_html(text: str | None) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def generate_forensic_pdf_report(
    case_data: Dict[str, Any],
    output_path: str | Path,
) -> None:
    """
    Generate a forensic PDF report from a case JSON and save to disk.

    case_data:
        The full forensic result you already store, e.g.:
        {
          "case_id": "...",
          "created_at": "...",
          "risk": {"score": 68, "level": "high", ...},
          "sender_identity": {...},
          "email_authentication": {...},
          "relay_analysis": {...},
          "indicators": {...},
          "forensic_findings": [...],
          ...
        }

    output_path:
        Path where the PDF will be written, e.g. "reports/case_123.pdf".
    """

    case_id = case_data.get("case_id", "UnknownCase")
    created_at = _format_datetime(case_data.get("created_at"))
    risk = case_data.get("risk") or {}
    risk_score = risk.get("score")
    risk_level = _risk_level_label(risk_score)

    sender = case_data.get("sender_identity") or {}
    from_info = sender.get("from") or {}
    from_display = f"{from_info.get('display_name') or ''} <{from_info.get('email') or ''}>".strip()

    auth = case_data.get("email_authentication") or {}
    reported = auth.get("reported_results") or {}
    spf = reported.get("spf", "none").upper()
    dkim = reported.get("dkim", "none").upper()
    dmarc = reported.get("dmarc", "none").upper()

    relay = case_data.get("relay_analysis") or {}
    hops = relay.get("received_hops") or []
    probable = relay.get("probable_source") or {}

    indicators = case_data.get("indicators") or {}
    urls = indicators.get("urls") or []
    ips = indicators.get("ips") or []
    attachments = indicators.get("attachments") or []

    findings = case_data.get("forensic_findings") or []

    # Build HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <title>Forensic Report – {case_id}</title>
      <style>
        @page {{
          size: A4;
          margin: 20mm;
        }}
        body {{
          font-family: "Helvetica", "Arial", sans-serif;
          font-size: 11pt;
          line-height: 1.4;
          color: #111827;
        }}
        h1, h2, h3 {{
          color: #0f172a;
          margin-top: 18pt;
          margin-bottom: 8pt;
        }}
        h1 {{
          font-size: 18pt;
          border-bottom: 2px solid #e5e7eb;
          padding-bottom: 6pt;
        }}
        h2 {{
          font-size: 14pt;
        }}
        .meta {{
          font-size: 10pt;
          color: #4b5563;
          margin-bottom: 12pt;
        }}
        .risk-banner {{
          border: 1px solid #e5e7eb;
          background: #f9fafb;
          padding: 10pt;
          border-radius: 6px;
          margin: 12pt 0;
        }}
        .risk-score {{
          font-size: 22pt;
          font-weight: bold;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
          margin: 10pt 0 16pt 0;
          font-size: 10pt;
        }}
        th, td {{
          border: 1px solid #e5e7eb;
          padding: 6pt 8pt;
          text-align: left;
        }}
        th {{
          background: #f3f4f6;
          font-weight: 600;
        }}
        .muted {{
          color: #6b7280;
          font-size: 9.5pt;
        }}
        ul {{
          margin: 6pt 0 10pt 14pt;
          padding: 0;
        }}
        .section-break {{
          margin-top: 18pt;
          border-top: 1px dashed #e5e7eb;
          padding-top: 10pt;
        }}
      </style>
    </head>
    <body>
      <h1>Forensic Email Analysis Report</h1>

      <div class="meta">
        <div><strong>Case ID:</strong> {_escape_html(str(case_id))}</div>
        <div><strong>Analysis time:</strong> {_escape_html(created_at)}</div>
        <div><strong>From:</strong> {_escape_html(from_display)}</div>
      </div>

      <div class="risk-banner">
        <div><strong>Overall risk level:</strong> {_escape_html(risk_level)}</div>
        <div class="risk-score">Risk score: {risk_score if risk_score is not None else "N/A"}</div>
      </div>

      <h2>1. Executive Summary</h2>
      <p>
        This report summarizes the forensic analysis of a suspicious email.
        It covers authentication results, sender identity, relay infrastructure,
        extracted indicators (URLs, IPs, domains, attachments), and automated
        threat detection findings.
      </p>
      <p>
        The risk score is computed from authentication failures, threat-intelligence
        hits, suspicious relay behavior, and NLP/rule-based detections.
      </p>

      <h2>2. Authentication Results</h2>
      <table>
        <tr>
          <th>Check</th>
          <th>Result</th>
        </tr>
        <tr>
          <td>SPF</td>
          <td>{_escape_html(spf)}</td>
        </tr>
        <tr>
          <td>DKIM</td>
          <td>{_escape_html(dkim)}</td>
        </tr>
        <tr>
          <td>DMARC</td>
          <td>{_escape_html(dmarc)}</td>
        </tr>
      </table>

      <h2>3. Relay Path Overview</h2>
      <p class="muted">
        The table below shows the visible mail relay hops reconstructed from
        Received headers. Times are in UTC where available.
      </p>
      <table>
        <tr>
          <th>Hop</th>
          <th>IP</th>
          <th>Trust</th>
          <th>Time (UTC)</th>
          <th>Key risk flags</th>
        </tr>
    """

    for i, hop in enumerate(hops[:15], start=1):
        ip = hop.get("ip") or "Unknown"
        trusted = "Trusted" if hop.get("trusted") else "Untrusted"
        ts = _format_datetime(hop.get("timestamp_utc"))
        flags = hop.get("risk_flags") or []
        flags_str = ", ".join(flags[:5]) if flags else "None"

        html_content += f"""
        <tr>
          <td>{i}</td>
          <td>{_escape_html(ip)}</td>
          <td>{_escape_html(trusted)}</td>
          <td>{_escape_html(ts)}</td>
          <td>{_escape_html(flags_str)}</td>
        </tr>
        """

    html_content += """
      </table>

      <h2>4. Extracted Indicators</h2>

      <h3>4.1 URLs</h3>
    """

    if urls:
        html_content += """
        <table>
          <tr>
            <th>URL</th>
            <th>Threat intel status</th>
            <th>Risk flags</th>
          </tr>
        """
        for u in urls[:20]:
            url_val = u.get("url") or "Unknown"
            rep = u.get("reputation") or {}
            threat = rep.get("threat") or ""
            status = rep.get("status") or "not_available"
            flags = u.get("risk_flags") or []
            flags_str = ", ".join(flags[:5]) if flags else "None"

            html_content += f"""
            <tr>
              <td>{_escape_html(url_val)}</td>
              <td>{_escape_html(threat)} ({_escape_html(status)})</td>
              <td>{_escape_html(flags_str)}</td>
            </tr>
            """
        html_content += "\n      </table>\n"
    else:
        html_content += "<p>No URLs were extracted or all were filtered out.</p>\n"

    html_content += """
      <h3>4.2 IP Addresses</h3>
    """

    if ips:
        html_content += """
        <table>
          <tr>
            <th>IP</th>
            <th>Location</th>
            <th>ASN / Org</th>
            <th>Risk flags</th>
          </tr>
        """
        for ip_obj in ips[:20]:
            ip_val = ip_obj.get("ip") or "Unknown"
            geo = ip_obj.get("geolocation") or {}
            city = geo.get("city") or ""
            country = geo.get("country") or ""
            loc = f"{city}, {country}".strip() or "Unknown"
            asn = geo.get("asn") or "Unknown"
            org = geo.get("asn_organization") or "Unknown"
            flags = ip_obj.get("risk_flags") or []
            flags_str = ", ".join(flags[:5]) if flags else "None"

            html_content += f"""
            <tr>
              <td>{_escape_html(ip_val)}</td>
              <td>{_escape_html(loc)}</td>
              <td>{_escape_html(asn)} / {_escape_html(org)}</td>
              <td>{_escape_html(flags_str)}</td>
            </tr>
            """
        html_content += "\n      </table>\n"
    else:
        html_content += "<p>No IP indicators were extracted or enriched.</p>\n"

    html_content += """
      <h3>4.3 Attachments</h3>
    """

    if attachments:
        html_content += """
        <table>
          <tr>
            <th>Filename</th>
            <th>Content type</th>
            <th>Size (bytes)</th>
            <th>SHA-256</th>
            <th>Risk flags</th>
          </tr>
        """
        for att in attachments[:20]:
            filename = att.get("filename") or "Unknown"
            content_type = att.get("content_type") or "Unknown"
            size = att.get("size_bytes")
            sha = att.get("sha256") or "Unknown"
            flags = att.get("risk_flags") or []
            flags_str = ", ".join(flags[:5]) if flags else "None"

            html_content += f"""
            <tr>
              <td>{_escape_html(filename)}</td>
              <td>{_escape_html(content_type)}</td>
              <td>{size if size is not None else "Unknown"}</td>
              <td>{_escape_html(sha)}</td>
              <td>{_escape_html(flags_str)}</td>
            </tr>
            """
        html_content += "\n      </table>\n"
    else:
        html_content += "<p>No attachments were found in this email.</p>\n"

    html_content += """
      <h2>5. Threat Detection Findings</h2>
    """

    if findings:
        html_content += """
        <table>
          <tr>
            <th>Severity</th>
            <th>Finding</th>
            <th>Evidence</th>
          </tr>
        """
        for f in findings[:20]:
            severity = f.get("severity") or "Unknown"
            finding = f.get("finding") or "No description"
            evidence = f.get("evidence") or ""
            html_content += f"""
            <tr>
              <td>{_escape_html(severity)}</td>
              <td>{_escape_html(finding)}</td>
              <td>{_escape_html(evidence)}</td>
            </tr>
            """
        html_content += "\n      </table>\n"
    else:
        html_content += "<p>No automated threat detection findings were raised.</p>\n"

    html_content += f"""
      <div class="section-break">
        <p class="muted">
          This report was automatically generated by the SatGuard email forensic
          engine. IP geolocation and threat-intelligence data are approximate and
          time-dependent; they do not by themselves confirm an attacker’s identity
          or exact physical location.
        </p>
      </div>
    </body>
    </html>
    """

    # Render to PDF
    html_obj = HTML(string=html_content)
    # You can add custom CSS here if desired
    pdf_bytes = html_obj.write_pdf()

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pdf_bytes)