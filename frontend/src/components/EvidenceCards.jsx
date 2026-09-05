import {
  AlertTriangle,
  BadgeCheck,
  FileWarning,
  Link,
  MailWarning,
  ShieldAlert,
} from "lucide-react";

function getSeverityClass(severity) {
  return `severity-${severity || "low"}`;
}

function getAuthClass(status) {
  if (status === "pass") return "auth-pass";
  if (status === "fail") return "auth-fail";
  return "auth-unknown";
}

function EvidenceCards({ data }) {
  const auth = data.email_authentication.reported_results;
  const findings = data.forensic_findings || [];

  const criticalCount = findings.filter(
    (item) => item.severity === "critical"
  ).length;

  const highCount = findings.filter(
    (item) => item.severity === "high"
  ).length;

  const suspiciousUrls = data.indicators.urls.filter(
    (url) => url.risk_flags.length > 0
  ).length;

  const riskyAttachments = data.indicators.attachments.filter(
    (attachment) => attachment.risk_flags.length > 0
  ).length;

  return (
    <section className="evidence-section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Forensic Evidence</p>
          <h2>Threat Evidence Summary</h2>
        </div>

        <div className="case-chip">
          Case: {data.case_id}
        </div>
      </div>

      <div className="evidence-grid">
        <article className="evidence-card">
          <MailWarning size={26} />
          <p>Identity anomalies</p>
          <strong>
            {data.sender_identity.analysis.risk_flags.length}
          </strong>
          <span>
            From / Reply-To / brand consistency findings
          </span>
        </article>

        <article className="evidence-card">
          <ShieldAlert size={26} />
          <p>Authentication</p>
          <div className="auth-chip-row">
            <span className={getAuthClass(auth.spf)}>
              SPF: {auth.spf.toUpperCase()}
            </span>
            <span className={getAuthClass(auth.dkim)}>
              DKIM: {auth.dkim.toUpperCase()}
            </span>
            <span className={getAuthClass(auth.dmarc)}>
              DMARC: {auth.dmarc.toUpperCase()}
            </span>
          </div>
        </article>

        <article className="evidence-card">
          <Link size={26} />
          <p>Suspicious URLs</p>
          <strong>{suspiciousUrls}</strong>
          <span>Hidden links, shortened URLs, or TI matches</span>
        </article>

        <article className="evidence-card">
          <FileWarning size={26} />
          <p>Risky attachments</p>
          <strong>{riskyAttachments}</strong>
          <span>Dangerous extensions or macro-enabled files</span>
        </article>

        <article className="evidence-card critical-card">
          <AlertTriangle size={26} />
          <p>Critical findings</p>
          <strong>{criticalCount}</strong>
          <span>{highCount} additional high-severity findings</span>
        </article>
      </div>

      <div className="finding-list">
        {findings.map((finding, index) => (
          <article
            className={`finding-item ${getSeverityClass(
              finding.severity
            )}`}
            key={`${finding.category}-${index}`}
          >
            <span className="finding-severity">
              {finding.severity.toUpperCase()}
            </span>

            <div>
              <strong>{finding.category.replaceAll("_", " ")}</strong>
              <p>{finding.message}</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

export default EvidenceCards;