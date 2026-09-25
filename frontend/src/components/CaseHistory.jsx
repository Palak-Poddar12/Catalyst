import {
  Clock3,
  Download,
  FileSearch,
  FileText,
  Mail,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";

function formatDate(timestamp) {
  if (!timestamp) return "Unknown time";

  return new Date(timestamp).toLocaleString();
}

function getRiskClass(severity) {
  return `case-risk case-risk-${severity || "safe"}`;
}

function CaseHistory({
  cases,
  isLoading,
  error,
  activeCaseId,
  onRefresh,
  onOpenCase,
  onDownloadCase,
  onDownloadCasePdf,
}) {
  return (
    <section className="case-history-panel">
      <div className="case-history-heading">
        <div>
          <p className="eyebrow">Stored forensic evidence</p>
          <h2>Recent Threat Cases</h2>
        </div>

        <button
          className="refresh-button"
          type="button"
          onClick={onRefresh}
          disabled={isLoading}
        >
          <RefreshCw
            size={16}
            className={isLoading ? "spin-icon" : ""}
          />
          Refresh
        </button>
      </div>

      {error && (
        <div className="case-history-error">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="case-history-empty">
          <RefreshCw size={20} className="spin-icon" />
          Loading saved forensic cases...
        </div>
      ) : cases.length === 0 ? (
        <div className="case-history-empty">
          <FileSearch size={26} />
          <p>No saved forensic cases yet.</p>
          <small>
            Upload and analyze a `.eml` file to create the first case.
          </small>
        </div>
      ) : (
        <div className="case-list">
          {cases.map((caseItem) => (
            <article
              className={
                activeCaseId === caseItem.case_id
                  ? "case-item active-case"
                  : "case-item"
              }
              key={caseItem.case_id}
            >
              <div className="case-item-topline">
                <span
                  className={getRiskClass(
                    caseItem.risk?.severity
                  )}
                >
                  <ShieldAlert size={13} />
                  {caseItem.risk?.severity || "safe"}
                </span>

                <span className="finding-count">
                  {caseItem.finding_count} finding
                  {caseItem.finding_count === 1 ? "" : "s"}
                </span>
              </div>

              <h3>
                {caseItem.subject || "No subject available"}
              </h3>

              <p className="case-sender">
                <Mail size={14} />
                {caseItem.from_address ||
                  caseItem.from_domain ||
                  "Unknown sender"}
              </p>

              <p className="case-time">
                <Clock3 size={14} />
                {formatDate(
                  caseItem.analysis_timestamp_utc
                )}
              </p>

              <div className="case-score-row">
                <span>Risk score</span>
                <strong>
                  {caseItem.risk?.score ?? 0}/100
                </strong>
              </div>

              <div className="case-actions">
                <button
                  className="open-case-button"
                  type="button"
                  onClick={() =>
                    onOpenCase(caseItem.case_id)
                  }
                >
                  Open Case
                </button>

                <button
                  className="download-case-button"
                  type="button"
                  onClick={() =>
                    onDownloadCase(caseItem.case_id)
                  }
                  title="Download JSON forensic report"
                >
                  <Download size={16} />
                  <span>JSON</span>
                </button>

                <button
                  className="download-case-button"
                  type="button"
                  onClick={() =>
                    onDownloadCasePdf(caseItem.case_id)
                  }
                  title="Generate and download PDF forensic report"
                >
                  <FileText size={16} />
                  <span>PDF</span>
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

export default CaseHistory;