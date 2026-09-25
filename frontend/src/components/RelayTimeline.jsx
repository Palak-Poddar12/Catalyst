import {
  CheckCircle2,
  CircleAlert,
  Server,
  ShieldCheck,
} from "lucide-react";

function formatDate(timestamp) {
  if (!timestamp) return "Timestamp unavailable";

  return new Date(timestamp).toLocaleString();
}

function RelayTimeline({ relayAnalysis }) {
  const hops = relayAnalysis.received_hops || [];

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Mail-route evidence</p>
          <h2>Relay Timeline</h2>
        </div>

        <span className="count-badge">
          {hops.length} hop{hops.length === 1 ? "" : "s"}
        </span>
      </div>

      <div className="timeline">
        {hops.map((hop) => {
          const hasRisk = hop.risk_flags.length > 0;

          return (
            <article className="timeline-item" key={hop.hop}>
              <div
                className={`timeline-node ${
                  hasRisk ? "node-risk" : "node-safe"
                }`}
              >
                {hop.trusted ? (
                  <ShieldCheck size={18} />
                ) : hasRisk ? (
                  <CircleAlert size={18} />
                ) : (
                  <CheckCircle2 size={18} />
                )}
              </div>

              <div className="timeline-content">
                <div className="timeline-topline">
                  <span className="hop-label">Hop {hop.hop}</span>

                  <span
                    className={`trust-badge ${
                      hop.trusted
                        ? "trusted"
                        : "untrusted"
                    }`}
                  >
                    {hop.trusted ? "Trusted" : "Untrusted"}
                  </span>
                </div>

                <h3>
                  {hop.from_host} <span>→</span> {hop.by_host}
                </h3>

                <div className="timeline-meta">
                  <span>
                    <Server size={15} />
                    {hop.ip || "IP unavailable"}
                  </span>

                  <span>{hop.ip_scope}</span>

                  <span>{formatDate(hop.timestamp_utc)}</span>
                </div>

                {hop.risk_flags.length > 0 && (
                  <div className="risk-tag-row">
                    {hop.risk_flags.map((flag) => (
                      <span className="risk-tag" key={flag}>
                        {flag.replaceAll("_", " ")}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

export default RelayTimeline;