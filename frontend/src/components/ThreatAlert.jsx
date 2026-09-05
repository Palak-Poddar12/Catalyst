import {
  AlertOctagon,
  CircleCheck,
  ShieldAlert,
  TriangleAlert,
} from "lucide-react";

function getAlertContent(risk) {
  const severity = risk?.severity || "safe";

  if (severity === "critical") {
    return {
      icon: <AlertOctagon size={25} />,
      title: "Critical Threat Alert",
      message:
        "High-confidence forensic indicators require immediate analyst review. Do not interact with links or attachments.",
      className: "alert-critical",
    };
  }

  if (severity === "high") {
    return {
      icon: <ShieldAlert size={25} />,
      title: "High-Risk Email Alert",
      message:
        "Multiple high-severity forensic findings were detected. Escalate this email for investigation.",
      className: "alert-high",
    };
  }

  if (severity === "medium") {
    return {
      icon: <TriangleAlert size={25} />,
      title: "Suspicious Email Alert",
      message:
        "The email contains indicators that require analyst validation before user action.",
      className: "alert-medium",
    };
  }

  return {
    icon: <CircleCheck size={25} />,
    title: "No Critical Evidence Detected",
    message:
      "No critical forensic indicators were identified by the current rule set. Continue normal review procedures.",
    className: "alert-safe",
  };
}

function ThreatAlert({ risk, isDemoMode }) {
  if (isDemoMode) {
    return (
      <section className="threat-alert alert-demo">
        <ShieldAlert size={25} />

        <div>
          <h2>Demo Evidence View</h2>
          <p>
            Upload a local `.eml` file to run the real Member 1
            forensic engine and generate a live investigation result.
          </p>
        </div>
      </section>
    );
  }

  const alert = getAlertContent(risk);

  return (
    <section className={`threat-alert ${alert.className}`}>
      {alert.icon}

      <div>
        <h2>{alert.title}</h2>
        <p>{alert.message}</p>

        <div className="alert-metrics">
          <span>Score: {risk?.score ?? 0}/100</span>
          <span>
            Critical: {risk?.critical_findings ?? 0}
          </span>
          <span>High: {risk?.high_findings ?? 0}</span>
          <span>
            Medium: {risk?.medium_findings ?? 0}
          </span>
        </div>
      </div>
    </section>
  );
}

export default ThreatAlert;