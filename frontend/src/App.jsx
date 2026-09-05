import { useEffect, useState } from "react";
import {
  Activity,
  FileCheck2,
  ShieldCheck,
  Upload,
} from "lucide-react";

import "./App.css";

import CaseHistory from "./components/CaseHistory";
import EvidenceCards from "./components/EvidenceCards";
import InfrastructureMap from "./components/InfrastructureMap";
import IocGraph from "./components/IocGraph";
import OriginConfidence from "./components/OriginConfidence";
import RelayTimeline from "./components/RelayTimeline";
import ThreatAlert from "./components/ThreatAlert";

import sampleForensicData from "./data/sampleForensicData";

const API_URL =
  "http://127.0.0.1:8000/api/v1/emails/analyze-jobs";

const CASES_API_URL =
  "http://127.0.0.1:8000/api/v1/cases";

function normalizeForensicData(rawData) {
  const safeData = rawData || {};

  const safeIndicators = safeData.indicators || {};

  const safeIps = (safeIndicators.ips || []).map((ipItem) => ({
    ...ipItem,
    risk_flags: ipItem.risk_flags || [],
    geolocation: ipItem.geolocation || {
      country: "",
      city: "",
      subdivision: "",
      latitude: null,
      longitude: null,
      accuracy_radius_km: null,
      asn: null,
      asn_organization: "",
    },
    reputation: ipItem.reputation || {
      source: "not_available",
      status: "not_available",
      abuse_confidence_score: 0,
      risk_flags: [],
    },
  }));

  const safeUrls = (safeIndicators.urls || []).map((urlItem) => ({
    ...urlItem,
    risk_flags: urlItem.risk_flags || [],
    reputation: urlItem.reputation || {
      source: "not_available",
      status: "not_available",
      threat: "",
      risk_flags: [],
    },
  }));

  const safeAttachments = (
    safeIndicators.attachments || []
  ).map((attachment) => ({
    ...attachment,
    risk_flags: attachment.risk_flags || [],
  }));

  const safeRelayAnalysis = safeData.relay_analysis || {};

  const safeReceivedHops = (
    safeRelayAnalysis.received_hops || []
  ).map((hop) => ({
    ...hop,
    risk_flags: hop.risk_flags || [],
    trusted: Boolean(hop.trusted),
    timestamp_utc: hop.timestamp_utc || "",
    ip_scope: hop.ip_scope || "unknown",
  }));

  const safeProbableSource =
    safeRelayAnalysis.probable_source || {
      earliest_visible_public_hop: null,
      confidence: "low",
      limitation:
        "No source-infrastructure assessment is available.",
    };

  const safeSenderIdentity =
    safeData.sender_identity || {};

  const safeAuth =
    safeData.email_authentication || {};

  return {
    ...safeData,

    sender_identity: {
      ...safeSenderIdentity,
      from: safeSenderIdentity.from || {},
      reply_to: safeSenderIdentity.reply_to || {},
      return_path: safeSenderIdentity.return_path || {},
      sender: safeSenderIdentity.sender || {},
      analysis: safeSenderIdentity.analysis || {
        risk_flags: [],
        findings: [],
      },
    },

    email_authentication: {
      ...safeAuth,
      reported_results: safeAuth.reported_results || {
        spf: "none",
        dkim: "none",
        dmarc: "none",
      },
      dmarc_forensic_assessment:
        safeAuth.dmarc_forensic_assessment || {
          assessment: "inconclusive",
          visible_from_domain: "",
          dmarc_dns_policy: "unknown",
        },
    },

    relay_analysis: {
      ...safeRelayAnalysis,
      received_hops: safeReceivedHops,
      probable_source: safeProbableSource,
    },

    indicators: {
      ...safeIndicators,
      ips: safeIps,
      urls: safeUrls,
      domains: safeIndicators.domains || [],
      attachments: safeAttachments,
    },

    forensic_findings: safeData.forensic_findings || [],
  };
}

function App() {
  const [data, setData] = useState(
    normalizeForensicData(sampleForensicData)
  );
  const [selectedFile, setSelectedFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isDemoMode, setIsDemoMode] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");
  const [risk, setRisk] = useState(null);

  const [cases, setCases] = useState([]);
  const [isLoadingCases, setIsLoadingCases] = useState(false);
  const [caseHistoryError, setCaseHistoryError] = useState("");

  const loadCases = async () => {
    setIsLoadingCases(true);
    setCaseHistoryError("");

    try {
      const response = await fetch(CASES_API_URL);
      const responseData = await response.json();

      if (!response.ok) {
        throw new Error(
          responseData.detail ||
            "Could not load saved forensic cases."
        );
      }

      setCases(responseData.cases || []);
    } catch (error) {
      setCaseHistoryError(
        error.message ||
          "Could not connect to the case-history API."
      );
    } finally {
      setIsLoadingCases(false);
    }
  };

  const openCase = async (caseId) => {
    setErrorMessage("");

    try {
      const response = await fetch(
        `${CASES_API_URL}/${caseId}`
      );

      const responseData = await response.json();

      if (!response.ok) {
        throw new Error(
          responseData.detail ||
            "Could not open the selected forensic case."
        );
      }

      setData(normalizeForensicData(responseData));
      setRisk(null);
      setIsDemoMode(false);
      setSelectedFile(null);
    } catch (error) {
      setErrorMessage(
        error.message ||
          "Could not open the selected case."
      );
    }
  };

  const downloadCase = (caseId) => {
    window.open(
      `${CASES_API_URL}/${caseId}/download`,
      "_blank",
      "noopener,noreferrer"
    );
  };

  const downloadCasePdf = (caseId) => {
    window.open(
      `${CASES_API_URL}/${caseId}/pdf`,
      "_blank",
      "noopener,noreferrer"
    );
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleFileChange = (event) => {
    const file = event.target.files?.[0] || null;

    setSelectedFile(file);
    setErrorMessage("");
  };

  const analyzeEmail = async () => {
    if (!selectedFile) {
      setErrorMessage(
        "Select a .eml email file before starting analysis."
      );
      return;
    }

    if (!selectedFile.name.toLowerCase().endsWith(".eml")) {
      setErrorMessage(
        "Only .eml email files are supported."
      );
      return;
    }

    setIsAnalyzing(true);
    setErrorMessage("");

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const createResponse = await fetch(API_URL, {
        method: "POST",
        body: formData,
      });

      const createData = await createResponse.json().catch(() => null);

      if (!createResponse.ok) {
        throw new Error(
          createData?.detail ||
            "Could not create forensic analysis job."
        );
      }

      if (!createData?.job_id) {
        throw new Error(
          "The forensic API did not return an analysis job ID."
        );
      }

      const jobId = createData.job_id;
      let completed = false;
      let attempts = 0;
      const maxAttempts = 80;

      while (!completed && attempts < maxAttempts) {
        await new Promise((resolve) => {
          setTimeout(resolve, 1500);
        });

        const statusResponse = await fetch(
          `${API_URL}/${jobId}`
        );

        const statusData = await statusResponse.json().catch(() => null);

        if (!statusResponse.ok) {
          throw new Error(
            statusData?.detail ||
              "Could not retrieve analysis status."
          );
        }

        // Guard against an empty/null API response so the UI never
        // crashes with: "Cannot read properties of null (reading 'status')".
        if (!statusData || typeof statusData !== "object") {
          throw new Error(
            "The forensic API returned an empty analysis-status response."
          );
        }

        if (statusData.status === "completed") {
          if (!statusData.forensic_result) {
            throw new Error(
              "Analysis completed but no forensic result was returned."
            );
          }

          setData(
            normalizeForensicData(statusData.forensic_result)
          );
          setRisk(statusData.risk || null);
          setIsDemoMode(false);
          await loadCases();
          completed = true;
        }

        if (statusData.status === "failed") {
          throw new Error(
            statusData.error ||
              "Forensic analysis failed."
          );
        }

        attempts += 1;
      }

      if (!completed) {
        throw new Error(
          "Analysis took too long. Please try again."
        );
      }
    } catch (error) {
      setErrorMessage(
        error.message ||
          "Could not connect to the forensic API."
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const loadDemoData = () => {
    setData(
      normalizeForensicData(sampleForensicData)
    );
    setSelectedFile(null);
    setErrorMessage("");
    setRisk(null);
    setIsDemoMode(true);
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>

          <div>
            <p className="eyebrow">SatGuard</p>
            <h1>Email Forensic Intelligence</h1>
          </div>
        </div>

        <div
          className={
            isDemoMode
              ? "topbar-status demo-status"
              : "topbar-status live-status"
          }
        >
          <Activity size={17} />
          {isDemoMode
            ? "Demo workspace"
            : "Live forensic result"}
        </div>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">
            Email threat investigation platform
          </p>

          <h2>
            Upload an email. Preserve evidence. Reveal the threat trail.
          </h2>

          <p>
            SatGuard analyzes raw email headers, authentication evidence,
            sender identity, suspicious URLs, attachments, relay
            infrastructure, and forensic indicators.
          </p>
        </div>

        <div className="evidence-proof">
          <FileCheck2 size={30} />

          <div>
            <span>Evidence integrity</span>
            <strong>SHA-256 preserved</strong>
          </div>
        </div>
      </section>

      <section className="upload-panel">
        <div className="upload-heading">
          <div>
            <p className="eyebrow">
              Real email analysis
            </p>

            <h2>Upload `.eml` File</h2>

            <p>
              The original email is hashed before Member 1 forensic
              analysis begins.
            </p>
          </div>

          <Upload size={28} />
        </div>

        <div className="upload-controls">
          <label className="file-picker">
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={handleFileChange}
              disabled={isAnalyzing}
            />

            <span>
              {selectedFile
                ? selectedFile.name
                : "Choose a .eml email file"}
            </span>
          </label>

          <button
            className="analyze-button"
            type="button"
            onClick={analyzeEmail}
            disabled={isAnalyzing || !selectedFile}
          >
            {isAnalyzing
              ? "Analyzing Evidence..."
              : "Analyze Email"}
          </button>

          <button
            className="demo-button"
            type="button"
            onClick={loadDemoData}
            disabled={isAnalyzing}
          >
            Load Demo Case
          </button>
        </div>

        {selectedFile && (
          <p className="selected-file-note">
            Selected: {selectedFile.name} ·{" "}
            {(selectedFile.size / 1024).toFixed(1)} KB
          </p>
        )}

        {errorMessage && (
          <div className="upload-error">
            {errorMessage}
          </div>
        )}
      </section>

      <ThreatAlert
        risk={risk}
        isDemoMode={isDemoMode}
      />

      <CaseHistory
        cases={cases}
        isLoading={isLoadingCases}
        error={caseHistoryError}
        activeCaseId={isDemoMode ? "" : data.case_id}
        onRefresh={loadCases}
        onOpenCase={openCase}
        onDownloadCase={downloadCase}
        onDownloadCasePdf={downloadCasePdf}
      />

      <EvidenceCards data={data} />

      <section className="two-column-layout">
        <OriginConfidence
          probableSource={data.relay_analysis.probable_source}
        />

        <RelayTimeline
          relayAnalysis={data.relay_analysis}
        />
      </section>

      <InfrastructureMap
        ipIndicators={data.indicators.ips}
        receivedHops={data.relay_analysis.received_hops}
      />

      <IocGraph data={data} />

      <footer className="footer-note">
        <p>
          SatGuard provides evidence-based infrastructure intelligence.
          IP data represents approximate network context, not a confirmed
          attacker identity or exact physical location.
        </p>
      </footer>
    </main>
  );
}

export default App;