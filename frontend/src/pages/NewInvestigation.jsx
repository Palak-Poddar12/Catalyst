import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  UploadCloud,
  FileCheck2,
  ShieldCheck,
  ArrowDown,
  Loader2,
} from "lucide-react";

import { createCase, uploadEmail } from "../api";
import { PageHeader, GlassCard, Section, ErrorState } from "../components/ui";

const steps = [
  "EMAIL",
  "MIME PARSER",
  "HEADER ANALYSIS",
  "AUTHENTICATION",
  "IOC EXTRACTION",
  "ML CLASSIFICATION",
  "THREAT INTELLIGENCE",
  "RISK ENGINE",
  "INVESTIGATION",
];

export default function NewInvestigation() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const navigate = useNavigate();

  async function run() {
    if (!file) return;

    setBusy(true);
    setErr(null);
    setResult(null);

    try {
      // 1. Create investigation case first
      const caseData = await createCase({
        title: `Email Investigation - ${file.name}`,
        name: `Email Investigation - ${file.name}`,
        description: "Uploaded EML forensic investigation",
        severity: "LOW",
      });

      // 2. Upload the EML against the created case
      const resultData = await uploadEmail(caseData.id, file);

      setResult(resultData);

      const caseId = resultData?.case_id ?? caseData?.id;
      const analysisId = resultData?.analysis_id ?? resultData?.id;

      if (!caseId) throw new Error("Backend did not return a case ID.");

      // Always enter the real case workspace after a successful upload.
      // analysisId is passed so the workspace can load the exact uploaded analysis.
      navigate(`/investigations/${encodeURIComponent(caseId)}${analysisId ? `?analysisId=${encodeURIComponent(analysisId)}` : ""}`, { replace: true });
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="INVESTIGATIONS / NEW"
        title="New Email Investigation"
        subtitle="Upload an .eml artifact and run the backend forensic pipeline."
      />

      <Section
        title="Email artifact"
        subtitle="Original message files remain under backend control"
      >
        <label className="dropzone">
          <input
            type="file"
            accept=".eml,message/rfc822"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />

          <UploadCloud size={30} />

          <b>{file ? file.name : "Drop .eml file here"}</b>

          <span>
            {file
              ? `${(file.size / 1024).toFixed(1)} KB selected`
              : "or browse from this device"}
          </span>
        </label>

        {file && (
          <GlassCard className="file-meta">
            <FileCheck2 />

            <div>
              <b>{file.name}</b>

              <span>
                Size: {(file.size / 1024).toFixed(1)} KB
              </span>

              <span>
                SHA-256: calculated by backend during ingestion
              </span>
            </div>
          </GlassCard>
        )}

        <button
          className="primary"
          disabled={!file || busy}
          onClick={run}
        >
          {busy ? (
            <>
              <Loader2 className="spin" />
              Running forensic analysis…
            </>
          ) : (
            <>
              <ShieldCheck size={17} />
              Run Forensic Analysis
            </>
          )}
        </button>
      </Section>

      {err && <ErrorState error={err} />}

      <Section
        title="Forensic pipeline"
        subtitle="Progress reflects requests made to the existing backend"
      >
        <div className="pipeline">
          {steps.map((step, index) => (
            <React.Fragment key={step}>
              <div
                className={`pipeline-node ${
                  result ? "reachable" : ""
                }`}
              >
                <span>{index + 1}</span>
                <b>{step}</b>
              </div>

              {index < steps.length - 1 && <ArrowDown size={17} />}
            </React.Fragment>
          ))}
        </div>
      </Section>

      {result && (
        <GlassCard className="result-note">
          <b>Backend response received.</b>

          <span>
            Analysis ID:{" "}
            {result.analysis_id || result.id || "—"}.
            Open the returned case/analysis resource to inspect
            forensic evidence.
          </span>
        </GlassCard>
      )}
    </>
  );
}
