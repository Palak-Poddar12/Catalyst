import React, { useMemo, useState } from "react";
import { UploadCloud, FileCheck2, ShieldCheck, ArrowDown, Loader2, Eye, FileText, Play, X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { createCase, uploadEmail } from "../api";
import { PageHeader, GlassCard, Section, ErrorState } from "../components/ui";

const steps = ["EMAIL", "MIME PARSER", "HEADER ANALYSIS", "AUTHENTICATION", "IOC EXTRACTION", "THREAT INTELLIGENCE", "RISK ENGINE", "INVESTIGATION"];

const mailLibrary = [
  {
    file: "account-security-review.eml",
    title: "Account Security Review Required",
    sender: "security@northstar-account.example",
    subject: "Immediate verification required",
    summary: "Urgent account verification message with sender mismatch, authentication failures and a credential URL.",
  },
  {
    file: "invoice-payment-review.eml",
    title: "Outstanding Invoice Notification",
    sender: "billing@meridian-payments.example",
    subject: "Payment confirmation required today",
    summary: "Payment-themed message containing a suspicious link and relay infrastructure indicators.",
  },
  {
    file: "shared-document-review.eml",
    title: "Shared Document Notification",
    sender: "documents@collabdesk.example",
    subject: "A document has been shared with you",
    summary: "Document-sharing lure with identity anomalies, authentication failures and a verification URL.",
  },
];

export default function NewInvestigation() {
  const nav = useNavigate();
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [preview, setPreview] = useState(null);

  const selectedName = useMemo(() => file?.name || "", [file]);

  async function useLibraryMail(item) {
    setErr(null);
    try {
      const response = await fetch(`/demo-mails/${item.file}`);
      if (!response.ok) throw new Error("Unable to load the investigation email.");
      const blob = await response.blob();
      setFile(new File([blob], item.file, { type: "message/rfc822" }));
      setPreview(null);
    } catch (e) {
      setErr(e);
    }
  }

  async function previewMail(item) {
    setErr(null);
    try {
      const response = await fetch(`/demo-mails/${item.file}`);
      if (!response.ok) throw new Error("Unable to load the email preview.");
      setPreview({ ...item, raw: await response.text() });
    } catch (e) {
      setErr(e);
    }
  }

  async function run() {
    if (!file) return;
    setBusy(true);
    setErr(null);
    try {
      const caseData = await createCase({
        title: `Email Investigation - ${file.name}`,
        name: `Email Investigation - ${file.name}`,
        description: "Email forensic investigation",
        severity: "LOW",
      });
      const result = await uploadEmail(caseData.id, file);
      if (!result?.analysis_id) throw new Error("Analysis was not created by the backend.");
      nav(`/cases/${caseData.id}`);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader eyebrow="INVESTIGATIONS / NEW" title="New Email Investigation" subtitle="Upload an .eml artifact and turn the message into an evidence-backed investigation." />

      <div className="two-col investigation-ingest-grid">
        <Section title="Email artifact" subtitle="Preserve the original message and inspect the resulting evidence trail.">
          <label className="dropzone">
            <input type="file" accept=".eml,message/rfc822" onChange={(e) => setFile(e.target.files?.[0] || null)} disabled={busy} />
            <UploadCloud size={30} />
            <b>{file ? file.name : "Drop .eml evidence here"}</b>
            <span>{file ? `${(file.size / 1024).toFixed(1)} KB selected` : "or browse from this device"}</span>
          </label>

          {file && <GlassCard className="file-meta"><FileCheck2 /><div><b>{file.name}</b><span>Size: {(file.size / 1024).toFixed(1)} KB</span><span>SHA-256: calculated during ingestion</span></div></GlassCard>}
          {err && <ErrorState error={err} />}
          <button className="primary wide" disabled={!file || busy} onClick={run}>
            {busy ? <><Loader2 className="spin" /> Running investigation…</> : <><ShieldCheck size={17} /> Start forensic analysis</>}
          </button>
        </Section>

        <Section title="Investigation pipeline" subtitle="The result opens directly in the investigation workspace.">
          <div className="pipeline">
            {steps.map((step, index) => <React.Fragment key={step}><div className={`pipeline-node ${file ? "reachable" : ""}`}><span>{index + 1}</span><b>{step}</b></div>{index < steps.length - 1 && <ArrowDown size={17} />}</React.Fragment>)}
          </div>
          <div className="pipeline-note"><ShieldCheck size={16} /><span>The threat score is evidence-derived. When the ML service is unavailable, the forensic signal remains available for the investigation.</span></div>
        </Section>
      </div>

      <Section title="Threat Mail Library" subtitle="Investigation-ready email scenarios with headers, IP infrastructure and domains.">
        <div className="mail-library-grid">
          {mailLibrary.map((item) => <GlassCard className="mail-library-card" key={item.file}>
            <div className="mail-library-icon"><FileText size={20} /></div>
            <div className="mail-library-copy"><b>{item.title}</b><span>{item.sender}</span><small>{item.subject}</small><p>{item.summary}</p></div>
            <div className="mail-library-actions"><button className="secondary" onClick={() => previewMail(item)}><Eye size={15} />Open</button><button className="primary" onClick={() => useLibraryMail(item)}><Play size={15} />Investigate</button></div>
          </GlassCard>)}
        </div>
      </Section>

      {preview && <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && setPreview(null)}><div className="modal mail-preview-modal"><div className="modal-head"><div><div className="eyebrow">EMAIL EVIDENCE</div><h3>{preview.title}</h3></div><button className="icon-btn" onClick={() => setPreview(null)}><X size={18} /></button></div><div className="mail-preview-meta"><span><b>From</b>{preview.sender}</span><span><b>Subject</b>{preview.subject}</span></div><pre className="mail-raw-preview">{preview.raw}</pre><div className="modal-actions"><button className="secondary" onClick={() => setPreview(null)}>Close</button><button className="primary" onClick={() => useLibraryMail(preview)}><Play size={15} />Use for investigation</button></div></div></div>}

      <p className="selected-file-note">Selected evidence: {selectedName || "No file selected"}</p>
    </>
  );
}
