import React, { useEffect, useState } from "react";
import { useNavigate, useSearchParams, useParams } from "react-router-dom";
import {
  ShieldAlert, ChevronLeft, FileText, GitBranch, Plus, Download,
  CheckCircle2, Layers3
} from "lucide-react";
import { getCase, getCaseAnalyses, getAnalysis } from "../api";
import { reportsApi } from "../api/modules";
import { getSession, roleOf } from "../utils/auth";
import { can } from "../utils/permissions";
import {
  PageHeader, GlassCard, Section, RiskBadge, StatusBadge,
  LoadingState, ErrorState, DataTable, EmptyState, CopyButton, Modal
} from "../components/ui";
import ThreatMap from "../components/ThreatMap";

const tabs = [
  ["overview", "Overview", "case:view"],
  ["authentication", "Authentication", "authentication:view"],
  ["relay", "Relay Timeline", "relay:view"],
  ["infrastructure", "Infrastructure", "infrastructure:view"],
  ["iocs", "IOCs", "ioc:view"],
  ["findings", "Findings", "case:view"],
  ["evidence", "Evidence", "evidence:view"],
  ["graph", "IOC Graph", "graph:view"],
  ["campaigns", "Campaigns", "campaign:view"],
  ["features", "Features", "investigation:view"],
  ["reports", "Reports", "report:view"],
];

const rows = (d, key) => Array.isArray(d?.[key]) ? d[key] : [];

function normalizeAnalysis(a) {
  if (!a) return null;
  const email = a.email || {};
  const metadata = email.metadata || {};
  const forensic = email.forensic_report || metadata.raw_forensic_result || {};
  const auth = metadata.authentication || forensic.authentication || forensic.auth || {};
  const relay = forensic.relay_analysis || {};

  return {
    ...a,
    risk_score: a.final_risk_score ?? a.risk_score ?? a.score ?? "—",
    risk_level: a.risk_level || a.risk || "UNKNOWN",
    confidence: a.ml_confidence ?? a.confidence ?? "—",
    findings: rows(a, "findings"),
    iocs: rows(a, "iocs"),
    timeline: rows(a, "timeline"),
    graph: a.graph || a.graph_json || null,
    authentication: a.authentication || auth,
    relay_timeline: a.relay_timeline || a.timeline || relay.hops || [],
    infrastructure: a.infrastructure || [],
    evidence: a.evidence || [],
    features: a.features || metadata.advanced_features || {},
    email,
    risk_breakdown: a.risk_breakdown || {
      ml_score: a.ml_risk_score != null ? Number(a.ml_risk_score) * 100 : "—",
      forensic_score: a.forensic_score != null ? Number(a.forensic_score) * 100 : "—",
      advanced_score: a.advanced_score != null ? Number(a.advanced_score) * 100 : "—",
    },
  };
}

export default function Investigation({ caseId: propCaseId }) {
  const { caseId: routeCaseId } = useParams();
  const caseId = propCaseId || routeCaseId;
  const [searchParams] = useSearchParams();
  const analysisId = searchParams.get("analysisId");
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [caseData, setCaseData] = useState(null);
  const [err, setErr] = useState(null);
  const [tab, setTab] = useState("overview");
  const [modal, setModal] = useState(false);
  const role = roleOf(getSession());

  useEffect(() => {
    let alive = true;
    async function load() {
      if (!caseId) {
        setErr(new Error("No case ID was supplied."));
        return;
      }
      setErr(null);
      try {
        const c = await getCase(caseId);
        if (!alive) return;
        setCaseData(c.data);

        let selectedId = analysisId;
        if (!selectedId) {
          const list = await getCaseAnalyses(caseId);
          const analyses = list.data?.analyses || [];
          selectedId = analyses[0]?.id;
        }

        if (!selectedId) {
          setData({
            id: null,
            case_id: Number(caseId),
            classification: "PENDING",
            risk_level: c.data?.severity || "LOW",
            risk_score: "—",
            findings: [], iocs: [], timeline: [], graph: null,
            email: {}, authentication: {}, evidence: [], features: {}
          });
          return;
        }

        const a = await getAnalysis(selectedId);
        if (alive) setData(normalizeAnalysis(a.data));
      } catch (e) {
        if (alive) setErr(e);
      }
    }
    load();
    return () => { alive = false; };
  }, [caseId, analysisId]);

  if (err) return <ErrorState error={err} />;
  if (!data || !caseData) return <LoadingState text="Loading forensic case workspace…" />;

  const email = data.email || {};
  const subject = email.subject || caseData.subject || caseData.title || caseData.name || "Investigation workspace";
  const sender = email.sender || caseData.sender || "Forensic investigation";

  return (
    <>
      <button className="back-btn" onClick={() => navigate("/cases")}>
        <ChevronLeft size={16} /> Cases
      </button>

      <PageHeader
        eyebrow={`CASE / ${caseId}`}
        title={subject}
        subtitle={sender}
        actions={
          <>
            <RiskBadge level={data.risk_level} />
            <StatusBadge status={caseData.status || "OPEN"} />
          </>
        }
      />

      <div className="case-strip">
        <div><span>Case ID</span><b>{caseId}</b></div>
        <div><span>Classification</span><b>{data.classification || "—"}</b></div>
        <div><span>Risk score</span><b>{formatScore(data.risk_score)}</b></div>
        <div><span>Analysis ID</span><b>{data.id || "—"}</b></div>
      </div>

      <div className="tabs">
        {tabs.filter(t => can(role, t[2])).map(t => (
          <button className={tab === t[0] ? "active" : ""} onClick={() => setTab(t[0])} key={t[0]}>
            {t[1]}
          </button>
        ))}
      </div>

      {tab === "overview" && <Overview data={data} />}
      {tab === "authentication" && <Authentication data={data} />}
      {tab === "relay" && <Relay data={data} />}
      {tab === "infrastructure" && <Infrastructure data={data} />}
      {tab === "iocs" && <IOCs data={data} />}
      {tab === "findings" && <Findings data={data} canEdit={can(role, "finding:create")} onAdd={() => setModal(true)} />}
      {tab === "evidence" && <Evidence data={data} />}
      {tab === "graph" && <Graph data={data} />}
      {tab === "campaigns" && <Campaigns data={data} />}
      {tab === "features" && <Features data={data} />}
      {tab === "reports" && <CaseReports caseId={caseId} />}

      <Modal
        open={modal}
        onClose={() => setModal(false)}
        title="Add forensic finding"
        actions={<button className="primary" onClick={() => setModal(false)}>Save finding</button>}
      >
        <label>Finding<input placeholder="Finding title" /></label>
        <label>Severity<select><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>CRITICAL</option></select></label>
        <label>Notes<textarea placeholder="Analyst evidence and rationale…" /></label>
      </Modal>
    </>
  );
}

function formatScore(v) {
  if (v === "—" || v == null) return "—";
  const n = Number(v);
  if (!Number.isFinite(n)) return String(v);
  return n <= 1 ? `${(n * 100).toFixed(1)}%` : `${n.toFixed(1)}%`;
}

function Overview({ data }) {
  const findings = rows(data, "findings");
  const rb = data.risk_breakdown || {};
  return <>
    <div className="hero-grid">
      <GlassCard className="risk-score">
        <span>Overall Risk Score</span>
        <strong>{formatScore(data.risk_score)}</strong>
        <RiskBadge level={data.risk_level} />
        <small>System-generated risk assessment</small>
      </GlassCard>
      <GlassCard>
        <div className="card-title">Classification</div>
        <h3>{data.classification || "—"}</h3>
        <p>Confidence: {data.confidence === "—" ? "—" : formatScore(data.confidence)}</p>
      </GlassCard>
      <GlassCard>
        <div className="card-title">Why this email was flagged</div>
        {findings.length ? <ul className="finding-list">{findings.slice(0, 6).map((f, i) => <li key={i}><ShieldAlert size={16}/><span>{f.title || f.finding || f.description || "Finding returned by backend"}</span></li>)}</ul> : <EmptyState title="No findings returned" text="The case analysis has not supplied forensic findings."/>}
      </GlassCard>
    </div>
    <Section title="Risk Breakdown" subtitle="System scoring components returned by the analysis service">
      <div className="score-grid">
        {[["ML Detection", rb.ml_score ?? rb.ml ?? "—"], ["Forensic Evidence", rb.forensic_score ?? rb.forensic ?? "—"], ["Advanced Intelligence", rb.advanced_score ?? rb.advanced ?? "—"]].map(([label, value]) => {
          const n = Number(value);
          const pct = Number.isFinite(n) ? (n <= 1 ? n * 100 : n) : 0;
          return <GlassCard key={label}><span>{label}</span><strong>{value === "—" ? "—" : `${pct.toFixed(1)}%`}</strong><div className="progress"><i style={{width:`${Math.min(100, Math.max(0, pct))}%`}}/></div></GlassCard>;
        })}
      </div>
    </Section>
  </>;
}

function Authentication({data}){const a=data.authentication||{};return <Section title="Email Authentication" subtitle="Forensic comparison of identity and authentication signals"><div className="auth-grid">{["spf","dkim","dmarc"].map(k=><GlassCard key={k}><span>{k.toUpperCase()}</span><div className="auth-status">{a[k]?.status||a[k]||"UNKNOWN"}</div><small>{a[k]?.reason||"No explanation returned by backend."}</small></GlassCard>)}</div><GlassCard className="forensic-fields"><b>Header identity</b>{["from","return_path","reply_to","authentication_results"].map(k=><div key={k}><span>{k.replaceAll("_"," ")}</span><code>{a[k]||"—"}</code><CopyButton value={a[k]}/></div>)}</GlassCard></Section>}
function Relay({data}){const hops=rows(data,"relay_timeline");return <Section title="Relay Timeline" subtitle="Received-header infrastructure path"><div className="timeline">{hops.length?hops.map((h,i)=><div className="timeline-item" key={i}><div className="timeline-dot"/><GlassCard><div className="timeline-head"><b>{h.hostname||h.host||h.ip||"Mail infrastructure"}</b><span>{h.timestamp||h.date||"—"}</span></div><div className="mini-grid"><span>IP <b>{h.ip||"—"}</b></span><span>Provider <b>{h.provider||h.asn_organization||"—"}</b></span><span>Country <b>{h.country||h.geolocation?.country||"—"}</b></span><span>ASN <b>{h.asn||h.geolocation?.asn||"—"}</b></span></div></GlassCard></div>):<EmptyState title="No relay hops returned" text="Received headers or relay telemetry are not available for this case."/>}</div><div className="notice">Infrastructure geolocation is contextual intelligence and does not prove the physical identity/location of the sender.</div></Section>}
function Infrastructure({data}){return <Section title="Infrastructure Map" subtitle="GeoIP context for infrastructure indicators"><ThreatMap points={rows(data,"infrastructure").concat(rows(data,"relay_timeline"))}/></Section>}
function IOCs({data}){const list=rows(data,"iocs");return <Section title="IOC Intelligence" subtitle="Indicators extracted or associated with this investigation"><DataTable rows={list} columns={[{key:"type",label:"Type"},{key:"value",label:"Value",render:r=><span className="mono">{r.value||r.indicator||"—"}</span>},{key:"source",label:"Source"},{key:"risk",label:"Risk",render:r=><RiskBadge level={r.risk||r.risk_level}/>} ,{key:"confidence",label:"Confidence"} ]}/></Section>}
function Findings({data,canEdit,onAdd}){const list=rows(data,"findings");return <Section title="Forensic Findings" subtitle="Evidence-backed observations from analysis" actions={canEdit&&<button className="secondary" onClick={onAdd}><Plus size={16}/>Add finding</button>}><DataTable rows={list} columns={[{key:"title",label:"Finding",render:r=>r.title||r.finding},{key:"severity",label:"Severity",render:r=><RiskBadge level={r.severity}/>} ,{key:"category",label:"Category"},{key:"evidence",label:"Evidence"},{key:"confidence",label:"Confidence"} ]}/></Section>}
function Evidence({data}){const list=rows(data,"evidence");return <Section title="Evidence & Chain of Custody" subtitle="Integrity state returned by the evidence service"><DataTable rows={list} columns={[{key:"evidence_id",label:"Evidence ID"},{key:"file_name",label:"File name"},{key:"sha256",label:"SHA-256",render:r=><span className="hash">{r.sha256||"—"}</span>},{key:"collected_at",label:"Collection time"},{key:"source",label:"Source"},{key:"integrity_status",label:"Integrity",render:r=><span className="integrity"><CheckCircle2 size={14}/>{r.integrity_status||"—"}</span>}]}/></Section>}
function Graph({data}){const g=data.graph;return <Section title="IOC Graph" subtitle="Relationship graph returned by backend"><GlassCard className="graph"><GitBranch size={25}/><h3>{g?"Investigation graph loaded":"No graph data returned"}</h3><p>{g?"Graph payload is available for investigation context.":"The backend has not returned graph data for this case."}</p></GlassCard></Section>}
function Campaigns({data}){const c=data.campaign||data.campaigns;return <Section title="Campaign Correlation" subtitle="Heuristic relationships must not be interpreted as confirmed attribution"><GlassCard className="campaign"><Layers3/><div><h3>{c?.name||c?.id||"No campaign cluster returned"}</h3><p>{c?.summary||"Shared infrastructure and indicators will appear when returned by the backend."}</p></div></GlassCard></Section>}
const featureList=["Multilingual Detection","BEC / Impersonation","Lookalike Domain Detection","URL Obfuscation","Cross-Case Campaign Correlation","Infrastructure Fingerprinting","Explainable Risk Breakdown","Investigation Graph","Evidence Hash Chain","Privacy Mode","Attachment Forensics","QR / Quishing Detection","Gmail Alert Integration","Natural Language Investigation Search","Analyst Copilot","Advanced Reports","Advanced Analytics"];
function Features({data}){const f=data.features||{};return <Section title="Advanced Intelligence" subtitle="Implementation status is derived from backend capability signals"><div className="feature-grid">{featureList.map(x=>{const key=x.toLowerCase().replace(/[^a-z0-9]+/g,"_");const v=f[key]??f[x];return <GlassCard key={x}><div className="feature-top"><span>{x}</span><StatusBadge status={v?.status||"HOOK_AVAILABLE"}/></div><p>{v?.description||"Backend capability signal not provided. UI does not infer completion."}</p>{v?.signal&&<small>Signal: {v.signal}</small>}</GlassCard>})}</div></Section>}
function CaseReports({caseId}){const [busy,setBusy]=useState(false);const generate=async()=>{setBusy(true);try{await reportsApi.generate({case_id:Number(caseId),type:"forensic_pdf"})}finally{setBusy(false)}};return <Section title="Reports" subtitle="Generate artifacts from backend-supported report types"><div className="report-actions"><button className="primary" onClick={generate} disabled={busy}><FileText size={17}/>{busy?"Generating…":"Generate Forensic PDF"}</button><button className="secondary"><Download size={17}/>JSON Evidence Report</button></div></Section>}
