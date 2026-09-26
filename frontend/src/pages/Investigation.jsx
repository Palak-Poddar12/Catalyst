import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, ChevronLeft, FileText, Lock, Network, Map, GitBranch, Paperclip, BrainCircuit, Download, CheckCircle2, Copy, ExternalLink } from "lucide-react";
import { getCase, getCaseAnalyses, getAnalysis, getAdvanced, reportPdf } from "../api";
import { PageHeader, GlassCard, Section, RiskBadge, StatusBadge, LoadingState, ErrorState, DataTable, EmptyState } from "../components/ui";
import ThreatMap from "../components/ThreatMap";

const tabs = [["overview","Overview"],["mail","Email"],["authentication","Authentication"],["relay","Relay Timeline"],["infrastructure","Infrastructure Map"],["iocs","IOCs"],["findings","Findings"],["evidence","Evidence"],["graph","IOC Graph"],["features","Advanced Intelligence"],["reports","Report"]];
const arr = (x) => Array.isArray(x) ? x : [];
const pct = (x) => x == null ? "—" : `${Math.round(Number(x) * 100)}%`;

export default function Investigation({ caseId }) {
  const nav = useNavigate();
  const [data, setData] = useState(null);
  const [advanced, setAdvanced] = useState(null);
  const [err, setErr] = useState(null);
  const [tab, setTab] = useState("overview");

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const c = await getCase(caseId);
        const summaries = await getCaseAnalyses(caseId);
        const list = summaries?.data?.analyses || [];
        const latest = list[0];
        if (!latest) throw new Error("This investigation has no completed analysis.");
        const full = await getAnalysis(latest.id);
        const adv = await getAdvanced(latest.id).catch(() => null);
        if (active) { setData({ case: c?.data, analysis: full?.data }); setAdvanced(adv?.data || null); }
      } catch (e) { if (active) setErr(e); }
    })();
    return () => { active = false; };
  }, [caseId]);

  if (err) return <ErrorState error={err} />;
  if (!data) return <LoadingState text="Loading forensic investigation…" />;

  const a = data.analysis || {};
  const email = a.email || {};
  const forensic = email.forensic_report || {};
  const findings = arr(a.findings);
  const iocs = arr(a.iocs);
  const timeline = arr(a.timeline);
  const graph = a.graph || {};
  const breakdown = a.risk_breakdown || {};
  const sourceIp = forensic?.message_metadata?.x_originating_ip || forensic?.relay_analysis?.earliest_visible_public_hop?.ip || forensic?.relay_analysis?.probable_source?.earliest_visible_public_hop?.ip;
  const domains = arr(forensic?.indicators?.domains).map((d) => typeof d === "string" ? d : d.domain).filter(Boolean);
  const urls = arr(forensic?.indicators?.urls).map((u) => typeof u === "string" ? u : u.url).filter(Boolean);
  const mode = a.assessment_mode || "ml_plus_forensics";

  return <>
    <button className="back-btn" onClick={() => nav("/cases")}><ChevronLeft size={16}/>Cases</button>
    <PageHeader eyebrow={`CASE / ${caseId}`} title={email.subject || data.case?.title || "Email Investigation"} subtitle={email.sender || "Forensic investigation"} actions={<><RiskBadge level={a.risk_level}/><StatusBadge status={a.classification}/></>} />

    <div className="investigation-score-hero">
      <GlassCard className="primary-threat-score"><div className="eyebrow">THREAT ASSESSMENT</div><strong>{Math.round((a.final_risk_score || 0) * 100)}<small>/100</small></strong><RiskBadge level={a.risk_level}/><span>{mode === "forensic_fallback" ? "Evidence-derived assessment" : "ML + forensic assessment"}</span></GlassCard>
      <GlassCard><div className="score-card-title"><BrainCircuit size={18}/>Classification</div><h2>{a.classification || "UNKNOWN"}</h2><p>{mode === "forensic_fallback" ? "The displayed threat score is derived from independently extracted email-forensic signals." : `Model confidence: ${pct(a.ml_confidence)}`}</p></GlassCard>
      <GlassCard><div className="score-card-title"><ShieldAlert size={18}/>Why it was flagged</div><div className="mini-findings">{findings.slice(0,4).map((f,i)=><span key={i}><b>{String(f.severity||"MEDIUM").toUpperCase()}</b>{f.description || f.title}</span>)}</div></GlassCard>
    </div>

    <div className="investigation-metrics"><Metric label="Threat score" value={`${Math.round((a.final_risk_score||0)*100)}%`} /><Metric label="Forensic signal" value={pct(a.forensic_score)} /><Metric label="ML score" value={a.ml_status === "success" ? pct(a.ml_risk_score) : "Not connected"} /><Metric label="IOCs" value={iocs.length} /><Metric label="Findings" value={findings.length} /><Metric label="Evidence" value={email.metadata?.sha256 ? "SHA-256" : "Stored"} /></div>

    <div className="tabs investigation-tabs">{tabs.map(([id,label]) => <button key={id} className={tab===id?"active":""} onClick={() => setTab(id)}>{label}</button>)}</div>

    {tab === "overview" && <Overview a={a} breakdown={breakdown} findings={findings} />}
    {tab === "mail" && <MailView email={email} forensic={forensic} sourceIp={sourceIp} domains={domains} urls={urls} />}
    {tab === "authentication" && <Authentication forensic={forensic} />}
    {tab === "relay" && <Relay timeline={timeline} forensic={forensic} />}
    {tab === "infrastructure" && <Section title="Infrastructure & Origin Map" subtitle="Approximate network context from public relay infrastructure"><ThreatMap analysisId={a.id} /></Section>}
    {tab === "iocs" && <IOCView iocs={iocs} />}
    {tab === "findings" && <FindingView findings={findings} />}
    {tab === "evidence" && <EvidenceView email={email} forensic={forensic} />}
    {tab === "graph" && <GraphView graph={graph} />}
    {tab === "features" && <AdvancedView advanced={advanced} />}
    {tab === "reports" && <ReportView analysisId={a.id} />}
  </>;
}

function Metric({label,value}) { return <GlassCard className="investigation-metric"><span>{label}</span><strong>{value}</strong></GlassCard>; }
function Overview({a,breakdown,findings}) { return <><Section title="Explainable risk assessment" subtitle="The score is decomposed into the evidence signals available to the investigation."><div className="score-breakdown-grid"><Score label="Threat score" value={breakdown.threat_score ?? Math.round((a.final_risk_score||0)*100)} /><Score label="Forensic evidence" value={breakdown.forensic_score ?? Math.round((a.forensic_score||0)*100)} /><Score label="ML detection" value={breakdown.ml_score} unavailable={breakdown.ml_score == null} /><Score label="ML confidence" value={breakdown.ml_confidence} unavailable={breakdown.ml_confidence == null} /></div></Section><Section title="Evidence-based explanation" subtitle="Signals extracted from the original email."><div className="explanation-grid">{findings.length ? findings.map((f,i)=><GlassCard className="explanation-card" key={i}><div><RiskBadge level={f.severity}/><b>{f.title || "Forensic finding"}</b></div><p>{f.description || f.evidence || "Evidence returned by the forensic engine."}</p>{f.evidence && <code>{f.evidence}</code>}</GlassCard>) : <EmptyState title="No findings" text="No forensic findings were returned for this analysis."/>}</div></Section></>; }
function Score({label,value,unavailable}) { return <GlassCard className="score-breakdown-card"><span>{label}</span><strong>{unavailable ? "—" : `${value}%`}</strong>{unavailable ? <small>Unavailable</small> : <div className="progress"><i style={{width:`${Math.min(100,Number(value)||0)}%`}}/></div>}</GlassCard>; }
function MailView({email,forensic,sourceIp,domains,urls}) { return <Section title="Original email intelligence" subtitle="Header and message metadata extracted from the submitted RFC822 artifact."><div className="mail-detail-grid"><GlassCard><KV k="From" v={email.sender}/><KV k="Reply-To" v={forensic?.sender_identity?.reply_to?.email_address}/><KV k="Subject" v={email.subject}/><KV k="Date" v={email.date}/><KV k="Message ID" v={email.message_id}/></GlassCard><GlassCard><KV k="Originating IP" v={sourceIp}/><KV k="Domains" v={domains.join(", ")}/><KV k="URLs" v={urls.join("\n")}/><KV k="Evidence SHA-256" v={email.metadata?.sha256}/></GlassCard></div></Section>; }
function KV({k,v}) { return <div className="kv"><span>{k}</span><b className="breakable">{v || "—"}</b></div>; }
function Authentication({forensic}) { const a=forensic?.email_authentication||{}; return <Section title="Authentication & identity" subtitle="SPF, DKIM, DMARC and sender identity checks."><div className="auth-grid">{["spf","dkim","dmarc"].map(k=><GlassCard key={k}><span>{k.toUpperCase()}</span><strong className={String(a.reported_results?.[k]||"").toLowerCase()==="fail"?"auth-fail":"auth-pass"}>{a.reported_results?.[k]||"UNKNOWN"}</strong><small>{a[`independent_${k}`]?.status || a[`${k}_reason`] || "Receiver-reported authentication evidence."}</small></GlassCard>)}</div><GlassCard className="forensic-fields"><KV k="From" v={forensic?.sender_identity?.from?.email_address}/><KV k="Reply-To" v={forensic?.sender_identity?.reply_to?.email_address}/><KV k="Return-Path" v={forensic?.sender_identity?.return_path?.email_address}/><KV k="Identity flags" v={arr(forensic?.sender_identity?.analysis?.risk_flags).join(", ")}/></GlassCard></Section>; }
function Relay({timeline,forensic}) { const hops=timeline.filter(x=>x.event==="received_hop").map(x=>x.value||{}); return <Section title="Relay timeline" subtitle="Received-header infrastructure path and probable-source assessment."><div className="timeline">{hops.map((h,i)=><div className="timeline-item" key={i}><div className="timeline-dot"/><GlassCard><b>Hop {h.hop || i+1} · {h.hostname || h.host || "Mail infrastructure"}</b><div className="mini-grid"><span>IP <b>{h.ip||"—"}</b></span><span>Scope <b>{h.ip_scope||"—"}</b></span><span>Country <b>{h.geolocation?.country||"—"}</b></span><span>ASN <b>{h.geolocation?.asn||"—"}</b></span></div></GlassCard></div>)}</div><GlassCard className="origin-callout"><b>Probable source infrastructure</b><span>{forensic?.relay_analysis?.probable_source?.earliest_visible_public_hop?.ip || "No public hop identified"}</span><small>{forensic?.relay_analysis?.probable_source?.limitation || "Geolocation is infrastructure context, not identity proof."}</small></GlassCard></Section>; }
function IOCView({iocs}) { return <Section title="Indicators of compromise" subtitle="Extracted IPs, domains, URLs and hashes."><DataTable rows={iocs} columns={[{key:"type",label:"Type",render:r=><span className="ioc-type">{r.type}</span>},{key:"value",label:"Indicator",render:r=><span className="mono breakable">{r.value}</span>},{key:"risk_flags",label:"Signals",render:r=><span>{arr(r.risk_flags).join(", ") || "Observed"}</span>},{key:"confidence",label:"Confidence",render:r=>`${Math.round(Number(r.confidence||0)*100)}%`}]} /></Section>; }
function FindingView({findings}) { return <Section title="Forensic findings" subtitle="Human-readable explanations linked to the underlying evidence."><div className="explanation-grid">{findings.map((f,i)=><GlassCard className="explanation-card" key={i}><div><RiskBadge level={f.severity}/><b>{f.title}</b></div><p>{f.description}</p><code>{f.evidence || "Evidence retained in the analysis record."}</code></GlassCard>)}</div></Section>; }
function EvidenceView({email,forensic}) { return <Section title="Evidence & chain of custody" subtitle="Integrity metadata captured during ingestion."><GlassCard><KV k="SHA-256" v={email.metadata?.sha256 || forensic?.evidence?.sha256}/><KV k="Evidence ID" v={forensic?.evidence?.case_id || forensic?.evidence?.evidence_id}/><KV k="Source file" v={email.filename}/><div className="chain">{["Collected","Hashed","Parsed","Analyzed","Stored"].map((x,i)=><div key={x}><span>{i+1}</span><b>{x}</b></div>)}</div></GlassCard></Section>; }
function GraphView({graph}) { const nodes=arr(graph.nodes),edges=arr(graph.edges); return <Section title="IOC relationship graph" subtitle="Relationships extracted from the message and its indicators."><div className="graph-summary"><GlassCard><Network size={20}/><strong>{nodes.length}</strong><span>Nodes</span></GlassCard><GlassCard><GitBranch size={20}/><strong>{edges.length}</strong><span>Relationships</span></GlassCard></div><div className="graph-list">{nodes.map(n=><GlassCard key={n.id}><span>{n.type}</span><b className="breakable">{n.label}</b></GlassCard>)}</div></Section>; }
function AdvancedView({advanced}) { const items=advanced?.features || advanced || {}; return <Section title="Advanced intelligence" subtitle="Signals returned by the current backend capability layer."><div className="advanced-feature-grid">{Object.entries(items).map(([k,v])=><GlassCard key={k}><b>{k.replaceAll("_"," ")}</b><p>{typeof v === "string" ? v : JSON.stringify(v)}</p></GlassCard>)}</div></Section>; }
function ReportView({analysisId}) { return <Section title="Forensic report" subtitle="Export the investigation as a structured PDF or JSON evidence package."><div className="report-actions"><a className="primary" href={reportPdf(analysisId)} target="_blank" rel="noreferrer"><FileText size={17}/>Open forensic PDF</a><a className="secondary" href={`${import.meta.env.VITE_API_BASE_URL}/reports/${analysisId}`} target="_blank" rel="noreferrer"><Download size={17}/>Open JSON evidence</a></div></Section>; }
