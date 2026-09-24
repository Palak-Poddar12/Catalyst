import { ArrowDown, Database, FileSearch, Globe2, Mail, Network, Search, Server, ShieldCheck, Sparkles } from "lucide-react";
import "./ArchitectureSection.css";

const stages = [
  { icon: Mail, label: "Email Ingestion", text: ".eml upload or Gmail OAuth", tone: "blue" },
  { icon: FileSearch, label: "Evidence Preservation", text: "SHA-256 + forensic case ID", tone: "cyan" },
  { icon: Search, label: "Forensic Analysis", text: "Headers, MIME, auth, IOCs", tone: "violet" },
  { icon: Globe2, label: "Threat Intelligence", text: "DNS, reputation, GeoIP / ASN", tone: "amber" },
  { icon: Network, label: "Correlation Engine", text: "Graphs, relays, campaigns", tone: "green" },
  { icon: ShieldCheck, label: "Investigation Workspace", text: "Risk, alerts, reports, cases", tone: "blue" },
];

function ArchitectureSection() {
  return (
    <section className="architecture-section" id="architecture">
      <div className="architecture-heading">
        <div>
          <p className="architecture-eyebrow"><Sparkles size={14} /> SATGUARD ARCHITECTURE</p>
          <h2>From raw email to an evidence-driven investigation.</h2>
          <p className="architecture-intro">
            SatGuard separates ingestion, deterministic forensic processing, threat intelligence,
            correlation, and analyst-facing investigation tools so every conclusion can be traced back to evidence.
          </p>
        </div>
        <div className="architecture-badge">
          <span className="architecture-live-dot" />
          <div><strong>Evidence-first pipeline</strong><small>Human review remains in control</small></div>
        </div>
      </div>

      <div className="architecture-flow">
        {stages.map((stage, index) => {
          const Icon = stage.icon;
          return (
            <div className="architecture-stage-wrap" key={stage.label}>
              <article className={`architecture-stage tone-${stage.tone}`}>
                <div className="architecture-icon"><Icon size={22} /></div>
                <span className="architecture-index">0{index + 1}</span>
                <h3>{stage.label}</h3>
                <p>{stage.text}</p>
              </article>
              {index < stages.length - 1 && <ArrowDown className="architecture-arrow" size={19} />}
            </div>
          );
        })}
      </div>

      <div className="architecture-layers">
        <div className="layer-card">
          <div className="layer-icon"><Server size={20} /></div>
          <div><span>Backend</span><strong>FastAPI + Python forensic services</strong><p>Analysis jobs, Gmail integration, intelligence adapters and report generation.</p></div>
        </div>
        <div className="layer-card">
          <div className="layer-icon"><Database size={20} /></div>
          <div><span>Evidence & Storage</span><strong>Cases + forensic JSON + report artifacts</strong><p>Preserved evidence and investigation outputs can be retained for review and correlation.</p></div>
        </div>
        <div className="layer-card">
          <div className="layer-icon"><Network size={20} /></div>
          <div><span>Investigator UI</span><strong>Map + graph + timeline + alerts</strong><p>Transform raw technical signals into an understandable investigation workspace.</p></div>
        </div>
      </div>

      <div className="architecture-principles">
        <div><ShieldCheck size={18} /><span><strong>Evidence before inference</strong> — findings should be tied to observable signals.</span></div>
        <div><Network size={18} /><span><strong>Correlation, not attribution</strong> — infrastructure relationships do not prove an attacker's identity.</span></div>
        <div><FileSearch size={18} /><span><strong>Human investigation</strong> — analysts remain responsible for final decisions.</span></div>
      </div>
    </section>
  );
}

export default ArchitectureSection;
