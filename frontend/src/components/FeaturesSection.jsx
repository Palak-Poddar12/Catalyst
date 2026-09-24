import { useEffect, useState } from "react";
import {
  ArrowRight,
  Bot,
  Boxes,
  Braces,
  CheckCircle2,
  Fingerprint,
  FileCheck2,
  FileSearch,
  Globe2,
  KeyRound,
  Link2,
  MailSearch,
  Map,
  QrCode,
  Radar,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";

import "./FeaturesSection.css";

const groups = [
  {
    id: "detection",
    eyebrow: "01",
    title: "Email & Threat Detection",
    description: "Turn message content and technical signals into structured threat intelligence.",
    features: [
      {
        id: "multilingual",
        icon: Globe2,
        title: "Multilingual Threat Detection",
        short: "Detect English, Hindi, Hinglish and mixed-language social-engineering patterns.",
        detail: "Language-aware analysis helps investigators see the language mix, threat pattern and classification context instead of treating every message as English-only text.",
        signals: ["Language detection", "Mixed-language analysis", "Phishing / BEC patterns", "Confidence context"],
      },
      {
        id: "bec",
        icon: MailSearch,
        title: "BEC & Impersonation Detection",
        short: "Identify business email compromise, executive impersonation and payment-diversion signals.",
        detail: "Move beyond a generic phishing label by classifying the likely threat intent and surfacing the evidence behind impersonation or fraud patterns.",
        signals: ["BEC", "Executive impersonation", "Payment diversion", "Credential theft"],
      },
      {
        id: "lookalike",
        icon: Fingerprint,
        title: "Brand & Lookalike Domains",
        short: "Surface typosquatting, homoglyphs, Unicode tricks and suspicious domain similarity.",
        detail: "Compare observed domains with trusted brands and expose visual or structural deception such as character substitution, homoglyphs and misleading subdomains.",
        signals: ["Edit distance", "Homoglyph detection", "Unicode normalization", "Subdomain tricks"],
      },
      {
        id: "redirects",
        icon: Link2,
        title: "URL Redirect & Obfuscation",
        short: "Follow the investigation from the email URL through redirects to the final destination.",
        detail: "Instead of treating a URL as a single indicator, represent its redirect chain and connect the destination to reputation and domain intelligence.",
        signals: ["Shorteners", "Encoded URLs", "Redirect chains", "Destination mismatch"],
      },
      {
        id: "attachments",
        icon: FileSearch,
        title: "Advanced Attachment Forensics",
        short: "Inspect hashes, MIME types, extensions and attachment risk without executing files.",
        detail: "Attachment evidence can expose extension mismatches, suspicious archives, executable MIME types, macro-enabled documents and deceptive filenames.",
        signals: ["SHA-256", "MIME validation", "Extension mismatch", "Suspicious archives"],
      },
      {
        id: "quishing",
        icon: QrCode,
        title: "QR / Quishing Detection",
        short: "Detect QR-based phishing and connect decoded destinations to URL intelligence.",
        detail: "Extract a QR destination from an email image, then continue the same forensic path into URL, domain and threat analysis.",
        signals: ["QR detection", "URL decoding", "Destination analysis", "Threat enrichment"],
      },
    ],
  },
  {
    id: "evidence",
    eyebrow: "02",
    title: "Evidence & Explainability",
    description: "Keep the investigation auditable and make the reasoning visible to the analyst.",
    features: [
      {
        id: "chain",
        icon: ShieldCheck,
        title: "Tamper-Evident Evidence Chain",
        short: "Build an evidence trail around hashes, timestamps and investigator actions.",
        detail: "A hash-chain approach extends basic SHA-256 preservation into a verifiable sequence of evidence events. Optional anchoring can be added later without making public blockchain storage mandatory.",
        signals: ["Evidence ID", "SHA-256", "Timestamp", "Previous hash"],
      },
      {
        id: "risk",
        icon: Radar,
        title: "Explainable Risk Decomposition",
        short: "Show what contributed to the final risk instead of displaying a score alone.",
        detail: "Break risk into understandable signal families such as authentication, sender identity, URL intelligence, infrastructure and threat intelligence.",
        signals: ["Authentication", "Sender identity", "URL intelligence", "Infrastructure"],
      },
      {
        id: "copilot",
        icon: Bot,
        title: "Evidence-Grounded Analyst Copilot",
        short: "Ask why a case is risky and get answers grounded in the investigation evidence.",
        detail: "The assistant is designed around the actual case: findings, indicators and related evidence. It should explain the decision and suggest investigation steps rather than behave like an unrestricted chatbot.",
        signals: ["Why this risk?", "Evidence references", "Next investigation step", "Case context"],
      },
    ],
  },
  {
    id: "infrastructure",
    eyebrow: "03",
    title: "Threat Intelligence & Infrastructure",
    description: "Connect indicators across the infrastructure behind suspicious messages.",
    features: [
      {
        id: "campaigns",
        icon: Boxes,
        title: "Cross-Case Campaign Correlation",
        short: "Find repeated infrastructure and relationships across previous investigations.",
        detail: "Cases become connected through shared IPs, domains, URLs and other indicators so investigators can recognize recurring campaign infrastructure.",
        signals: ["Related cases", "Shared IPs", "Shared domains", "Campaign timeline"],
      },
      {
        id: "fingerprint",
        icon: Fingerprint,
        title: "Threat Infrastructure Fingerprinting",
        short: "Compare sender, domain, IP, ASN, MX, URL and hosting signals.",
        detail: "Build an infrastructure fingerprint from multiple observable signals and report likely relationships without claiming that infrastructure proves a person's identity.",
        signals: ["IP overlap", "ASN overlap", "Domain similarity", "Sender pattern"],
      },
      {
        id: "map",
        icon: Map,
        title: "Advanced Forensic Infrastructure Map",
        short: "Visualize relay hops, source infrastructure and confidence-aware geolocation.",
        detail: "Turn Received-header evidence into an investigation map with IP, country, ASN, provider and confidence context. Geolocation is infrastructure evidence, not proof of an actor's physical location.",
        signals: ["Relay hops", "Country / city", "ASN / provider", "Confidence"],
      },
    ],
  },
  {
    id: "workspace",
    eyebrow: "04",
    title: "Investigator Workspace",
    description: "Give analysts a structured way to search, organize and investigate cases.",
    features: [
      {
        id: "nl-search",
        icon: Search,
        title: "Natural-Language Investigation Search",
        short: "Search cases with questions such as which cases share an IP or campaign.",
        detail: "The investigation layer can translate analyst questions into structured searches across cases, indicators, campaigns and infrastructure relationships.",
        signals: ["Case questions", "IOC relationships", "Campaign search", "Structured queries"],
      },
      {
        id: "cases",
        icon: FileCheck2,
        title: "Investigation Case Management",
        short: "Track status, severity, evidence, related emails, IOCs and campaigns in one case.",
        detail: "A case becomes the container for evidence and investigation progress, with clear lifecycle states such as new, investigating, contained, resolved and false positive.",
        signals: ["Case status", "Severity", "Assigned analyst", "Related IOCs"],
      },
    ],
  },
  {
    id: "monitoring",
    eyebrow: "05",
    title: "Monitoring & Secure Access",
    description: "Connect real inbox workflows while keeping analyst privacy and access controls visible.",
    features: [
      {
        id: "gmail",
        icon: MailSearch,
        title: "Near-Real-Time Gmail Monitoring",
        short: "Connect Gmail for message ingestion and extend analysis toward alert-driven monitoring.",
        detail: "SatGuard separates Gmail authorization from SatGuard authentication. The investigation workflow can ingest raw MIME messages and send them through the same forensic pipeline.",
        signals: ["Gmail OAuth", "Raw MIME", "Inbox ingestion", "Threat alerts"],
      },
      {
        id: "privacy",
        icon: KeyRound,
        title: "Privacy Mode",
        short: "Mask sensitive email content while preserving the indicators investigators need.",
        detail: "Privacy controls can mask addresses, names and message bodies while retaining headers and indicators required for investigation and evidence review.",
        signals: ["Mask addresses", "Mask names", "Mask body", "Retain IOCs"],
      },
    ],
  },
  {
    id: "reporting",
    eyebrow: "06",
    title: "Evidence to Report",
    description: "Turn an investigation into a structured deliverable that another analyst can review.",
    features: [
      {
        id: "report",
        icon: FileSearch,
        title: "One-Click Investigation Report",
        short: "Package findings, authentication, relay paths, IOCs, infrastructure and evidence integrity.",
        detail: "The report view brings the investigation together into an investigator-ready artifact covering executive summary, threat classification, risk assessment, sender analysis, authentication, relay path, IOC intelligence and findings.",
        signals: ["Executive summary", "Risk assessment", "IOC intelligence", "PDF report"],
      },
    ],
  },
];

function FeaturesSection({ onStart }) {
  const [selected, setSelected] = useState(null);

  const allFeatures = groups.flatMap((group) =>
    group.features.map((feature) => ({ ...feature, groupTitle: group.title }))
  );

  useEffect(() => {
    if (!selected) return undefined;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const handleKeyDown = (event) => {
      if (event.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previous;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [selected]);

  const openFeature = (feature) => setSelected(feature);

  const openNext = () => {
    const index = allFeatures.findIndex((item) => item.id === selected?.id);
    const next = allFeatures[(index + 1) % allFeatures.length];
    setSelected(next);
  };

  const SelectedIcon = selected?.icon;

  return (
    <section className="features-section" id="features">
      <div className="features-heading">
        <div>
          <p className="features-eyebrow"><Sparkles size={14} /> SATGUARD CAPABILITIES</p>
          <h2>One investigation surface for the entire threat story.</h2>
        </div>
        <p className="features-intro">
          Explore the capabilities from detection to evidence preservation, infrastructure correlation and investigator-ready reporting.
        </p>
      </div>

      <div className="feature-group-list">
        {groups.map((group) => (
          <div className="feature-group" key={group.id}>
            <div className="feature-group-header">
              <span className="feature-group-number">{group.eyebrow}</span>
              <div>
                <h3>{group.title}</h3>
                <p>{group.description}</p>
              </div>
            </div>

            <div className="feature-card-grid">
              {group.features.map((feature) => {
                const Icon = feature.icon;
                return (
                  <button
                    className="feature-card"
                    type="button"
                    key={feature.id}
                    onClick={() => openFeature({ ...feature, groupTitle: group.title })}
                  >
                    <span className="feature-card-icon"><Icon size={20} /></span>
                    <span className="feature-card-body">
                      <strong>{feature.title}</strong>
                      <span>{feature.short}</span>
                    </span>
                    <ArrowRight className="feature-card-arrow" size={17} />
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="features-final-cta">
        <div>
          <span className="features-cta-kicker">FROM SIGNAL TO EVIDENCE</span>
          <h3>Ready to investigate a suspicious email?</h3>
          <p>Start with an .eml file or connect Gmail, then follow the evidence through the investigation workspace.</p>
        </div>
        <button type="button" onClick={onStart}>
          Start Investigation <ArrowRight size={17} />
        </button>
      </div>

      {selected && (
        <div className="feature-modal-backdrop" role="presentation" onMouseDown={() => setSelected(null)}>
          <article
            className="feature-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="feature-modal-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <button className="feature-modal-close" type="button" onClick={() => setSelected(null)} aria-label="Close feature details">
              <X size={20} />
            </button>

            <div className="feature-modal-icon"><SelectedIcon size={28} /></div>
            <p className="feature-modal-group">{selected.groupTitle}</p>
            <h3 id="feature-modal-title">{selected.title}</h3>
            <p className="feature-modal-detail">{selected.detail}</p>

            <div className="feature-signal-title"><Braces size={15} /> Investigation signals</div>
            <div className="feature-signal-grid">
              {selected.signals.map((signal) => (
                <div key={signal}><CheckCircle2 size={15} /> {signal}</div>
              ))}
            </div>

            <div className="feature-modal-footer">
              <span><ShieldCheck size={15} /> Evidence-first workflow</span>
              <button type="button" onClick={openNext}>Next capability <ArrowRight size={16} /></button>
            </div>
          </article>
        </div>
      )}
    </section>
  );
}

export default FeaturesSection;
