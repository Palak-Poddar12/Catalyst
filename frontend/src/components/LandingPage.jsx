import {
  ArrowRight,
  FileSearch,
  Globe2,
  Mail,
  Network,
  Search,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";

import "./LandingPage.css";
import FeaturesSection from "./FeaturesSection";
import ArchitectureSection from "./ArchitectureSection";
import AboutTeamSection from "./AboutTeamSection";

function LandingPage({ onLogin, onStart }) {
  const scrollToHowItWorks = () => {
    document.getElementById("how-it-works")?.scrollIntoView({ behavior: "smooth" });
  };

  const scrollToAbout = () => {
    document.getElementById("about")?.scrollIntoView({ behavior: "smooth" });
  };

  const scrollToArchitecture = () => {
    document.getElementById("architecture")?.scrollIntoView({ behavior: "smooth" });
  };

  const scrollToFeatures = () => {
    document.getElementById("features")?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <main className="landing-page">
      <header className="landing-nav">
        <button className="landing-brand" type="button" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>
          <span className="landing-logo"><ShieldCheck size={24} /></span>
          <span>
            <strong>SAT<span>GUARD</span></strong>
            <small>Email Threat Intelligence &amp; Forensics</small>
          </span>
        </button>

        <nav className="landing-links" aria-label="Main navigation">
          <button type="button" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>Home</button>
          <button type="button" onClick={scrollToFeatures}>Features</button>
          <button type="button" onClick={scrollToHowItWorks}>How It Works</button>
          <button type="button" onClick={scrollToArchitecture}>Architecture</button>
          <button type="button" onClick={scrollToAbout}>About</button>
        </nav>

        <div className="landing-actions">
          <button className="landing-login" type="button" onClick={onLogin}>Log In</button>
          <button className="landing-get-started" type="button" onClick={onStart}>Get Started <ArrowRight size={16} /></button>
        </div>
      </header>

      <section className="landing-hero">
        <div className="landing-hero-copy">
          <div className="landing-kicker"><Sparkles size={14} /> Evidence-driven email security</div>
          <h1>Turn Suspicious Emails into <span>Actionable Forensic Evidence.</span></h1>
          <p>
            SatGuard analyzes headers, authentication, URLs, attachments, sender identity, and threat infrastructure — then connects the evidence into one investigation workspace.
          </p>
          <div className="landing-cta-row">
            <button className="primary-cta" type="button" onClick={onStart}>Start Investigation <ArrowRight size={18} /></button>
            <button className="secondary-cta" type="button" onClick={scrollToHowItWorks}>See How It Works</button>
          </div>
          <div className="landing-trust-row">
            <span><ShieldCheck size={15} /> Evidence preserved</span>
            <span><Network size={15} /> Infrastructure correlated</span>
            <span><FileSearch size={15} /> Reports ready</span>
          </div>
        </div>

        <div className="forensic-preview" aria-label="SatGuard forensic dashboard preview">
          <div className="preview-topbar">
            <span className="preview-dot" />
            <span>Email Analysis</span>
            <span className="preview-risk">HIGH RISK</span>
          </div>
          <div className="preview-risk-score">
            <div><small>Risk Score</small><strong>87<span>/100</span></strong></div>
            <div className="preview-ring"><ShieldCheck size={25} /></div>
          </div>
          <div className="preview-email">
            <div><small>FROM</small><strong>billing@company-secure.com</strong></div>
            <div><small>SUBJECT</small><strong>Urgent invoice payment required</strong></div>
          </div>
          <div className="preview-tags">
            <span>BEC</span><span>Lookalike Domain</span><span>Suspicious URL</span><span>High-Risk IP</span>
          </div>
          <div className="preview-network">
            <div className="preview-node node-mail"><Mail size={15} /></div>
            <div className="preview-line line-one" />
            <div className="preview-node node-domain"><Globe2 size={15} /></div>
            <div className="preview-line line-two" />
            <div className="preview-node node-ip"><Network size={15} /></div>
            <div className="preview-map-grid"><i /><i /><i /><i /><i /><i /></div>
          </div>
          <div className="preview-bottom">
            <span><b /> DMARC failed</span>
            <span><b /> Sender mismatch</span>
            <span><b /> Reputation alert</span>
          </div>
        </div>
      </section>

      <section className="landing-capabilities">
        <div className="landing-section-heading">
          <p>BUILT FOR INVESTIGATORS</p>
          <h2>From suspicious message to connected evidence.</h2>
        </div>
        <div className="capability-grid">
          <article><span><Search size={20} /></span><h3>Advanced Threat Detection</h3><p>Identify phishing, BEC, impersonation, malicious links, and suspicious attachments.</p></article>
          <article><span><FileSearch size={20} /></span><h3>Forensic Analysis</h3><p>Preserve evidence, inspect headers, reconstruct relay paths, and explain findings.</p></article>
          <article><span><Network size={20} /></span><h3>Threat Intelligence</h3><p>Connect IPs, domains, URLs, ASN information, reputation, and infrastructure signals.</p></article>
          <article><span><Workflow size={20} /></span><h3>Investigation Workspace</h3><p>Move from individual evidence to cases, relationships, timelines, and reports.</p></article>
        </div>
      </section>

      <FeaturesSection onStart={onStart} />

      <ArchitectureSection />

      <section className="landing-how" id="how-it-works">
        <div className="landing-section-heading center">
          <p>HOW IT WORKS</p>
          <h2>One investigation flow. Five clear stages.</h2>
        </div>
        <div className="how-grid">
          {[
            ["01", "Ingest", "Upload an .eml file or connect Gmail.", Mail],
            ["02", "Analyze", "Inspect identity, authentication, URLs, and attachments.", Search],
            ["03", "Correlate", "Connect IOCs and threat infrastructure.", Network],
            ["04", "Investigate", "Explore maps, graphs, timelines, and evidence.", FileSearch],
            ["05", "Report", "Generate an investigator-ready forensic report.", ShieldCheck],
          ].map(([number, title, text, Icon]) => (
            <article className="how-step" key={number}>
              <span className="step-number">{number}</span>
              <Icon size={21} />
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>

      <AboutTeamSection onStart={onStart} />

      <section className="landing-bottom-cta" id="ready">
        <div>
          <p>READY TO INVESTIGATE?</p>
          <h2>Bring the evidence together.</h2>
        </div>
        <button className="primary-cta" type="button" onClick={onStart}>Start with SatGuard <ArrowRight size={18} /></button>
      </section>

      <footer className="landing-footer">
        <span>© 2026 SatGuard</span>
        <span>Real threats. Real evidence. A safer digital world.</span>
        <button type="button" onClick={onLogin}>Investigator Login</button>
      </footer>
    </main>
  );
}

export default LandingPage;
