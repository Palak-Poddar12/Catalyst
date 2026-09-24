import { ArrowRight, Github, Mail, ShieldCheck, Users, Target, Code2, Database, Network, Brain } from "lucide-react";
import "./AboutTeamSection.css";

const team = [
  {
    role: "Cybersecurity & Forensics",
    title: "Security Analyst",
    description: "Email evidence preservation, header analysis, SPF/DKIM/DMARC, IOC extraction, relay reconstruction and forensic investigation.",
    icon: ShieldCheck,
  },
  {
    role: "Backend & API",
    title: "Platform Engineer",
    description: "FastAPI services, analysis jobs, Gmail integration, secure API boundaries, case APIs and report generation.",
    icon: Code2,
  },
  {
    role: "AI / ML",
    title: "Threat Intelligence Engineer",
    description: "Threat classification, BEC and impersonation intelligence, explainable risk signals and evidence-grounded reasoning.",
    icon: Brain,
  },
  {
    role: "Full Stack & DevSecOps",
    title: "Product Engineer",
    description: "Investigator dashboard, visualization, deployment workflow, testing and secure application delivery.",
    icon: Network,
  },
];

const pillars = [
  [Target, "Evidence-first", "Every investigation starts from preserved technical evidence."],
  [Database, "Structured cases", "Indicators, findings and reports remain organized around investigations."],
  [Users, "Human-in-the-loop", "SatGuard supports analysts instead of making autonomous attribution decisions."],
];

function AboutTeamSection({ onStart }) {
  return (
    <section className="about-team-section" id="about">
      <div className="about-team-heading">
        <div>
          <p className="about-eyebrow"><ShieldCheck size={14} /> ABOUT SATGUARD</p>
          <h2>Built to help investigators connect the evidence.</h2>
          <p className="about-intro">
            SatGuard brings email forensics, threat intelligence, infrastructure correlation,
            visualization and reporting into one investigation workflow.
          </p>
        </div>
        <button className="about-start-btn" type="button" onClick={onStart}>
          Start Investigation <ArrowRight size={17} />
        </button>
      </div>

      <div className="about-pillars">
        {pillars.map(([Icon, title, text]) => (
          <article className="about-pillar" key={title}>
            <div className="about-pillar-icon"><Icon size={20} /></div>
            <div><h3>{title}</h3><p>{text}</p></div>
          </article>
        ))}
      </div>

      <div className="team-heading-row">
        <div>
          <span>THE TEAM</span>
          <h3>One platform. Multiple investigation disciplines.</h3>
        </div>
        <p>Replace these role labels with your final team member names and profiles before submission.</p>
      </div>

      <div className="team-grid">
        {team.map(({ role, title, description, icon: Icon }) => (
          <article className="team-card" key={role}>
            <div className="team-avatar"><Icon size={23} /></div>
            <span className="team-role">{role}</span>
            <h4>{title}</h4>
            <p>{description}</p>
            <div className="team-card-line" />
            <span className="team-status"><span /> SatGuard contributor</span>
          </article>
        ))}
      </div>

      <div className="about-contact">
        <div>
          <span className="about-contact-label">PROJECT LINKS</span>
          <h3>Ready to investigate a suspicious message?</h3>
          <p>Use SatGuard to preserve evidence, correlate infrastructure and produce an investigator-ready report.</p>
        </div>
        <div className="about-contact-actions">
          <button type="button" onClick={onStart}><ShieldCheck size={17} /> Open SatGuard</button>
          <a href="mailto:team@satguard.local"><Mail size={17} /> Contact Team</a>
          <a href="https://github.com/Palak-Poddar12/SatQuery" target="_blank" rel="noreferrer"><Github size={17} /> Repository</a>
        </div>
      </div>
    </section>
  );
}

export default AboutTeamSection;
