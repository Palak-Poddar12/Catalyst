# 🛡️ SatGuard — Email Forensic Intelligence Platform

SatGuard is an email security and forensic intelligence platform designed to analyze suspicious emails, reconstruct their infrastructure, identify indicators of compromise (IOCs), evaluate authentication failures, visualize attack infrastructure, and generate explainable forensic reports.

The platform is designed as a modular multi-member architecture so that cybersecurity analysis, AI/ML detection, backend orchestration, DevSecOps, frontend visualization, and network intelligence can be developed independently and integrated into one application.

---

## 🎯 Project Objective

The goal of SatGuard is to transform a suspicious email into an explainable security investigation.

Instead of only saying:

> "This email is phishing."

SatGuard attempts to answer:

- Who sent the email?
- Does the sender identity match?
- Did SPF pass?
- Did DKIM pass?
- Did DMARC pass?
- Is DMARC aligned?
- What servers handled the email?
- What is the earliest visible public IP?
- What domains and URLs are present?
- Are there suspicious attachments?
- What infrastructure is associated with the email?
- What indicators are suspicious?
- What evidence supports the finding?
- What is the final risk?
- Can an investigator download a forensic report?

---

# 🏗️ Current Architecture

```text
Suspicious Email
       │
       ▼
Evidence Preservation
       │
       ▼
Header + Body Parsing
       │
       ▼
Sender Identity Analysis
       │
       ├── From
       ├── Reply-To
       ├── Return-Path
       └── Sender comparison
       │
       ▼
Email Authentication
       │
       ├── SPF
       ├── DKIM
       └── DMARC
       │
       ▼
DMARC Alignment
       │
       ▼
Received Header Parsing
       │
       ▼
Relay Path Reconstruction
       │
       ▼
IOC Extraction
       │
       ├── IP addresses
       ├── Domains
       ├── URLs
       ├── Attachments
       └── Hashes
       │
       ▼
Threat Intelligence
       │
       ├── DNS
       ├── GeoIP
       ├── ASN
       ├── IP reputation
       └── URL reputation
       │
       ▼
Forensic Findings
       │
       ▼
Risk / Severity
       │
       ├───────────────┐
       ▼               ▼
 Dashboard         PDF Report
       │
       ├── Map
       ├── IOC Graph
       ├── Relay Timeline
       ├── Threat Alerts
       └── Case History