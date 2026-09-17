# 🛡️ SIH 2026 Strategy & Addon Roadmap — Email Threat Intelligence Platform

> **Project**: Enterprise Email Threat Detection & Forensic Intelligence  
> **Target Event**: Smart India Hackathon (SIH 2026)  
> **Domain / Theme**: Blockchain & Cybersecurity  
> **Source Analysis**: Extracted from Codebase Knowledge Graph (`1,637 nodes, 3,796 edges, 136 communities`)

---

## 📊 1. Current Architecture Overview (From Code Graph)

The platform already possesses a solid, production-grade modular architecture:
- **Core Processing Pipeline**: `EmailParser`, `HeaderForensicsAnalyzer`, `AttachmentAnalyzer`, `SenderIntelligenceAnalyzer`, and `EvidenceCorrelator`.
- **Decision Engine**: Multi-tier hybrid scoring combining deterministic rule sets, heuristic logic, static OOXML/PDF inspectors, and a pre-trained `MLClassifier`.
- **Threat Intelligence Network**: Integrations with `ThreatFox`, `URLhaus`, `AbuseIPDB`, `VirusTotal`, `GoogleSafeBrowsing`, `AlienVaultOTX`, `ShodanInternetDB`, `TorExitNodeChecker`, `DNSIntelligenceService`, and `WHOISIntelligenceService`.
- **Forensics & Outputs**: Hop-by-hop SMTP relay map visualizer, interactive Evidence Graph builder, STIX 2.1 JSON exporter, and forensic PDF generator.
- **Enterprise Security**: JWT authentication, Google OAuth integration, role-based access control (`Admin`, `Analyst`, `User`), rate limiting, and audit trail logging.

---

## 🏆 2. High-Impact SIH 2026 Addons

### 🔗 Addon 1: Blockchain Chain of Custody & Tamper-Proof Audit Vault
- **Hackathon Value**: Directly fulfills the **Blockchain & Cybersecurity** theme criteria.
- **Technical Architecture**:
  - Compute a cryptographic SHA-256 / Blake3 hash of the normalized forensic bundle (headers, findings, IOCs, verdict).
  - Deploy a lightweight smart contract on Polygon (Amoy testnet) / Sepolia testnet to anchor:
    - `scan_id` (UUID)
    - `evidence_hash` (bytes32)
    - `timestamp` (uint256)
    - `analyst_address` (address)
  - Generate a verification badge & QR code in the PDF report that links to the block explorer (Polygonscan/Etherscan) for courtroom / cyber-cell chain-of-custody verification.
- **Judge Pitch**: *"Guarantees evidence integrity and legal chain-of-custody for Indian Cyber Crime Investigation Cells (I4C/State Police) and legal proceedings."*

---

### 🇮🇳 Addon 2: CERT-In Automated Incident Reporting & Compliance Pack
- **Hackathon Value**: High governance and national relevance score.
- **Technical Architecture**:
  - Implement a 1-click exporter formatted according to Indian Computer Emergency Response Team (**CERT-In**) cyber security incident guidelines.
  - Generates structured XML/JSON/PDF submissions containing:
    - Incident type (Phishing / BEC / Malicious Payload / Spoofing)
    - Originating foreign IPs, ASN classifications, and geographical relay hops
    - Extracted IOCs (malicious URLs, sender domains, attachment hashes)
    - Remediation action taken / suggested quarantine rules
- **Judge Pitch**: *"Enables organizations to meet CERT-In's mandatory cyber incident reporting directives within minutes instead of hours."*

---

### 💳 Addon 3: Bharat Threat Intelligence (UPI, Indian Banking & Gov Protection)
- **Hackathon Value**: Localization and relevance to real-world Indian cyber threats.
- **Technical Architecture**:
  - **UPI / VPA Spoof Detection**: Heuristics to detect suspicious payment links and impersonated UPI handles (`@okhdfcbank`, `@paytm`, `@ybl`, `@upi`, `@axisbank`).
  - **Government Domain Whitelisting & Guarding**: Strict SPF/DKIM/DMARC checks for `.gov.in`, `.nic.in`, `.ac.in`, and `.org.in` domains. Flag emails claiming to be government agencies sending from generic public providers (e.g., Gmail/Outlook).
  - **Regional Scam Heuristics**: Dedicated keyword recognition for Aadhaar/PAN KYC update suspensions, e-Challan payment scams, and Income Tax refund frauds.
- **Judge Pitch**: *"Engineered with localized threat models specifically defending Indian citizens and digital financial infrastructure."*

---

### 📱 Addon 4: Quishing (QR-Code Phishing) & Image OCR Inspector
- **Hackathon Value**: Addresses the latest 2025/2026 evasion vector bypassing standard email gateways.
- **Technical Architecture**:
  - Inspect embedded images and PDF attachments using `pyzbar` and `opencv-python` to detect and decode QR codes.
  - Extract hidden destination URLs and route them automatically through the URL intelligence pipeline (`URLhaus`, `VirusTotal`, `Google Safe Browsing`).
  - OCR inspection for image-only email bodies designed to evade text tokenizers.
- **Judge Pitch**: *"Eliminates blind spots caused by QR code phishing (Quishing) and image-rendered lure attacks."*

---

### 🎯 Addon 5: Interactive Attack Simulator / Red-Team Sandbox (Live Demo Weapon)
- **Hackathon Value**: Creates an unforgettable, engaging live judging demonstration.
- **Technical Architecture**:
  - Add an interactive "Attack Lab / Simulator" tab in the frontend UI.
  - Include instant test presets:
    - *Scenario A*: Executive Impersonation (BEC) with spoofed display name.
    - *Scenario B*: State-Sponsored Phishing with weaponized PDF attachment.
    - *Scenario C*: Banking KYC Urgent Phishing with homoglyph domain.
    - *Scenario D*: Benign business email.
  - Allow judges to tweak headers, inject links, and see the detection pipeline compute scores and render graphs in under 2 seconds.
- **Judge Pitch**: *"Proves system speed, accuracy, and operational readiness through interactive live testing."*

---

## 🗺️ 3. Recommended Phased Implementation Plan

| Phase | Focus Area | Deliverables |
|---|---|---|
| **Phase 1 (Quick Wins)** | Bharat Threat Intel & Heuristics | UPI pattern regex, `.gov.in` strict validator, Indian scam keyword rules |
| **Phase 2 (Live Impact)** | Red Team Attack Simulator Tab | Pre-loaded threat scenarios, real-time UI interactive testing |
| **Phase 3 (Theme Requirement)** | Web3 Blockchain Ledger | Smart contract deployment, SHA-256 hash anchoring, verification portal |
| **Phase 4 (Compliance & Gov)** | CERT-In Incident Export | Official reporting schema generator in PDF/JSON |
| **Phase 5 (Deep Defense)** | Quishing & Attachment OCR | QR code decoding from inline images and attachment payloads |
| **Phase 6 (Explainable Intelligence)** | XAI, MITRE & Zero-Trust Enrichment | Plain-English evidence summaries, ATT&CK heatmap, breach/proxy/hosting context |
| **Phase 7 (Enterprise Scale)** | Inbox Automation & Bulk Analysis | Gmail/O365 OAuth ingestion, `.zip`/`.mbox` queues, concurrent processing and campaign reporting |

---

## 🚀 4. Additional SIH 2026 Feature Waves

The following additions build on the five core SIH addons above. They are intentionally designed around free or self-hostable components so the live demo does not depend on paid SaaS quotas.

### 🧠 Phase 6: Explainable Intelligence & Zero-Trust Context

#### Addon 6: Explainable AI / Plain-English Threat Summaries
- **Hackathon Value**: Makes the verdict understandable to judges, analysts, and non-technical incident responders instead of presenting a black-box score.
- **Implementation**:
  - Generate a deterministic evidence summary from the existing risk ledger, authentication results, IOC findings, domain age, mail-flow anomalies, and attachment evidence.
  - Optionally add a compact local transformer or sentence-embedding model behind a feature flag; the deterministic summary remains the fallback.
  - Require every sentence to reference an existing finding or evidence ID. Unknown, timeout, and unavailable provider states must never be described as clean.
  - Display the summary beside numbered, color-coded reasons in the report dossier and CERT-In export.
- **Example**: *"This message claims to represent an Indian bank, but SPF and DMARC failed, the sender domain resembles the claimed brand, and the body requests urgent KYC verification."*
- **Acceptance**:
  - Summary is generated without an external API key.
  - Every explanation item links to a finding, IOC, header, or provider result.
  - Phishing, BEC, attachment, and benign fixtures produce distinct explanations.
  - Explanation generation does not change the deterministic verdict or score.

#### Addon 7: MITRE ATT&CK Heatmap & Analyst Mapping
- **Hackathon Value**: Converts raw forensic signals into the language used by professional SOC and threat-intelligence teams.
- **Implementation**:
  - Map phishing, credential harvesting, malicious attachments, URL execution, and collection signals to ATT&CK technique IDs.
  - Render tactic coverage as an interactive heatmap with confidence, evidence count, and source finding on hover/click.
  - Include technique IDs and evidence references in JSON, PDF, and CERT-In exports.
- **Acceptance**:
  - No technique is shown without a mapped evidence reference.
  - The heatmap distinguishes triggered, inferred, and unobserved techniques.
  - A judge can move from a heatmap cell to the underlying explanation in one click.

#### Addon 8: Zero-Trust Enrichment Without Paid Keys
- **Hackathon Value**: Adds attack-surface context around sender infrastructure without turning unavailable intelligence into a false negative.
- **Implementation**:
  - Use HaveIBeenPwned domain checks only when the required API access is configured; expose `not_configured` honestly otherwise.
  - Use Shodan InternetDB for keyless IP enrichment where available.
  - Combine RDAP domain age, DNS, proxy/TOR/hosting indicators, and provider provenance into an infrastructure-risk panel.
  - Cache enrichment by normalized domain/IP and apply bounded timeouts and concurrency.
- **Acceptance**:
  - Provider states remain visible as `available`, `not_found`, `not_configured`, `timeout`, or `error`.
  - Enrichment is additive and cannot downgrade a confirmed threat to clean.
  - Results identify the source and lookup timestamp for each enrichment.

### 📬 Phase 7: Enterprise Ingestion & Scale

#### Addon 9: Direct Gmail / Microsoft 365 Inbox Integration
- **Hackathon Value**: Demonstrates continuous protection instead of a tool that only analyzes manually uploaded files.
- **Implementation**:
  - Add OAuth authorization for a test Gmail account and Microsoft Graph mailbox.
  - Request least-privilege read-only scopes and store refresh tokens encrypted or replace them with short-lived demo sessions.
  - Poll or subscribe to unread-message events, normalize each message to RFC 5322, and submit it to the existing durable analysis queue.
  - Show connection state, last sync time, messages scanned, and failures in Settings and the dashboard.
- **Acceptance**:
  - OAuth callback never exposes access or refresh tokens to the frontend logs.
  - Duplicate message IDs are idempotent and do not create duplicate analyses.
  - Revoked credentials and provider rate limits produce actionable status without stopping local uploads.
  - A demo mailbox can receive a message and show its analysis in the case history.

#### Addon 10: Batch Analysis for ZIP / MBOX Archives
- **Hackathon Value**: Proves the architecture can scale from one suspicious message to an incident corpus.
- **Implementation**:
  - Accept `.zip` and `.mbox` uploads with archive size, file count, MIME, and decompression-ratio limits.
  - Extract safely into an isolated workspace and enqueue one durable job per message.
  - Use bounded concurrent workers with progress counters, retry limits, cancellation, and partial-success reporting.
  - Generate a bulk report showing verdict distribution, top shared IOCs, campaign clusters, and failed items.
- **Acceptance**:
  - Malformed archives, zip bombs, oversized messages, and unsupported files are rejected safely.
  - One bad message does not fail the batch.
  - Batch progress survives a worker restart and remains queryable by batch ID.
  - Results link each message back to its individual forensic dossier.

### 🎤 Phase 6–7 Hackathon Demo Sequence

1. Upload or connect a test mailbox and show the intake pre-flight summary.
2. Run an Indian KYC phish and open the plain-English explanation beside the ATT&CK heatmap.
3. Expand zero-trust enrichment to show RDAP age, proxy/TOR/hosting state, and provider provenance.
4. Upload an MBOX/ZIP sample and show durable queue progress, campaign grouping, and shared IOCs.
5. Export the CERT-In report and verify the evidence hash through the Phase 3 blockchain anchor.