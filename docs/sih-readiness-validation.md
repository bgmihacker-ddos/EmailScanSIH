# SIH Readiness Validation

Date: 2026-09-09

## Scope

This validation covers the forensic engine and analysis workflow. Authentication/RBAC administration remains outside the SIH engine scope.

## Capability Matrix

| Capability | Evidence in system | Validation state |
|---|---|---|
| Raw EML ingestion | `POST /api/analyze` accepts raw content or an uploaded file | Implemented |
| Header and relay forensics | Received-chain, sender, Return-Path, Reply-To, Message-ID, and duplicate-header analysis | Implemented |
| Authentication analysis | Header-reported SPF/DKIM/DMARC/ARC plus DNS SPF/DMARC policy verification when DNS is available | Implemented with provenance labels |
| IOC and content analysis | URL, domain, IP, email, attachment, urgency, credential, BEC, and impersonation signals | Implemented |
| Threat intelligence | VirusTotal, URLhaus, ThreatFox, and AbuseIPDB with capability-aware routing and truthful unavailable states | Implemented |
| Infrastructure tracing | DNS, WHOIS, public-IP geolocation, and bounded PTR reverse lookup | Implemented |
| Explainable risk | Correlated evidence ledger, score breakdown, confidence, reasoning, graph, timeline, and MITRE mapping | Implemented |
| Evidence integrity | Raw-message SHA-256, analysis ID, retention policy, and export masking metadata | Implemented |
| Privacy controls | Raw-email export masking by default and configurable retention metadata | Implemented; deletion scheduler remains deployment work |
| Alert/integration contract | Sanitized webhook alert for non-benign results; no raw email is sent | Implemented; SIEM/mail-gateway adapters remain deployment work |
| Job lifecycle | Queued, processing, completed, failed, partial-compatible persistence, cancellation endpoint, stale-job recovery, and database-backed job payloads | Implemented with one-pass worker entry point; process supervision remains deployment work |
| Case and campaign support | History, related investigations, campaign correlation, exports | Implemented; assignment/collaboration remains future work |

## Test Evidence

- Focused parser/scoring/provider/geolocation validation: passing.
- Backend regression suite excluding optional Playwright collection: passing before the final readiness additions.
- Frontend production build: passing.
- Optional browser test requires the Playwright package and browser installation in the active environment.

## Latest fixture matrix

The five required sanitized fixtures were run through the offline forensic pipeline on 2026-09-12:

| Fixture class | Fixture | Observed verdict |
|---|---|---|
| Legitimate | `benign_internal_newsletter.eml` | `benign` |
| Credential phishing | `phishing_credential_harvesting.eml` | `malicious` |
| BEC | `bec_wire_transfer_fraud.eml` | `malicious` |
| Sender spoofing | `sender_spoofing_spf_fail.eml` | `suspicious` |
| Malicious attachment | `malware_executable_attachment.eml` | `malicious` |

The public ML model was retrained on 3,250 records from SpamAssassin and Enron-derived public mail. Its held-out accuracy is 0.9189 and macro F1 is 0.9163; phishing recall is 0.8297, so these metrics are corpus-scoped and not a production-world guarantee.

The latest balanced-weight retraining improved held-out accuracy to 0.9361, macro F1 to 0.9347, and phishing recall to 0.8819 at threshold 0.50. A 0.40 threat threshold reaches 0.9451 recall with 0.9223 precision. Threshold selection remains an operational policy decision and should be calibrated against representative deployment traffic.

## Required Demonstration Dataset

Run one sanitized fixture from each class and record verdict, score, confidence, provider statuses, timing, and evidence references:

1. Legitimate authenticated transactional email
2. Credential-phishing email
3. Business email compromise or payment-diversion email
4. Spoofed sender/authentication-failure email
5. Malicious attachment email

## Claim Boundaries

The platform estimates probable infrastructure origin and correlation. It does not prove a person's physical location or identity. Public IP geolocation, reverse DNS, WHOIS, and threat-intelligence results must be presented as evidence with provider provenance and uncertainty.
