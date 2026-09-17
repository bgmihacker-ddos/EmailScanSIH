# Real-World Detection Validation

**Date:** September 7, 2026
**Scope:** Email Threat Detection & Intelligence Platform (Phases 6B-10)

## Overview
This document outlines the validation and hardening steps taken to ensure that the detection pipeline operates exclusively on genuine, user-supplied or real-world email inputs, without relying on synthetic generation or demo-data injection in production. 

## Test Corpus and Isolation
To perform robust validation, a corpus of sanitized, localized `.eml` fixtures was created under `backend/tests/fixtures/emails/`. These fixtures represent canonical real-world threat classes:
1. `benign_internal_newsletter.eml`: Standard safe mail with valid signatures.
2. `benign_customer_invoice.eml`: Routine non-malicious attachment traffic.
3. `phishing_credential_harvesting.eml`: Brand impersonation with malicious links.
4. `bec_wire_transfer_fraud.eml`: Sender/Reply-To divergence + language cues.
5. `sender_spoofing_spf_fail.eml`: Authenticity breakdown.
6. `malware_executable_attachment.eml`: Double extension and malicious content.
7. `url_manipulation_punycode.eml`: Homograph domain URL embedding.
8. `dkim_dmarc_auth_mismatch.eml`: Cryptographic alignment failure.

**Crucial:** These items are strictly for automated local testing. They are explicitly isolated from production datastores, endpoints, dashboard analytics, and logs. 

## Hardening Interventions
1. **Attachment Normalization & Safe Hashing:**
   - Modified the MIME traversal to extract magic bytes (first 4 bytes) safely.
   - Introduced safe, offline, in-memory cryptohashing (SHA-256 and MD5) without touching the local disk.
   - Checked for MIME-Type vs byte mismatch without executing code.
2. **Authentication Parsing vs Verdict Verification:**
   - Isolated sender-provided header claims (`Authentication-Results: ... dmarc=pass`) from definitive Domain Name System verification points.
   - Fixed the deduplication constraint whereby informational forensics overly inflated the risk score.
3. **Threat Intel Granularity:**
   - Normalization of `Unavailable`, `Rate Limited`, `Error`, and `Not Configured` statuses across external threat provider models (VirusTotal, ThreatFox, URLHaus, AbuseIPDB).
   - Ensured keys, secrets, or raw bytes are never leaked during enrichment API requests.
4. **Risk Determinism Check:**
   - Validated point clustering ensuring independent heuristics (Content, DMARC, Attachments) sum properly into `Risk Breakdowns` and prevent score inflation from multiple `info` labels.

## Controlled Fixture Results (Not Production Metrics)
The validation harness maps each sanitized fixture through parse → forensics →
authentication → IOC extraction → local enrichment → attachment/content
analysis → risk fusion → reasoning/attack-chain reconstruction. Its controlled
fixture result is:

| Metric | Count |
| --- | ---: |
| True positives | 6 |
| True negatives | 2 |
| False positives | 0 |
| False negatives | 0 |

This is a small, curated, **non-representative** test corpus. The results only
show that the stated fixtures exercised their expected detection paths. They
must not be presented as field accuracy, production false-positive rate, or a
statistically meaningful detection-rate claim. Production efficacy requires a
larger consented and independently labelled corpus, documented sampling, and
continuous evaluation.

The suite also forces DNS resolution unavailable, proving the pipeline continues
with structured, non-verified authentication evidence rather than treating a
network failure as an authentication failure.

## Known Limitations

- The application parses and records reported SPF/DKIM/DMARC/ARC outcomes, but
  a header claim alone is never treated as cryptographic verification.
- The optional DNS check discovers SPF/DMARC/DKIM policy records; it does not
  perform full SPF evaluation or DKIM signature validation.
- Provider results are only available when corresponding API keys are configured.
  A `not_configured`, `unavailable`, `timeout`, or `rate_limited` result is not
  evidence that an indicator is safe.
- Attachment checks are static only: no attachment is executed, opened through
  external applications, decompressed, or uploaded to third parties.
- No live malicious payloads, active phishing endpoints, credentials, or
  personal data are stored in this corpus.

## Reproduction

From `backend/`, run:

```bash
venv/Scripts/python.exe -m pytest tests/test_real_world_validation.py -v
```

The expected result is nine passing tests. The final test computes the matrix
above directly from all fixtures so a regression changes the reported count.

## Status

- Core SOC detection is validated against sanitized spoofing, credential
  phishing, BEC, URL manipulation, authentication-failure, and attachment-risk
  representations.
- Attack-chain mappings produce evidence-backed `social_engineering` and
  `malware_attachment` stages where those indicators are observed.
- The fixture corpus remains test-only and is never a data source for the
  dashboard, live feed, persisted default analyses, or production APIs.