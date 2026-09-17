# SIH Hackathon Upgrade Plan

This plan optimizes for a reliable, judge-visible demonstration rather than production-scale infrastructure.

## Completed foundation

- Indian UPI/KYC and brand-focused threat intelligence
- Attack simulation flow with prepared suspicious-email scenarios
- Evidence hashing, optional Sepolia anchoring, live verification, and Etherscan links
- CERT-In JSON export
- Attachment analysis, OCR/QR fallback behavior, MITRE mapping, evidence graph, and explainable reasoning
- Gmail inbox and batch analysis workflows

## Active local upgrade slice

- Connect anomaly detection and brand-impersonation detection to the real risk fusion path.
- Expose detector results in the analysis response for the demo dossier.
- Cover typo-squatting, homoglyph, UPI/KYC, reply-to mismatch, and benign-message regression cases.

## Recommended SIH demo order

1. Run the prepared Indian KYC phishing scenario.
2. Show the anomaly and impersonation evidence beside the verdict.
3. Open the MITRE and evidence graph views.
4. Export the CERT-In report.
5. Click blockchain `Verify` and show `MATCH` when the local chain configuration is available.

## Defer until after judging

- Microsoft Graph integration
- Distributed worker deployment and dead-letter queues
- Full MBOX scale testing and large dataset governance
- Model drift monitoring and production SLOs
- Broad provider expansion that makes the demo dependent on external quotas

## Local acceptance gate

- The prepared KYC, BEC, homoglyph, typo-squat, QR, and benign fixtures produce explainable results.
- External provider outages remain visible and do not turn into a clean verdict.
- Backend focused tests and the frontend build pass.
- No changes are pushed until local review is complete.