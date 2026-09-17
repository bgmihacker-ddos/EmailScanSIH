# Advanced Email Threat Detection Engine Roadmap

## Purpose

This roadmap focuses on the five upgrades that matter most for the SIH engine and for a credible AI-powered email security product:

1. Reliable analysis workers
2. Modern threat-data coverage
3. Hybrid AI detection
4. Operational evaluation
5. End-to-end production validation

The current rules, forensic parser, evidence ledger, threat intelligence integrations, explainable TF-IDF model, indexed IOC persistence, and frontend investigation workflow are the baseline. This roadmap improves their reliability and decision quality without replacing the evidence-first architecture.

## Priority Order

| Priority | Workstream | Why it comes first | Exit condition |
|---|---|---|---|
| P0 | Reliable analysis workers | A stalled or lost job invalidates every later capability | Jobs survive restart, retry safely, and return partial or terminal truth |
| P1 | Operational evaluation | We need trustworthy measurements before promoting new models | Frozen fixture and holdout reports are reproducible |
| P1 | Modern threat-data coverage | Current public data is not representative enough for BEC and modern phishing | Dataset has provenance, category balance, and safe licensing |
| P2 | Hybrid AI detection | Semantic understanding improves paraphrased and novel attacks | Hybrid model beats baseline on recall without unacceptable false positives |
| P2 | End-to-end validation | Demonstrates the complete SIH workflow under failures and real timings | Repeatable demonstration report passes all gates |

## Workstream 1: Reliable Analysis Workers

### Current phase status

This first phase was completed as a practical hardening slice focused on the worker claim contract and lease safety. The engine now tracks worker status, worker ownership, lease expiry, and stale-lock recovery without corrupting terminal states.

### 1.1 Define the job contract

- [x] Persist analysis ID, payload, status, attempts, lock time, and timestamps.
- [x] Define terminal states: `completed`, `partial`, `failed`, and `cancelled`.
- [x] Define the state transition table and reject invalid transitions.
- [x] Add a `heartbeat_at` field updated at every major stage.
- [x] Add `worker_id` and `lease_expires_at` for multi-worker ownership.
- [ ] Store a sanitized failure code separately from internal logs.

### 1.2 Make claiming concurrency-safe

- [x] Replace read-then-update claiming with an atomic database claim.
- [x] Use row locking or an atomic update appropriate for PostgreSQL and SQLite test mode.
- [x] Prove that two workers cannot process one job simultaneously.
- [x] Add duplicate submission and simultaneous claim tests.
- [x] Reclaim expired leases only after the configured lease period.

### 1.3 Separate fast and deep analysis

- [x] Return fast deterministic results after parsing, authentication, IOC extraction, rules, ML, and initial risk.
- [x] Continue DNS, WHOIS, provider enrichment, campaign correlation, and finalization as deep work.
- [x] Persist a partial result before external enrichment.
- [x] Mark provider failures as partial evidence, never as clean evidence.
- [x] Allow the frontend to display partial results while deep work continues.
- [x] Record per-domain `dns:<domain>` and `whois:<domain>` stages so remaining enrichment time can be optimized precisely without hiding provider status.

### 1.4 Retry and failure policy

- [x] Add bounded attempts and stale-lock recovery.
- [ ] Retry only transient failures such as timeout, connection reset, or rate limit.
- [ ] Do not retry malformed MIME, safety-limit violations, or invalid payloads.
- [ ] Add exponential backoff with jitter.
- [ ] Move exhausted jobs to a reviewable failed state.
- [ ] Add a dead-letter export for failed job metadata without raw email.

### 1.5 Worker observability

- [ ] Emit structured events for claim, stage start, stage completion, retry, cancellation, and failure.
- [ ] Record queue depth, age of oldest job, processing latency, and provider latency.
- [x] Add a worker health endpoint or metrics snapshot.
- [ ] Add an operator command to drain or pause new work.

### Acceptance gate

- Worker restart does not lose queued jobs.
- A crashed worker's lease is reclaimed once and only once.
- A cancelled job cannot later become completed.
- A provider timeout produces a truthful partial result.
- Two workers cannot duplicate persistence or alerts.

## Workstream 2: Modern Threat-Data Coverage

### 2.1 Dataset governance

- [ ] Create a dataset manifest with source URL, license, retrieval date, label policy, and checksum.
- [ ] Store normalized records with stable `source`, `source_file`, `source_message_id`, and content hash.
- [ ] Remove secrets, personal data, active credentials, and unsafe executable payloads.
- [ ] Keep raw archives outside the repository and commit only safe derived data or documented download scripts.
- [ ] Version datasets separately from model artifacts.

### 2.2 Required categories

- [ ] Modern credential phishing.
- [ ] BEC and executive impersonation.
- [ ] Invoice fraud and payment diversion.
- [ ] OAuth consent and cloud-account phishing.
- [ ] Spoofed sender and authentication failures.
- [ ] Malicious attachment metadata and safe attachment descriptors.
- [ ] QR-code phishing and shortened-link abuse.
- [ ] Hard benign enterprise mail, newsletters, receipts, support, and automated notifications.

### 2.3 Dataset quality

- [ ] Deduplicate exact and near-duplicate messages.
- [ ] Detect label leakage from subject prefixes, source folder names, and synthetic markers.
- [ ] Balance categories without artificially forcing equal class counts.
- [ ] Keep source groups together during evaluation.
- [ ] Create a time-based holdout where timestamps exist.
- [ ] Create a frozen SIH holdout that is never used for training.
- [ ] Manually review a sample of every category and every false negative.

### Acceptance gate

- Every record has provenance and label rationale.
- No train/test duplicate crosses the split.
- Every target category has measurable support.
- Dataset limitations are documented before reporting metrics.

## Workstream 3: Hybrid AI Detection

### 3.1 Baseline preservation

- [x] Keep deterministic parser, authentication analysis, rules, and evidence ledger.
- [x] Keep the current TF-IDF/logistic model as a fast fallback.
- [ ] Freeze a baseline artifact and baseline metrics before adding a semantic model.

### 3.2 Semantic model

- [ ] Benchmark a compact transformer or sentence-embedding model offline.
- [ ] Use subject, normalized body, sender/reply-to relationship, and selected structural features.
- [ ] Truncate input safely and record truncation metadata.
- [ ] Measure CPU/memory/latency on the deployment target.
- [ ] Add model loading failure fallback to the current classifier.
- [ ] Never send raw email to an external model by default.

### 3.3 Evidence fusion

- [ ] Build a versioned fusion input contract.
- [ ] Combine authentication, header, content, URL, domain, attachment, ML, semantic, and TI signals.
- [ ] Prevent duplicate scoring when multiple sources describe the same signal.
- [ ] Calibrate probabilities on a validation set.
- [ ] Keep final score reproducible from the evidence ledger.
- [ ] Put hybrid inference behind a feature flag until validated.

### 3.4 Novelty and anomaly detection

- [ ] Add sender/domain novelty features.
- [ ] Add campaign similarity using indexed IOC candidates.
- [ ] Add anomaly signals for unusual reply-to, mail-flow, language, URL, and attachment combinations.
- [ ] Label anomaly output as contextual evidence unless confirmed by stronger signals.
- [ ] Do not convert novelty alone into a malicious verdict.

### 3.5 Analyst feedback and active learning

- [ ] Add analyst labels: correct, false positive, false negative, and uncertain.
- [ ] Store labels separately from original automated verdicts.
- [ ] Prioritize low-confidence and disagreement cases for review.
- [ ] Generate a retraining candidate set only after privacy review.
- [ ] Track model version against every analyst label.

### 3.6 Optional AI explanation layer

- [ ] Add only after hybrid scoring is validated.
- [ ] Give the model the evidence ledger, not unrestricted raw provider output.
- [ ] Require structured JSON with evidence references and confidence.
- [ ] Add a refusal state when evidence is insufficient.
- [ ] Display AI explanation as a summary, never as the source of the verdict.

### Acceptance gate

- Hybrid model improves phishing/BEC recall on the frozen holdout.
- False-positive rate remains within the agreed operational limit.
- Every explanation maps to stored evidence.
- Deterministic fallback remains available and tested.

## Workstream 4: Operational Evaluation

### 4.1 Frozen test assets

- [x] Legitimate fixture.
- [x] Phishing fixture.
- [x] BEC fixture.
- [x] Spoofing fixture.
- [x] Malicious attachment fixture.
- [ ] Add modern BEC and OAuth-phishing fixtures.
- [ ] Add adversarial paraphrases of existing attacks.
- [ ] Add near-miss benign messages for false-positive testing.

### 4.2 Metrics

- [ ] Accuracy, macro F1, and per-class support.
- [ ] Threat precision and recall at multiple thresholds.
- [ ] False-positive rate on hard benign mail.
- [ ] False-negative review by threat category.
- [ ] Calibration error and reliability curve.
- [ ] P50/P95/P99 latency for fast and deep stages.
- [ ] Provider timeout and partial-result rates.
- [ ] Worker queue age and retry rate.

### 4.3 Release comparison

- [ ] Evaluate baseline and candidate on the same frozen holdout.
- [ ] Store metrics beside the artifact.
- [ ] Compare feature and model versions.
- [ ] Require explicit promotion notes.
- [ ] Keep the prior artifact for rollback.

### Acceptance gate

No model or scoring change is promoted from one metric alone. Promotion requires category metrics, latency, false-positive review, fixture results, and a rollback artifact.

## Workstream 5: End-to-End Production Validation

### 5.1 Core flows

- [ ] Submit raw MIME.
- [ ] Upload EML.
- [ ] Observe live queue progress.
- [ ] Open partial result.
- [ ] Open completed result.
- [ ] Download masked JSON and HTML reports.
- [ ] Search indexed IOCs.
- [ ] Reopen a historical investigation.
- [ ] Cancel a running job.
- [ ] Recover a stale job.

### 5.2 Failure flows

- [ ] Invalid MIME.
- [ ] Oversized email.
- [ ] Oversized attachment.
- [ ] Provider timeout.
- [ ] Provider unauthorized response.
- [ ] Database reconnect.
- [ ] Worker crash during parsing.
- [ ] Worker crash during enrichment.
- [ ] Duplicate worker claim.
- [ ] Alert delivery failure.

### 5.3 Demonstration evidence

- [ ] Record exact commit and model version.
- [ ] Record dataset manifest and metrics.
- [ ] Record fixture verdicts and evidence references.
- [ ] Record provider states and timing percentiles.
- [ ] Record known limitations.
- [ ] Produce a five-minute SIH demonstration runbook.

### Acceptance gate

The system gives a truthful result or truthful failure state for every tested flow, never silently labels unavailable intelligence as clean, and produces enough evidence for a judge or analyst to reproduce the decision.

## Additional Recommended Upgrades

These support the five priorities and should follow them rather than compete with them:

- [ ] Add privacy-preserving retention deletion and verify it on PostgreSQL.
- [ ] Add secrets scanning and prevent API keys from entering frontend bundles or reports.
- [ ] Add request correlation IDs across API, worker, provider calls, and logs.
- [ ] Add rate limiting and upload quotas at the API boundary.
- [ ] Add database backup/restore rehearsal before production deployment.
- [ ] Add SIEM and mail-gateway adapters after the core worker contract is stable.
- [ ] Add role-based analyst collaboration only after engine behavior is validated.
- [ ] Add frontend code splitting after the engine workflow is stable; current bundle-size warnings are secondary.

## Explicit Non-Goals For Now

- Do not chase a 99.9% accuracy claim.
- Do not add an external LLM before evidence-grounded fusion is validated.
- Do not add more providers merely to increase the provider count.
- Do not rebuild authentication/RBAC while the SIH engine is the priority.
- Do not train on unverified, unlabeled, or privacy-sensitive mail.
