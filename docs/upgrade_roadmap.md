# Email Threat Detection Engine Modernization Plan

Scope: SIH 2026 forensic analysis engine. Platform login, RBAC, and account administration are deferred for now. Email authentication evidence (SPF, DKIM, DMARC, ARC) remains in scope.

## Phase 1: Audit and Profiling

- Add reusable stage timing and item-count instrumentation.
- Record parse, headers, authentication, IOC, URL, domain, content, attachment, ML, DNS, WHOIS, TI, fusion, reasoning, attack-chain, campaign, persistence, and total durations.
- Produce a developer-readable timing report from sanitized test emails.
- Establish baseline latency and identify the slowest stage before changing timeouts.
- Acceptance: every major stage has status, duration, analysis ID, and error information.
- Per-domain acceptance: DNS and WHOIS records are separately timed and retain truthful provider status.

## Phase 2: Truthful Job Lifecycle

- Keep one analysis ID from submission through persistence and frontend result loading.
- Define queued, running, completed, partial, failed, and cancelled semantics.
- Persist stage state and intermediate results where practical.
- Prevent stale processing jobs from remaining indefinitely.
- Add duplicate-submission and simultaneous-analysis tests.

## Phase 3: Fast and Deep Pipeline

- Keep parsing, header forensics, authentication evidence, IOC extraction, static URL/domain/content/attachment analysis, rules, ML, initial correlation, and initial risk in the fast path.
- Move DNS, WHOIS, IP reputation, URL/domain reputation, provider enrichment, campaign correlation, graph enrichment, MITRE enrichment, and finalization into bounded deep work.
- Preserve partial results when deep providers fail.

## Phase 4: Provider Health and Threat Intelligence

- Normalize and deduplicate IOC keys before provider fan-out.
- Add provider health states: available, not_configured, not_found, timeout, unauthorized, rate_limited, error, skipped.
- Add bounded concurrency, provider-specific timeouts, connection reuse, short-lived caching, and provider-aware retry rules.
- Never interpret unavailable or timeout as clean.

## Phase 5: Evidence Provenance and Risk Integrity

- Require every finding to include source, finding ID, evidence class, risk relevance, confidence, analysis ID, and evidence references.
- Keep contextual and informational evidence visible but non-scoring.
- Prevent duplicate authentication, URL, domain, TI, rule, and ML scoring.
- Make the final score reproducible from the evidence ledger.

## Phase 6: Email Forensics Accuracy

- Improve Received-chain parsing and distinguish observed infrastructure from attacker location.
- Add independent authentication verification where feasible; otherwise label header-reported evidence explicitly.
- Improve brand impersonation, BEC, URL, domain, and attachment evidence without keyword-only verdicts.
- Add public-IP geolocation to the email analysis path with provider provenance and approximate-location semantics.

## Phase 7: Scalable Correlation and Persistence

- Keep full forensic JSON for reports.
- Add indexed candidate fields/tables for sender domains, URLs, domains, IPs, message IDs, attachment hashes, and campaign keys.
- Replace bounded full-result scans with indexed candidate queries.
- Add migration coverage from a clean database.

## Phase 8: Safety and Resilience

- Enforce backend email, attachment, MIME, archive, IOC, and CPU/memory limits.
- Ensure DNS and WHOIS cannot block the event loop indefinitely.
- Isolate provider failures and preserve truthful partial results.
- Add structured logs without raw email, passwords, JWTs, or API keys.

## Phase 9: Validation and SIH Demonstration

- Maintain legitimate provider-routed regression coverage.
- Maintain phishing, BEC, spoofing, Punycode, malicious infrastructure, suspicious URL, and malicious attachment regressions.
- Add provider failure, timing, stale-result, duplicate-request, and simultaneous-analysis tests.
- Validate one legitimate, one phishing, one BEC, one spoofed, and one attachment-threat EML end to end.
- Record exact commands, timings, provider states, and remaining limitations.

## Phase 10: ML Training and Evaluation Plan

Current model status:

- [x] Public model trained and active: `tfidf-logreg-public-v3`.
- [x] Current corpus assembled from SpamAssassin and Enron-derived public mail.
- [x] Current corpus size recorded: 3,250 messages, 1,852 benign and 1,398 phishing.
- [x] Grouped source-aware evaluation enabled.
- [x] Threat threshold metrics recorded at 0.30, 0.40, 0.50, 0.60, and 0.70.
- [x] Balanced class weighting enabled to improve threat recall.
- [x] Current baseline recorded: 93.61% accuracy, 93.47% macro F1, 88.19% phishing recall at threshold 0.50.

Dataset expansion checklist:

- [ ] Add modern phishing email samples from a public, redistribution-permitted source.
- [ ] Add BEC, invoice fraud, payment-diversion, and executive-impersonation samples.
- [ ] Add malicious attachment metadata and sanitized attachment-threat samples.
- [ ] Add spoofing and SPF/DKIM/DMARC failure examples.
- [ ] Add hard benign enterprise messages to control false positives.
- [ ] Record source, license, label rationale, timestamp, and deduplication key for every record.
- [ ] Remove secrets, personal data, live credentials, and unsafe executable payloads before training.

Training and acceptance checklist:

- [ ] Deduplicate by message hash and source identifier before splitting.
- [ ] Keep source groups together between train and test sets.
- [ ] Add a time-based holdout when message dates are available.
- [ ] Compare the existing model against every candidate model on the same frozen holdout.
- [ ] Report phishing recall, threat precision, macro F1, false-positive rate, and threshold metrics.
- [ ] Validate all five SIH fixtures after retraining.
- [ ] Inspect false negatives manually before replacing the active artifact.
- [ ] Promote a new artifact only when it improves threat recall without unacceptable benign false positives.
- [ ] Store dataset provenance and evaluation metadata inside the model artifact.

Training decision gate:

- Do not retrain only because code changed.
- Retrain after meaningful labeled-data additions or feature-contract changes.
- Keep the current public artifact as the rollback model until the new model passes the acceptance checklist.
- The next ML milestone is modern phishing/BEC data coverage, not another run on the current corpus.

## Phase 11: AI-Powered Detection Roadmap

The SIH requirement should be implemented as a hybrid, evidence-grounded AI system. The AI may prioritize and interpret signals, but it must never invent evidence or override raw forensic facts.

### Current AI foundation

- [x] Explainable TF-IDF/logistic email classifier.
- [x] Structural email features for URLs, HTML, urgency, credentials, finance, replies, and attachments.
- [x] Rule engine for deterministic security signals.
- [x] Evidence correlation and reproducible risk ledger.
- [x] Threat reasoning, attack-chain reconstruction, MITRE mapping, and provider-aware enrichment.

### Recommended AI upgrades

- [ ] Add a semantic text model using a compact transformer or sentence-embedding model for paraphrased phishing and BEC language.
- [ ] Keep the current TF-IDF model as a fast, interpretable baseline and fallback when the semantic model is unavailable.
- [ ] Train an ensemble layer that combines rule score, classical ML probability, semantic probability, authentication evidence, attachment risk, and threat-intelligence evidence.
- [ ] Calibrate ensemble probabilities so confidence reflects validation behavior rather than raw model certainty.
- [ ] Add an unsupervised anomaly detector for unusual sender domains, reply-to relationships, mail-flow patterns, language, and attachment combinations.
- [ ] Add sender and campaign embeddings for similarity search against prior investigations.
- [ ] Use graph-based features for shared domains, URLs, IPs, hashes, senders, and campaigns before considering a graph neural network.
- [ ] Add active learning: queue low-confidence and false-positive/false-negative cases for analyst labeling.
- [ ] Add drift monitoring for class balance, vocabulary changes, provider-state changes, and confidence distribution.
- [ ] Add an optional local or hosted LLM explanation layer that can summarize only the evidence ledger and never raw provider claims outside the ledger.
- [ ] Require structured JSON output, evidence references, confidence, and a refusal state for every AI explanation.
- [ ] Cache AI enrichment by message hash and model version; never call an external AI service during deterministic parsing.

### AI safety and acceptance gates

- [ ] No AI component may create a finding without an evidence reference.
- [ ] Provider timeout, missing data, and unknown status must not be described as clean evidence.
- [ ] Raw email, credentials, tokens, and sensitive attachments must not be sent to external AI providers by default.
- [ ] Compare AI ensemble performance against the current public model on one frozen holdout.
- [ ] Report per-class precision, recall, F1, calibration, false-positive rate, false-negative review, and latency.
- [ ] Validate the five SIH fixtures and adversarial paraphrases after each model promotion.
- [ ] Preserve the current rules-plus-TF-IDF path as a deterministic fallback.

### Recommended implementation order

1. Add semantic embeddings and benchmark them without changing verdicts.
2. Add calibrated hybrid fusion behind a feature flag.
3. Add campaign/sender similarity retrieval using the existing IOC indexes.
4. Add active-learning review and drift dashboards.
5. Add optional evidence-grounded LLM summaries only after the deterministic AI ensemble is validated.
