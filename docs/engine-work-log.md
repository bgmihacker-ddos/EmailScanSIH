# Engine Modernization Work Log

## 2026-09-09

### Completed

- Fixed repository-relative ML training paths so CLI invocations resolve to absolute paths before artifact metadata is written; added a regression test for missing repository-relative files.
- Hardened analysis job lifecycle updates so late worker checkpoints cannot overwrite completed, failed, or cancelled jobs.
- Added database-backed analysis jobs and indexed IOC candidates with an Alembic migration; async analysis payloads can be claimed by the one-pass worker in `backend/app/services/analysis_worker.py`.
- Switched campaign correlation from a broad recent-result scan to indexed IOC candidate lookup.
- Corrected the public corpus importer for extensionless/trailing-dot Enron Maildir entries by reading the original tarball on Windows.
- Rebuilt the mixed public corpus with 3,250 records (1,852 benign, 1,398 phishing) and retrained the public model; held-out accuracy is 0.9189 and macro F1 is 0.9163.
- Switched inference to prefer the public model artifact and added grouped source-aware ML evaluation metadata.
- Ran the five-fixture SIH matrix successfully: benign newsletter, phishing, BEC, spoofing, and malicious attachment.
- Applied migration `202609120001` to the configured PostgreSQL database.
- Added worker retry limits, stale-lock reclamation, continuous `--loop` mode, and a bounded retention sweep command.
- Added worker tests for exhausted jobs and stale-lock reclaim; focused result: 2 passed.
- Added threat probability operating-point metrics and balanced class weighting. Retrained public model metrics: accuracy 0.9361, macro F1 0.9347, phishing recall 0.8819 at threshold 0.50 and 0.9451 at threshold 0.40.
- Full-suite validation was attempted with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` and explicit `pytest_asyncio`; focused worker tests pass, while the broad run reaches async/provider tests and then hangs in the current Python environment. This is an environment/test-runner limitation, not a reported assertion failure in the new worker tests.
- Disabled unauthorized Google Safe Browsing and WHOIS integrations for the free-provider deployment; removed their local credentials, excluded Safe Browsing from active fan-out, and made WHOIS return an explicit non-networked `disabled` state.
- Live free-provider registry after the change: VirusTotal, URLhaus, ThreatFox, AbuseIPDB, RDAP, CIRCL Hashlookup, and AlienVault OTX connected; crt.sh temporarily offline; Google Safe Browsing absent; WHOIS disabled.

- Completed the next engine hardening pass across Phases 2, 3, 5, and 8.
- Added a reproducible `evidence_ledger` to risk results with source, signal, points, confidence, evidence class, risk relevance, and evidence references.
- Propagated analysis IDs into persisted evidence-ledger entries and added the ledger to the analysis schema.
- Added configurable safety limits for raw email size, attachment count, attachment hashing size, MIME parts, and IOC fan-out.
- Added bounded attachment hashing and explicit `hashing_status` metadata for oversized payloads.
- Added MIME-tree truncation metadata and a regression for rejected oversized emails.
- Focused validation passed: 45 tests across parser, scoring, correlation, and threat-intelligence suites.
- Corrected threat-intelligence capability routing: AbuseIPDB is IP-only and URLhaus is URL-only; unsupported combinations are now skipped with an explicit reason.
- Added bounded public-IP reverse DNS and geolocation enrichment to email analysis with source provenance and a frontend Infrastructure panel.
- Corrected duplicated ML explanation text (`Model classified as ml classified as ...`).
- Provider/API/geolocation validation passed: 23 tests; reverse-DNS/provider validation passed: 22 tests; frontend production build passed.
- Added independent-authentication provenance labels, raw-message SHA-256 evidence integrity, configurable retention/export masking, sanitized high-risk webhook alerts, cancellation and stale-job recovery, and the SIH readiness validation matrix.
- Final readiness validation: 204 backend tests passed (excluding optional Playwright collection) and the frontend production build passed.
- Added keyless RDAP registration/network context, crt.sh certificate-transparency history, and CIRCL Hashlookup file context providers.
- Corrected threat-intelligence scoring so `unknown` provider results remain informational and never receive a false clean-risk reduction.
- Provider expansion validation: 207 backend tests passed (excluding optional Playwright collection) and the frontend production build passed.
- Integrated Google Safe Browsing URL matching and AlienVault OTX URL/domain/IP/hash pulse context into the bounded threat-intelligence fan-out.
- Live verification: OTX domain lookup responded successfully; Google Safe Browsing returned authorization failure; OTX IP lookup timed out within the provider bound.
- WHOIS remains unauthorized because the configured key has no active subscription; these provider failures remain non-scoring and isolated.
- Final provider integration validation: 209 backend tests passed (excluding optional Playwright collection).
- Started the efficiency and ML quality roadmap: pipeline timing now separates URL, domain, attachment, content, and ML inference stages while retaining aggregate static timing.
- External IOC enrichment now prioritizes URLs, public relay IPs, attachment hashes, and suspicious-context indicators within the bounded lookup budget.
- ML evaluation now reports per-class support/precision/recall/F1 and binary threat-versus-benign metrics without changing the deployed classifier.

- Audited the official SIH problem statement against the existing engine.
- Confirmed the repository already contains parsing, header forensics, authentication evidence parsing, IOC extraction, URL/domain analysis, content analysis, attachments, ML, rules, threat intelligence, correlation, reasoning, attack-chain, graph, timeline, MITRE, and STIX components.
- Deferred platform authentication/RBAC work for the SIH engine scope.
- Identified the first engine bottleneck: major stages have status checkpoints but no reusable duration/item-count instrumentation.
- Added `backend/app/services/stage_timing.py` and `backend/tests/test_stage_timing.py`.
- Wired timing records for fast forensics, static analysis, DNS/WHOIS, threat intelligence, synthesis, campaign correlation, persistence, and total duration into the optional `stage_timings` result field.
- Generated `backend/docs/analysis-timing-baseline-2026-09-09.md` from a real sanitized benign fixture.
- Identified DNS/WHOIS enrichment as the dominant bottleneck at 26,506 ms of a 37,464 ms total.
- Added WHOIS result caching and a cold-start provider health probe lock.
- Added bounded DNS query and per-domain deadlines.
- Removed authentication parser labels from IOC domain enrichment; the same fixture improved to 22,078 ms total and 12,016 ms DNS/WHOIS.
- Full backend regression suite remains green at 195 tests after the optimization slice.
- Added separate per-domain `dns:<domain>` and `whois:<domain>` timing records with provider status/error propagation.
- Latest per-domain baseline: total `21,887 ms`; DNS peak `5,513 ms`; WHOIS cold probe `4,519 ms`.

### In Progress

- Phase 1: audit and profiling is implemented; timing baseline remains a measurement artifact to refresh after deployment changes.
- Phase 2/3: queued and running lifecycle exists; cancellation, stale-job cleanup, and true background deep-work separation still need an explicit job worker contract.
- Phase 6: forensic parsing and evidence labeling are implemented; independent authentication verification and production geolocation require provider/infrastructure decisions.
- Phase 7: full JSON persistence exists; indexed candidate tables and clean-database migration coverage remain.
- Phase 9: core regression coverage is maintained; final SIH fixture matrix and runtime demonstration report remain.
- The six readiness foundations are now implemented; distributed workers, mail-gateway/SIEM adapters, scheduled retention deletion, and analyst collaboration still depend on deployment choices.

### 2026-09-12

#### Completed

- Hardened the worker job contract by adding `status`, `worker_id`, `lease_expires_at`, and `heartbeat_at` to the persisted `AnalysisJob` model.
- Added `ANALYSIS_LEASE_SECONDS` to the runtime settings and used it to reclaim expired leases while preserving terminal-state safety.
- Updated the worker claim workflow to reject stale or expired leases, set the next attempt count, and reset jobs cleanly after a transient failure.
- Added a focused regression test for lease metadata, expired-lease reclaim, and invalid terminal-state transitions. Result: 5 worker tests passed.
- Added a shared `_update_job_status` guard that blocks invalid overwrites of terminal records to keep lifecycle transitions deterministic.

#### Completed

- Replaced the read-then-update claim with a single SQL `UPDATE` guard that checks the stale/expired lease conditions atomically in the database.
- Added a concurrency regression proving that a second worker cannot claim the same queued job after the first one succeeds.
- Kept retry, stale-lock recovery, and terminal-state protection intact while making the claim path safe across SQLite and PostgreSQL-style conditions.

#### Completed

- Added a worker health snapshot that reports `queue_depth`, `processing_jobs`, `stale_jobs`, `active_workers`, and `oldest_job_age_seconds`.
- Exposed the snapshot through the health route at `/api/worker/health`.
- Normalized timezone comparisons so stale/expired lease checks are truthful in SQLite and UTC-aware runtime data.

#### Verified / Completed

- Confirmed the per-domain DNS/WHOIS split is active in the pipeline via `dns:<domain>` and `whois:<domain>` timer records, with truthful provider status and error propagation retained alongside the aggregate `dns_whois_enrichment` stage.
- Validated the live app route and analysis flow in the browser: login and investigation pages load, auth bypass remains local-only for development, and the engine responds without blocking on the smallest controls.

#### Next

- Add structured lifecycle events, provider latency capture, and operator drain/pause controls.
- Resume the next roadmap phase focused on deeper worker telemetry and partial-result handling.
