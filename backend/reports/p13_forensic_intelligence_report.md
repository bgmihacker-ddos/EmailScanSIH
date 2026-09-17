# AUDIT SCRIPT: Phase 13 Forensic Intelligence Report
# Importers/Callers: Documentation / Project Tracking
# Affected API: /api/v1/intelligence/{case_id}
# Data schemas: ForensicIntelligence
# Verbatim instruction: "Create backend/reports/p13_forensic_intelligence_report.md... Include implementation summary, architecture, intelligence schema..."

# Phase 13: Forensic Intelligence & Investigation Automation

## 1. Implementation Summary
Implemented a unified `ForensicIntelligenceEngine` that converts the fragmented evidence nodes from Phase 11 and Timeline from Phase 12 into a single, cohesive, investigator-oriented output. This phase adds a presentation intelligence layer securely without introducing redundant detection scores or duplicate algorithms.

## 2. Architecture & Components
- **`app/schemas/intelligence.py`**: Strongly-typed `ForensicIntelligence` schema for investigation outputs.
- **`app/services/forensic_intelligence_engine.py`**: Rule-based engine translating `EvidenceManifest` and `EvidenceNode` graphs into concrete intelligence findings including ATT&CK mappings and contradictions.
- **`app/api/routes/intelligence.py`**: Exposes `GET /api/v1/intelligence/{case_id}` secured via `get_current_user` ensuring strict RBAC boundaries.
- **`tests/test_forensic_intelligence.py`**: Targeted integration test suite ensuring the engine structure, deterministic ordering, and API security.

## 3. Intelligence Derivation Features
- **IOC Prioritization**: Extracted, grouped, and strictly sorted by canonical evidence IDs resulting in deterministic IOC arrays.
- **Origin Assessment**: Extracts reliable observed origins (IPs and Relays) directly from the `RELAY_HOP` evidence chain, defaulting to observed (not claiming absolute attribution without data).
- **Attack Narrative**: Deterministic trace generator building human-readable sentences based directly on the presence or absence of graph indicators (relays, IPs, Ti matches).
- **ATT&CK Mapping**: Maps concrete evidence classes to MITRE definitions using a unified translation layer (`T1566.001` for attachments, `T1566.002` for URLs, `T1534` for BEC impersonations) supported by underlying evidence IDs.
- **Contradiction/Uncertainty Engine**: Automatically identifies logical disjoints (e.g., ML declaring benign while SIEM/TI declares malicious).
- **Recommendations**: Evidence-driven response workflows automatically mapped (e.g., "Inspect attachment manually in isolated sandbox" if an attachment node exists).

## 4. Integration with Existing Systems (P7-P12)
- **P7 Evidence**: `RELAY_HOP` and `IP` consumed directly for Origin Assessment.
- **P8 ML / BEC**: Extracted and summarized into Contributing Findings. Contradicts checked against external TI.
- **P9 Attachment**: Analyzed for static properties, drives dynamic AT&CK labeling and quarantine recommendations.
- **P10 Threat Intelligence**: Fusion results parsed to drive total case Severity (`CRITICAL`/`HIGH`) and Confidence scaling.
- **P11/P12 Manifest & Graph**: Complete dependence; Engine consumes `EvidenceManifest` making this layer strictly non-duplicative.

## 5. Security & Determinism
- **Authentication**: `Depends(get_current_user)` guarantees zero unauthorized Case access.
- **Determinism**: All dynamically built lists (`suspicious_indicators`, `attack_techniques`) undergo multi-key `.sort()` ensuring identical inputs produce mathematically identical schema representations on repeated executions.
- **No Execute Policy**: Engine contains no runtime sandboxing or LLM prompting — 100% rule-based data transformation eliminating injection threat models.

## 6. Known Limitations
- Related-Email Correlation is constrained to existing Database IDs; no multi-tenant cross-org sweeping is allowed due to strict silo rules.
- Confidence scoring is currently a rule-based baseline (85/50) rather than a probabilistic bayesian distribution.
- No independent Case-Management UI was built (Forbidden by scope rules).
