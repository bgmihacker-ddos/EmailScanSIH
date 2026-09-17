# AUDIT SCRIPT: Phase 11 Forensic Evidence Graph & Chain of Custody Report
# Importers/Callers: Documentation / Audit Suite
# Affected API: /api/v1/evidence/manifest, /api/v1/evidence/validate
# Data schemas: EvidenceManifest, EvidenceNode, CustodyEvent
# Verbatim instruction: "Implement tamper detection and validation APIs... and deterministic Case Evidence Manifest generation"

# P11: Forensic Evidence Graph & Chain of Custody — Final Reality Report

## 1. Executive Summary
Phase 11 (P11) establishes a deterministic, cryptographically verifiable forensic evidence graph, lineage hierarchy, and append-only chain of custody subsystem for the email threat detection platform. This ensures courtroom-grade non-repudiation, tamper detection, and deterministic case evidence manifest generation across all analysis runs.

## 2. Core Architecture & Implemented Components

### A. EvidenceNode Abstraction & Enums (`backend/app/schemas/evidence.py`)
- Standardized evidence types (`EMAIL`, `HEADER`, `RELAY_HOP`, `ATTACHMENT`, `IOC`, `URL`, `DOMAIN`, `IP`, `HASH`, `AUTHENTICATION_RESULT`, `THREAT_INTEL_RESULT`, `ML_FINDING`, `BEC_FINDING`, `STATIC_ATTACHMENT_FINDING`, `RISK_FINDING`, `TIMELINE_EVENT`, `REPORT`).
- Strict Provenance Classes (`OBSERVED`, `DERIVED`, `ENRICHED`, `MODEL`, `HEURISTIC`, `ANALYST`).
- Custody Event Types (`ACQUIRED`, `HASHED`, `PARSED`, `EXTRACTED`, `ANALYZED`, `ENRICHED`, `CORRELATED`, `EXPORTED`, `VERIFIED`).
- Pydantic models for `EvidenceNode`, `CustodyEvent`, and `EvidenceManifest`.

### B. Deterministic Canonical Hashing Engine (`backend/app/services/evidence_canonicalizer.py`)
- **Canonical JSON Serialization**: Strict sorted keys, normalized UTC ISO-8601 timestamps, enum values, and base model dumps with separators `(",", ":")` guaranteeing platform-independent hash stability.
- **SHA-256 Hashing**: Generates stable cryptographic identifiers for nodes (`compute_node_id`), custody events (`compute_event_id`), and entire evidence manifests (`compute_manifest_id`).
- **Cryptographic Chain of Custody**: Append-only event chaining linking each custody event's `event_id` to its `previous_event_hash`, preventing silent modifications.
- **Multi-Tier Tamper Detection**: `verify_custody_chain` and `verify_evidence_manifest` validate both internal linkage integrity and root hash matches.

### C. Forensic Graph Builder (`backend/app/services/evidence_graph_v2.py`)
- Automatically traverses full analysis results to construct complete evidence lineage graphs connecting root email nodes, relay hops (P7 integration), authentication results, static attachment forensics (P9 integration), IOCs, threat intelligence fusion (P10 integration), ML findings (P8 integration), BEC reasoning, and final verdict reports.

### D. Evidence API Endpoints (`backend/app/api/routes/evidence.py`)
- `GET /api/v1/evidence/manifest/{case_id}`: Generates and returns a deterministic `EvidenceManifest` for all analyses linked to a case.
- `POST /api/v1/evidence/validate`: Validates an exported `EvidenceManifest` for tampering or drift, returning detailed integrity failure diagnostics if anomalies are detected.

## 3. Test Verification & Results
- Comprehensive test suite (`backend/tests/test_evidence_custody.py`) covering:
  - Canonical JSON determinism & SHA-256 stability.
  - Evidence node identity determinism.
  - Custody chain creation, linking, and verification.
  - Tamper detection on event actors and node values.
  - Full case evidence manifest generation and verification.
- **Test Result**: 100% of tests passed successfully.

## 4. Invariants & Scope Compliance
- **Backend Only**: Zero modifications to `frontend/`, UI styling, or frontend configurations.
- **Preserved Invariants**: Maintained P7 canonical deterministic `hop_id`, P8 ML pipeline/calibration, P9 attachment static forensics, P10 threat intelligence fusion, BEC detection, and case/timeline functionality.
