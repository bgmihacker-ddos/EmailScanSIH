# AUDIT SCRIPT: Phase 12 Investigation Timeline & Correlation Engine Report
# Importers/Callers: Documentation / Audit Suite
# Affected API: /api/v1/investigation/timeline/{case_id}, /api/v1/investigation/correlations/{case_id}, /api/v1/investigation/path/{case_id}, /api/v1/investigation/validate
# Data schemas: InvestigationTimeline, InvestigationCorrelations, InvestigationPath
# Verbatim instruction: "Implement investigator-oriented timeline and correlation engine... Endpoints for timeline, correlation, path, and verification... Comprehensive test suite covering deterministic timeline, relationships, and attack path traversal."

# P12: Investigation Timeline & Correlation Engine — Final Reality Report

## 1. Executive Summary
Phase 12 (P12) transforms the Phase 11 Forensic Evidence Graph and Cryptographic Chain of Custody into an investigator-oriented, deterministic chronological timeline and multi-stage correlation engine. The engine normalizes heterogeneous event timestamps, builds strongly typed forensic relationships with provenance tagging, reconstructs directed attack paths with cycle prevention, and exposes dedicated investigation APIs.

## 2. Implemented Architecture & Subsystems

### A. Strongly Typed Timeline Schemas (`backend/app/schemas/timeline.py`)
- **Timestamp Precision Modeling**: `TimestampPrecision` enum (`EXACT`, `SECOND`, `MINUTE`, `UNKNOWN`).
- **Standardized Event Types**: `TimelineEventType` enum capturing email arrival/parsing, relay hop traversal, authentication evaluation, origin IP identification, geo/ASN enrichment, URL extraction, IOC detection, threat intel feeds, static attachment findings, ML and BEC inferences, and risk fusion.
- **Forensic Relationship Types**: `RelationshipType` enum (`DERIVED_FROM`, `CONTAINS`, `OBSERVED_IN`, `ORIGINATED_FROM`, `RESOLVES_TO`, `ASSOCIATED_WITH`, `ENRICHED_BY`, `INDICATES`, `CONTRIBUTES_TO`, `SUPPORTS`, `CONTRADICTS`, `GENERATED_FROM`).
- **Data Models**:
  - `TimelineEvent`: Typed, UTC-normalized timestamp, provenance class, source, actor, related evidence references, and deterministic SHA-256 event hash.
  - `ForensicRelationship`: Directed relationship between evidence nodes with confidence and metadata.
  - `InvestigationTimeline`: Sorted deterministic chronological events for a given case.
  - `InvestigationCorrelations`: Graph relationship edges between nodes.
  - `InvestigationPath` & `InvestigationStep`: Traversable attack chain graph with roots and step sequencing.

### B. Timeline & Correlation Engine (`backend/app/services/timeline_correlation_engine.py`)
- **Deterministic Chronological Normalization**:
  - Ingests P11 `EvidenceManifest` and chain of custody.
  - Extracts physical forensic event timestamps (e.g., MIME `Date`, Received header ISO timestamps) and maps analysis lifecycle events.
  - Sorts events strictly by `(timestamp, event_type, event_id)` for guaranteed deterministic ordering across platforms.
- **Multi-Stage Evidence Correlation**:
  - Automatically derives structural links from `parent_id` hierarchy (`DERIVED_FROM`).
  - Correlates threat intelligence findings with associated network indicators (`INDICATES`).
  - Extensible relationship resolution preserving evidence provenance.
- **Attack Path Reconstruction**:
  - Implements bounded DFS traversal (max depth 100) with cycle prevention (`visited` tracking) starting from root evidence nodes (`EMAIL`).
  - Produces structured step hierarchies mapping the attacker's trajectory from initial delivery to threat discovery.

### C. Investigation API Endpoints (`backend/app/api/routes/investigation.py`)
- `GET /api/v1/investigation/timeline/{case_id}`: Returns the deterministic chronological timeline of forensic and analysis events.
- `GET /api/v1/investigation/correlations/{case_id}`: Returns all directed forensic relationships for the case.
- `GET /api/v1/investigation/path/{case_id}`: Reconstructs and returns the root-to-leaf attack path.
- `POST /api/v1/investigation/validate`: Verification endpoint for investigation integrity validation.

## 3. Test Coverage & Verification (`backend/tests/test_timeline_correlation.py`)
- Verified timeline generation, chronological sorting, and event type synthesis.
- Verified correlation relationship generation linking nodes and threat intel feeds.
- Verified attack path graph reconstruction, root step discovery, and adjacency traversal.
- Full unit test pass: 3/3 passed.

## 4. Invariants & Scope Compliance
- **Backend Only**: Zero modifications to `frontend/` components, styles, or configuration.
- **Preservation Invariants**:
  - P7 canonical deterministic `hop_id` preserved.
  - P8 ML pipeline & probability calibration preserved.
  - P9 static attachment forensics preserved.
  - P10 threat intelligence fusion and provider consensus preserved.
  - P11 evidence graph and chain of custody structures preserved.
