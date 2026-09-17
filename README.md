# EmailScanSIH — AI Email Threat Detection, GeoLocation & Forensic Intelligence

> **Smart India Hackathon 2026 · SIH26106 · Cyber Security Cell**

EmailScanSIH is an evidence-first email security and forensic analysis platform. It accepts raw `.eml` messages and combines independent security signals to produce an explainable threat assessment rather than relying on a single machine-learning prediction.

The system is designed for **phishing, Business Email Compromise (BEC), spoofing, credential harvesting, brand impersonation, suspicious infrastructure, malicious URLs/domains, authentication anomalies, and attachment-based indicators**.

> **Core principle:** probabilistic ML is supporting evidence. The final assessment is based on multiple technical and contextual signals that investigators can trace back to the original message and extracted artifacts.

---

## What the platform does

```text
Raw .eml
   │
   ▼
Email ingestion + safe parsing
   │
   ├── Headers / routing / Received chain
   ├── SPF / DKIM / DMARC / authentication evidence
   ├── URLs / domains / IPs / hashes / IOCs
   ├── Content / NLP / ML
   └── Attachments / static artifact analysis
   │
   ▼
Threat Intelligence enrichment
   │
   ▼
BEC + brand impersonation + forensic intelligence
   │
   ▼
Threat fusion + risk scoring
   │
   ├── Explainable findings
   ├── Evidence provenance + integrity
   ├── Timeline / correlations / attack path
   └── Investigation intelligence / reporting
   │
   ▼
Security dashboard / API
```

---

## Key capabilities

| Capability | Implementation focus |
|---|---|
| **Raw Email Forensics** | MIME parsing, headers, metadata, message integrity, body and artifact extraction |
| **Routing Analysis** | `Received` chain reconstruction and relay/origin context |
| **SPF / DKIM / DMARC** | Authentication results are preserved as evidence and interpreted with other signals |
| **URL Intelligence** | URL extraction, normalization, suspicious patterns and enrichment |
| **Domain Intelligence** | Domain characteristics, lookalikes, typosquatting and homoglyph-style indicators |
| **IOC Extraction** | URLs, domains, IPs, hashes and other security indicators |
| **Threat Intelligence Fusion** | Multiple external providers with normalized results, caching, failure handling and consensus |
| **ML Detection** | Explainable TF-IDF + Logistic Regression pipeline trained offline |
| **BEC Detection** | Executive/freemail impersonation, payment/bank-change, gift-card and urgency/secrecy patterns |
| **Attachment Static Forensics** | File identification, hashes, entropy, archive inspection, macro/execution indicators, PDF/script checks and IOC extraction |
| **Risk Engine** | Multi-signal fusion of deterministic and probabilistic evidence |
| **Explainable Analysis** | Human-readable findings linked to supporting evidence |
| **Evidence Graph** | Deterministic evidence nodes, lineage and append-only custody records |
| **Investigation Timeline** | Deterministic event ordering, relationships and attack-path traversal |
| **Forensic Intelligence** | Evidence-backed IOC prioritization, root/origin context, ATT&CK-aligned findings, contradictions and recommendations |
| **Campaign Correlation** | Connects related IOC/artifact candidates across analyses |
| **Durable Analysis Jobs** | Queued work, bounded retries, cancellation and stale-job recovery |
| **Gmail Ingestion** | Read-only Gmail message retrieval through OAuth for analysis workflows |
| **Security Controls** | Authentication, authorization, input validation, resource limits and SSRF protections |

---

## Architecture

The backend is built as a modular FastAPI application with distinct analysis services and explicit data contracts between stages.

```text
                         ┌───────────────────────┐
                         │      Raw .eml         │
                         └───────────┬───────────┘
                                     ▼
                         ┌───────────────────────┐
                         │ Ingestion / MIME      │
                         │ Parsing + Validation  │
                         └───────────┬───────────┘
                                     ▼
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
      Header / Auth        URL / Domain / IOC      Content / ML
      & relay analysis          analysis             analysis
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   ▼
                         ┌───────────────────────┐
                         │ Threat Intelligence  │
                         │ + Provider Consensus │
                         └───────────┬───────────┘
                                     ▼
                         ┌───────────────────────┐
                         │ BEC / Impersonation   │
                         │ Attachment Forensics  │
                         └───────────┬───────────┘
                                     ▼
                         ┌───────────────────────┐
                         │ Threat Fusion + Risk  │
                         └───────────┬───────────┘
                                     ▼
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
        Explainability       Evidence Graph        Investigation
                                   │             Timeline / Correlation
                                   └──────────┬─────────┘
                                              ▼
                                   Forensic Intelligence
                                              │
                                              ▼
                                      API / Dashboard
```

### Evidence and investigation flow

```text
Email
  ↓
Evidence extraction
  ↓
Evidence nodes + cryptographic identifiers
  ↓
Custody / provenance relationships
  ↓
Timeline events
  ↓
Cross-artifact relationships
  ↓
Attack-path traversal
  ↓
Forensic intelligence
```

---

## Threat assessment philosophy

EmailScanSIH deliberately separates **evidence** from **probability**.

Deterministic signals such as authentication results, observed IOCs, suspicious routing, attachment indicators and threat-intelligence findings are represented as evidence. ML probabilities provide contextual classification signals and are not treated as proof of maliciousness.

This is especially important for false-positive control. A short legitimate transactional email can produce an elevated standalone ML probability while still remaining low risk when the surrounding technical evidence is benign. The platform therefore evaluates the whole message rather than blindly promoting a single classifier output to the final verdict.

---

## Machine Learning

The current production-oriented public training workflow uses an explainable **TF-IDF + Logistic Regression** classifier.

Example training command:

```powershell
python ml/training/train.py `
  --dataset ml/datasets/real/public_email_threats.jsonl `
  --artifact ml/models/email_threat_tfidf_logreg_public.joblib
```

Important ML engineering practices in the project include:

- deterministic seeds and reproducible training;
- exact duplicate controls and dataset validation;
- held-out evaluation partitions;
- calibration-aware probability handling;
- separate robustness evaluation for synthetic/human test sets;
- distinction between model probability and final forensic risk;
- adversarial/red-team validation of model and end-to-end behavior.

### ML limitation worth noting

The classifier is not presented as universally accurate. Evaluation exposed sensitivity to very short, finance-heavy benign messages, which is why the system uses multi-signal risk fusion instead of treating the classifier as a standalone verdict engine.

Do not interpret a benchmark score from a single dataset as proof of generalized phishing-detection performance.

---

## Threat Intelligence

The backend normalizes IOC enrichment from multiple providers and tracks provider-level status instead of assuming every external source is always available.

The threat-intelligence layer supports normalized IOC records, provider results, confidence/reputation metadata, references, failures/fallback states and consensus/disagreement information.

Operational protections include bounded HTTP connection pools, short timeouts, bounded caching, provider circuit-breaker behavior and SSRF defenses for unsafe IP targets.

External TI failures are treated as **informational system conditions** and do not silently manufacture a lower-risk result.

---

## Attachment static forensics

Attachments are treated as untrusted input and are analyzed statically rather than executed.

The forensic layer supports checks including:

- Shannon entropy and file fingerprints;
- MIME/magic-byte identification;
- ZIP/TAR/GZIP/BZIP archive inspection;
- Zip Slip and archive-bomb protections;
- nested executable and multi-extension indicators;
- OOXML macro / remote-template / execution-keyword detection;
- PDF action / JavaScript / embedded-file indicators;
- PE/script indicators;
- extracted URLs and IPv4 IOCs with provenance metadata.

Static inspection is intentionally bounded and should not be interpreted as a guarantee that arbitrary future malware formats are fully detected.

---

## Evidence integrity & chain of custody

The evidence layer provides deterministic canonicalization and SHA-256-derived identifiers for evidence and custody records.

Evidence can connect:

```text
Email headers
   ├── relay hops
   ├── authentication
   ├── URLs / domains / IPs
   ├── attachments
   ├── threat-intelligence results
   ├── ML findings
   ├── BEC findings
   └── reports / derived intelligence
```

This allows investigators to trace a finding back to the supporting artifact instead of relying on an opaque final score.

> The evidence system is cryptographically verifiable, but this repository does **not** claim that its local ledger is equivalent to an external blockchain or an independently notarized legal evidentiary system.

---

## Investigation timeline & correlation

The investigation engine consumes evidence-manifest data and produces deterministic timeline events and relationships.

It can represent relationships such as:

- parent/child evidence relationships;
- relay-path relationships;
- indicator-to-event relationships;
- derived investigation relationships;
- bounded attack-path traversal with cycle protection.

The internal investigation identifier is a technical grouping mechanism connecting an email, its analysis, evidence, timeline and derived intelligence. It is not intended to expose a heavy case-management workflow.

---

## Forensic intelligence

The intelligence layer turns lower-level evidence into structured investigation context, including:

- prioritized IOCs;
- origin/relay context;
- authentication intelligence;
- URL/domain intelligence;
- attachment intelligence;
- BEC intelligence;
- ATT&CK-aligned technique references where evidence supports them;
- evidence-backed confidence separated from ML probability;
- contradiction and uncertainty reporting;
- deterministic investigator recommendations.

Recommendations are generated from available evidence and should be reviewed by an analyst before operational action.

---

## Gmail ingestion

The platform includes a read-only Gmail ingestion flow for analysis.

The backend can retrieve raw Gmail messages through Google OAuth, refresh encrypted access credentials when needed, queue analyses, and expose analysis status through the application API.

No mailbox modification operation is required for the core analysis workflow.

---

## Security engineering

Because raw email and extracted indicators are untrusted input, the backend applies defensive controls including:

- request authentication and authorization;
- input validation and bounded payload processing;
- MIME-part and archive resource limits;
- SSRF protections for unsafe destinations;
- safe static attachment inspection;
- secret/environment separation;
- bounded external-provider timeouts and retries;
- provider circuit breakers;
- stale analysis recovery;
- deterministic evidence handling;
- avoidance of automatic attachment execution.

Production deployments should additionally apply network segmentation, managed secrets, HTTPS, database hardening, least-privilege credentials, logging controls and an appropriate retention policy.

---

## Project structure

```text
EmailScanSIH/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── detection/
│   │   ├── models/
│   │   ├── schemas/
│   │   └── services/
│   ├── alembic/
│   ├── contracts/
│   ├── docs/
│   ├── reports/
│   ├── samples/
│   ├── scripts/
│   ├── tests/
│   └── requirements.txt
├── frontend/                 # React / TypeScript dashboard
├── ml/                       # Training code and ignored model artifacts
├── docs/                     # Project documentation / datasets
├── .gitignore
├── LICENSE
└── README.md
```

Generated databases, local environments, large datasets and trained model weights should remain outside the Git repository unless intentionally required as reproducible fixtures.

---

## Local setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- PostgreSQL 15+ or a compatible PostgreSQL/Supabase database

### Backend

```bash
git clone https://github.com/bgmihacker-ddos/EmailScanSIH.git
cd EmailScanSIH
cd backend
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies and migrations:

```bash
pip install -r requirements.txt
python -m alembic upgrade head
```

Run the API:

```bash
uvicorn app.main:app --reload
```

### Frontend

From the repository root:

```bash
cd frontend
npm install
npm run dev
```

### Configuration

Create an environment file from `backend/.env.example` and provide the required database, authentication and optional intelligence-provider settings.

```env
DATABASE_URL=postgresql://<user>:<password>@<host>:5432/<database>
```

Never commit:

- API keys;
- OAuth client secrets;
- JWT signing secrets;
- database passwords;
- service-role keys;
- private email data.

---

## Production-style worker operation

The backend includes durable analysis worker and retention-process entry points.

Analysis worker:

```bash
python -m app.services.analysis_worker --loop
```

Retention process:

```bash
python -m app.services.retention
```

Bounded retry and stale-job settings are controlled through the backend configuration.

For hosted deployments, validate the full lifecycle rather than assuming that a request returning `202` proves durable completion:

```text
upload
  ↓
queued
  ↓
worker claims job
  ↓
analysis executes
  ↓
results persisted
  ↓
evidence generated
  ↓
status becomes complete
```

---

## Testing

Run the backend test suite from the `backend` environment:

```bash
pytest
```

The project also contains dedicated validation for attachment forensics, threat-intelligence behavior, evidence integrity, investigation correlation and full-system/red-team scenarios.

A green unit-test run is not, by itself, proof that the detector is universally accurate. Security evaluation should include representative benign traffic, phishing/BEC variants, malformed inputs, adversarial examples, external-provider failures and resource-exhaustion cases.

---

## Current engineering status

The repository focuses on **maturity and reliability rather than feature-count inflation**.

Completed engineering areas include:

- ✅ email parsing and header forensics
- ✅ SPF/DKIM/DMARC evidence handling
- ✅ URL/domain/IOC analysis
- ✅ ML classification and evaluation workflow
- ✅ BEC and impersonation detection
- ✅ threat-intelligence normalization and fusion
- ✅ attachment static forensics
- ✅ evidence graph and chain-of-custody model
- ✅ investigation timeline and correlation engine
- ✅ forensic-intelligence layer
- ✅ authentication/authorization protections on investigation APIs
- ✅ durable analysis-job infrastructure
- ✅ red-team and adversarial validation work

The project is intentionally **not** advertising unfinished roadmap items as completed capabilities.

---

## What this repository does not claim

To keep the project technically honest:

- It does not claim perfect or universal phishing-detection accuracy.
- It does not treat ML probability as ground truth.
- It does not treat IP geolocation as attacker attribution.
- It does not claim local evidence storage is equivalent to blockchain notarization.
- It does not execute malicious attachments during static analysis.
- It does not treat third-party threat-intelligence availability as guaranteed.

---

## Responsible use

EmailScanSIH is intended for **education, research, prototyping and authorized defensive security analysis**.

Analyze only email data and infrastructure for which you have appropriate authorization. Threat-intelligence observations, geolocation, automated classifications and forensic conclusions should be reviewed in context before incident-response or other operational decisions.

---

## License

MIT License. See [`LICENSE`](LICENSE).

---

## Project goal

> **Turn suspicious emails into evidence-backed, explainable security intelligence.**

Built for **Smart India Hackathon 2026 — SIH26106**.
