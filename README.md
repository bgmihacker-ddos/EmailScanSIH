# EmailScanSIH

> AI-assisted email threat detection, threat intelligence, and forensic investigation platform for Smart India Hackathon 2026 (SIH26106).

EmailScanSIH analyzes raw `.eml` email messages and combines multiple security signals into an explainable assessment. Instead of treating a single ML prediction as the verdict, the platform correlates email content, headers, authentication results, URLs, domains, IPs, attachments, threat-intelligence data, and forensic evidence.

## Why EmailScanSIH

Modern phishing and Business Email Compromise (BEC) messages can look legitimate while hiding suspicious infrastructure, authentication failures, manipulated URLs, impersonation, or malicious attachments. EmailScanSIH is designed to expose those signals and present them together so an analyst can understand **why** a message was flagged.

## Core capabilities

| Area | What the platform provides |
|---|---|
| Email forensics | MIME parsing, message extraction, header inspection, metadata and artifact handling |
| Authentication analysis | SPF, DKIM and DMARC result extraction and contextual interpretation |
| Relay analysis | `Received`-chain reconstruction, relay/origin context and path analysis |
| URL & domain analysis | URL extraction, normalization, suspicious patterns, domain intelligence and lookalike detection |
| IOC extraction | URLs, domains, IPv4 addresses, hashes and other security indicators |
| Threat intelligence | Provider enrichment, normalized results, caching, provider health/fallback handling and consensus information |
| ML detection | TF-IDF + Logistic Regression email classifier with reproducible training/evaluation tooling |
| BEC detection | Urgency, payment/bank-change, gift-card, executive impersonation and related patterns |
| Attachment forensics | Static file identification, hashes, entropy, archive inspection, macro/PDF/script/executable indicators and IOC extraction |
| Threat fusion | Combines deterministic and probabilistic signals into an explainable risk assessment |
| Evidence graph | Links findings back to source artifacts with deterministic identifiers and provenance relationships |
| Investigation timeline | Correlates evidence and events into a traceable investigation sequence |
| Forensic intelligence | IOC prioritization, origin/relay context, contradictions, ATT&CK-aligned references and evidence-backed recommendations |
| Campaign correlation | Finds relationships between indicators and related analyses |
| Durable analysis jobs | Queued analysis, bounded retries, cancellation and stale-job recovery |
| Gmail ingestion | Read-only Gmail message retrieval through OAuth for analysis workflows |
| Security controls | Authentication, authorization, validation, resource limits and SSRF defenses |

## Analysis pipeline

```text
                         Raw .eml
                            │
                            ▼
               Ingestion + safe MIME parsing
                            │
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼
   Header / relay      URL / domain / IOC   Content / ML
   authentication           analysis          analysis
         │                  │                  │
         └──────────────────┼──────────────────┘
                            ▼
                  Threat-intelligence
                       enrichment
                            │
                  ┌─────────┴─────────┐
                  ▼                   ▼
             BEC / spoofing     Attachment
             / impersonation      forensics
                  └─────────┬─────────┘
                            ▼
                  Threat fusion + risk
                         scoring
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
 Explainable findings  Evidence graph      Timeline / cases
                            │                    │
                            └─────────┬──────────┘
                                      ▼
                           Forensic intelligence
                                      │
                                      ▼
                              API / web dashboard
```

### Evidence-first design

The project deliberately separates **evidence** from **probability**.

Deterministic observations—such as authentication outcomes, extracted IOCs, routing anomalies, attachment findings, and external threat-intelligence results—remain traceable evidence. ML probabilities add contextual classification signals but are not treated as proof of maliciousness.

This design also makes uncertainty visible. A message can have a high model probability while still receiving a different overall assessment when surrounding technical evidence is benign or contradictory.

## Architecture

The repository is organized as a modular full-stack application:

```text
EmailScanSIH/
├── backend/
│   ├── app/
│   │   ├── api/                 # FastAPI routes
│   │   ├── core/                # configuration, security, OAuth helpers
│   │   ├── detection/           # detection and risk-fusion components
│   │   ├── models/              # database models
│   │   ├── schemas/             # API/data contracts
│   │   └── services/            # parsing, enrichment, forensics, TI, jobs
│   ├── alembic/                 # database migrations
│   ├── contracts/               # evidence-ledger contract
│   ├── samples/                 # safe sample emails for development/testing
│   ├── scripts/                 # dataset, training and maintenance scripts
│   ├── tests/                   # backend and security-focused tests
│   └── requirements.txt
├── frontend/                    # React + TypeScript + Vite dashboard
├── ml/
│   ├── datasets/                # small controlled fixtures; large/raw data ignored
│   ├── inference/               # inference helpers
│   └── training/                # training and evaluation pipeline
├── docs/                        # architecture and project documentation
├── .gitignore
├── LICENSE
└── README.md
```

## Technology stack

**Backend:** Python, FastAPI, Pydantic, SQLAlchemy, Alembic, PostgreSQL-compatible storage.

**Frontend:** React, TypeScript, Vite and Tailwind CSS.

**ML:** scikit-learn TF-IDF + Logistic Regression; optional BERT/DistilBERT training tooling is kept separate from the main lightweight inference path.

**Security / intelligence:** SPF/DKIM/DMARC analysis, DNS/WHOIS-style enrichment, URL/domain analysis, IOC processing, multiple public threat-intelligence integrations, static attachment forensics, evidence correlation and ATT&CK-aligned mapping.

## Machine learning

The primary explainable classifier is a TF-IDF + Logistic Regression pipeline. Training and evaluation code lives under `ml/training/` and the project includes dataset validation, deduplication controls, reproducible seeds and held-out evaluation workflows.

Example:

```bash
python ml/training/train.py \
  --dataset ml/datasets/real/public_email_threats.jsonl \
  --artifact ml/models/email_threat_tfidf_logreg_public.joblib
```

Large datasets and trained model binaries are intentionally excluded from normal Git history. Keep reproducible dataset sources and training instructions documented rather than committing multi-hundred-megabyte artifacts.

### Interpreting ML results

The classifier is not presented as universally accurate. Short, finance-heavy, or unusual legitimate emails can be difficult for text-only classifiers, which is why EmailScanSIH uses multi-signal fusion rather than promoting model probability directly to the final risk decision.

## Threat intelligence

The threat-intelligence layer is designed to normalize results from multiple sources and preserve provider-level outcomes. This supports:

- IOC reputation and enrichment;
- provider confidence and references;
- cache-aware lookups;
- bounded timeouts and retries;
- failure/fallback states;
- provider disagreement and consensus handling;
- SSRF protection for externally resolved targets.

A third-party provider being unavailable should not silently fabricate a safe result.

## Attachment static forensics

Attachments are treated as untrusted input and are inspected **without executing them**. The forensic layer includes checks such as:

- file type and magic-byte identification;
- SHA-256/file fingerprinting;
- entropy analysis;
- ZIP/TAR/GZIP/BZIP archive inspection;
- nested executable and multi-extension indicators;
- Office macro and remote-template indicators;
- PDF action/JavaScript/embedded-file indicators;
- PE and script indicators;
- URL/IP IOC extraction with provenance.

Archive and parsing operations are bounded to reduce resource-exhaustion risk.

## Evidence integrity & investigations

The evidence layer creates deterministic identifiers from canonicalized evidence and records relationships between source artifacts and derived findings.

```text
Email
 ├── Headers / relay hops
 ├── Authentication results
 ├── URLs / domains / IPs
 ├── Attachments
 ├── Threat-intelligence results
 ├── ML findings
 ├── BEC / impersonation findings
 └── Derived investigation intelligence
```

Investigation services can then build timeline events, evidence relationships, attack-path views, related-analysis links and forensic intelligence.

The repository does **not** claim that a local evidence ledger is equivalent to independent legal notarization or an external blockchain-based chain of custody.

## Gmail ingestion

EmailScanSIH includes a read-only Gmail workflow using Google OAuth. The backend can retrieve raw messages for analysis, persist the analysis workflow, and expose processing status through the application API.

Mailbox modification is not required for the core detection workflow.

## Security design

Because email content and extracted indicators are untrusted, the application includes defensive controls around:

- authentication and authorization;
- request and payload validation;
- MIME and archive resource limits;
- SSRF protection;
- safe static attachment inspection;
- secret/environment separation;
- bounded external HTTP operations;
- provider circuit-breaker/fallback behavior;
- stale-job recovery;
- deterministic evidence handling.

For production, use HTTPS, managed secrets, least-privilege database credentials, network segmentation, hardened database configuration, controlled logs, and an explicit retention policy.

## Local development

### Prerequisites

- Python 3.10+
- Node.js 18+
- PostgreSQL 15+ (or compatible PostgreSQL/Supabase deployment)

### 1. Clone

```bash
git clone https://github.com/bgmihacker-ddos/EmailScanSIH.git
cd EmailScanSIH
```

### 2. Backend

```bash
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

Install dependencies:

```bash
pip install -r requirements.txt
```

Create your environment file from `backend/.env.example` and configure the database and optional integrations.

Apply migrations:

```bash
python -m alembic upgrade head
```

Run the API:

```bash
uvicorn app.main:app --reload
```

### 3. Frontend

Open a second terminal from the repository root:

```bash
cd frontend
npm install
npm run dev
```

### Configuration and secrets

Never commit real credentials. Keep values such as these in local environment configuration or your deployment secret manager:

```env
DATABASE_URL=postgresql://<user>:<password>@<host>:5432/<database>
```

Do not commit API keys, OAuth client secrets, JWT signing secrets, service-role keys, database passwords, or private mailbox data.

## Worker operation

For environments using durable analysis jobs, the backend exposes worker/retention entry points in the source tree. A typical lifecycle is:

```text
request → queued → worker claims job → analysis → persistence → evidence → complete
```

A successful HTTP request or `202 Accepted` should not be interpreted as proof that background processing has completed; inspect the persisted job/status result.

## Testing

Run backend tests from the backend environment:

```bash
pytest
```

The test suite includes coverage for API behavior, parsing robustness, authentication, BEC detection, ML classification, threat-intelligence handling, attachment forensics, evidence integrity, investigation correlation and system-level validation.

For security evaluation, combine automated tests with representative benign emails, phishing/BEC variants, malformed messages, adversarial cases, provider failures and resource-exhaustion scenarios.

## Repository hygiene

The repository is intended to contain **source code, reproducible configuration, safe fixtures, tests and useful documentation**.

The following should remain out of Git history unless deliberately required:

- `.env` and other secret-bearing files;
- local databases such as `*.db` / `*.sqlite3`;
- `node_modules/`, Python virtual environments and build output;
- large raw/processed datasets;
- trained ML binaries and model caches;
- temporary analysis exports and logs;
- local agent/tool state.

The `.gitignore` is configured accordingly.

## Project status

The current codebase contains implemented work across email parsing, authentication analysis, URL/domain/IOC analysis, ML classification, BEC/impersonation detection, threat-intelligence enrichment, attachment forensics, evidence correlation, investigation timelines, forensic intelligence, durable analysis jobs, Gmail ingestion, frontend dashboards and security-focused testing.

Capabilities and limitations should be judged from the implementation and test coverage in the repository rather than from a single benchmark number.

## Responsible use

EmailScanSIH is intended for education, research, prototyping and authorized defensive security analysis. Only analyze email data, accounts and infrastructure for which you have appropriate authorization.

Threat-intelligence observations, geolocation signals, automated classifications and forensic findings should be interpreted in context before operational or incident-response decisions.

## License

This project is released under the MIT License. See [`LICENSE`](LICENSE).

## Project goal

> **Turn suspicious emails into explainable, evidence-backed security intelligence.**

Built for **Smart India Hackathon 2026 — SIH26106**.
