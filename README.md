# Email Threat Detection & Intelligence Platform

> **SIH 2026 — AI-Powered Email Security Analysis**

Email Threat Detection is a production-oriented security platform for analyzing raw emails and turning multiple independent security signals into an explainable threat assessment.

It is designed to detect phishing, spam, Business Email Compromise (BEC), credential harvesting, malware indicators, sender spoofing, brand impersonation, suspicious URLs/domains, and authentication failures — while preserving evidence and supporting campaign-level correlation.

## Why this project?

Modern phishing attacks rarely rely on a single clue. A malicious email may contain convincing language, pass some authentication checks, use a lookalike domain, redirect through suspicious infrastructure, or resemble other messages from the same campaign.

This project therefore follows a **multi-signal threat-fusion approach** rather than treating a single ML prediction as the final answer.

```text
                         ┌──────────────────────┐
                         │      Raw .eml        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                       ┌────────────────────────┐
                       │   Email Ingestion      │
                       │   + Parsing            │
                       └───────────┬────────────┘
                                   │
            ┌──────────────────────┼───────────────────────┐
            │                      │                       │
            ▼                      ▼                       ▼
    ┌───────────────┐     ┌────────────────┐      ┌────────────────┐
    │ Header/Auth   │     │ URL / Domain   │      │ Content / NLP  │
    │ SPF/DKIM/DMARC│     │ + IOC Analysis │      │ + ML Detection │
    └───────┬───────┘     └───────┬────────┘      └───────┬────────┘
            │                     │                       │
            └─────────────────────┼───────────────────────┘
                                  │
                         ┌────────▼─────────┐
                         │ Threat Intelligence│
                         │ VT / URLhaus /   │
                         │ AbuseIPDB         │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │ Threat Fusion +  │
                         │ Risk Scoring      │
                         └────────┬─────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
             ┌──────────┐  ┌───────────┐  ┌──────────────┐
             │ Explain- │  │ Evidence  │  │ Campaign /   │
             │ able AI  │  │ Provenance│  │ IOC Graph    │
             └────┬─────┘  └─────┬─────┘  └──────┬───────┘
                  └──────────────┼───────────────┘
                                 ▼
                       ┌────────────────────┐
                       │ Security Dashboard │
                       └────────────────────┘
```

## Key capabilities

| Capability | What it does |
|---|---|
| **Email Parsing** | Extracts and structures headers, body, attachments, URLs, and message metadata. |
| **Header Analysis** | Examines sender information, routing data, and suspicious header patterns. |
| **SPF / DKIM / DMARC** | Verifies available email authentication signals. |
| **URL & Domain Analysis** | Identifies suspicious URLs, domains, redirects, and domain characteristics. |
| **NLP Content Analysis** | Detects phishing and social-engineering language patterns. |
| **Rule-Based Detection** | Applies deterministic security rules for known indicators and behaviors. |
| **Machine Learning** | Uses an explainable TF-IDF + logistic-regression classifier trained offline. |
| **Threat Intelligence** | Integrates external intelligence providers such as VirusTotal, URLhaus, and AbuseIPDB. |
| **Threat Fusion** | Combines independent signals into a unified assessment. |
| **Risk Scoring** | Produces a quantified threat severity score. |
| **Explainable AI** | Provides human-readable reasons behind detections. |
| **IOC Extraction** | Extracts indicators such as IPs, domains, URLs, hashes, and related artifacts. |
| **BEC Detection** | Looks for patterns associated with Business Email Compromise. |
| **Brand Impersonation** | Detects typosquatting and homoglyph-style lookalike domains. |
| **Security Dashboard** | Visualizes findings, scores, evidence, and analysis state. |
| **Durable Analysis Jobs** | Supports queued work, cancellation, bounded retries, and stale-job recovery. |
| **Evidence Provenance** | Maintains a reproducible evidence ledger, message integrity hash, and export masking. |
| **Campaign Correlation** | Indexes IOC candidates to connect related URLs, domains, IPs, and attachment hashes. |

## Tech stack

| Layer | Technology |
|---|---|
| **Frontend** | React, TypeScript, Vite, Tailwind CSS |
| **Backend** | Python, FastAPI, Pydantic, SQLAlchemy |
| **Database** | PostgreSQL / Supabase |
| **ML** | scikit-learn, pandas, numpy, joblib |
| **Testing** | pytest |
| **Visualization** | Dashboard-based threat analytics and investigation views |

## Project structure

```text
email-threat-detection/
├── frontend/                    # React + TypeScript frontend
├── backend/                     # FastAPI backend and services
├── ml/                          # Training, datasets, and ML artifacts
├── samples/                     # Test / fixture email samples
├── docs/                        # Architecture and project documentation
├── scripts/                     # Development and maintenance utilities
├── .gitignore
├── README.md
└── LICENSE
```

## Getting started

### Prerequisites

- **Node.js 18+**
- **Python 3.10+**
- **PostgreSQL 15+** (or a Supabase PostgreSQL database)

### 1. Clone the repository

```bash
git clone https://github.com/bgmihacker-ddos/email-threat-detection.git
cd email-threat-detection
```

### 2. Backend setup

```bash
cd backend
python -m venv .venv
```

Activate the environment.

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
source .venv/bin/activate
```

Install the backend dependencies used by the project, then run migrations:

```bash
pip install -r requirements.txt
python -m alembic upgrade head
```

Start the API in development mode:

```bash
uvicorn app.main:app --reload
```

### 3. Frontend setup

From the repository root:

```bash
cd frontend
npm install
npm run dev
```

### 4. Supabase / PostgreSQL configuration

The backend reads the database connection from the environment. A Supabase PostgreSQL connection string can be supplied directly.

```env
DATABASE_URL=postgresql://postgres:<PASSWORD>@db.<PROJECT_REF>.supabase.co:5432/postgres
```

Alternatively:

```env
SUPABASE_DATABASE_URL=postgresql://postgres:<PASSWORD>@db.<PROJECT_REF>.supabase.co:5432/postgres
```

Optional Supabase client configuration:

```env
SUPABASE_URL=https://<PROJECT_REF>.supabase.co
SUPABASE_ANON_KEY=<anon-key>
SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
```

For local development, the project can continue using SQLite when the database URL is not overridden.

> **Never commit API keys, service-role keys, OAuth secrets, passwords, or other credentials to Git.**

## Machine-learning model

The current public-data training workflow uses the project training script and a JSONL dataset:

```powershell
python ml/training/train.py --dataset ml/datasets/real/public_email_threats.jsonl --artifact ml/models/email_threat_tfidf_logreg_public.joblib
```

The analysis engine prefers the public artifact when present and can fall back to the controlled artifact. External provider failures remain informational and should not silently reduce the calculated risk.

## Production-style operation

For production-style operation, the backend supports durable analysis workers and retention jobs.

Run the analysis worker:

```bash
python -m app.services.analysis_worker --loop
```

Run the retention process:

```bash
python -m app.services.retention
```

The worker supports bounded retries through `ANALYSIS_MAX_ATTEMPTS` and stale-lock recovery through `ANALYSIS_STALE_MINUTES`.

## Development workflow

A typical investigation looks like this:

```text
Email received
     ↓
Parse message + attachments
     ↓
Extract headers / URLs / domains / IOCs
     ↓
Authenticate sender (SPF/DKIM/DMARC)
     ↓
Run deterministic rules + NLP/ML analysis
     ↓
Query threat-intelligence sources
     ↓
Detect BEC / impersonation / suspicious infrastructure
     ↓
Fuse signals into risk score
     ↓
Generate explainable verdict
     ↓
Store evidence + integrity metadata
     ↓
Correlate with related messages / campaigns
     ↓
Display results in the dashboard
```

## Detection philosophy

The platform intentionally combines **deterministic evidence** and **probabilistic signals**.

Authentication failures, known malicious indicators, suspicious domains, and other concrete findings can provide strong evidence. NLP and ML add behavioral/contextual signals, but their predictions should be interpreted alongside the underlying evidence.

This makes the system more useful for security analysts because a verdict can be traced back to **why** the email was classified as risky.

## Development phases

1. ✅ **Foundation** — Project structure and configuration
2. 🔄 **Basic Email Pipeline** — Upload, parse, and display
3. 🔄 **Security Analysis** — Headers, authentication, URLs, and content
4. 🔄 **Detection Engine** — Rules, scoring, and classification
5. 🔄 **Machine Learning** — Training and inference
6. 🔄 **Threat Intelligence** — External API integrations
7. 🔄 **Advanced Intelligence** — Fusion, BEC, impersonation, and explainability
8. 🔄 **Production Operations** — Durable workers, migrations, fixture validation, and deployment adapters

## Testing

Run the backend test suite from the appropriate project environment:

```bash
pytest
```

Before opening a pull request, verify both the API and frontend locally and test representative email fixtures from `samples/`.

## Security considerations

This is a defensive security project. Treat input emails and extracted indicators as untrusted data.

Avoid exposing secrets in source control, logs, screenshots, API responses, or exported reports. Production deployments should additionally apply authentication, authorization, rate limits, secret management, network controls, and appropriate data-retention policies.

## Roadmap

Planned areas for expansion include:

- Live Gmail / Outlook integrations
- Broader attachment and malware analysis
- More advanced campaign clustering
- Analyst case management
- Richer IOC and threat-intelligence enrichment
- Model evaluation dashboards and drift monitoring
- Production observability and alerting
- Scalable asynchronous processing for large mail volumes

## Contributing

1. Create a feature branch from `main`.
2. Keep changes focused and reviewable.
3. Preserve stable API/module contracts unless the change is coordinated.
4. Add or update tests for meaningful behavior changes.
5. Update documentation when configuration, commands, or architecture changes.
6. Do not commit credentials or sensitive email data.

## License

MIT License — see [`LICENSE`](LICENSE) for details.

## Disclaimer

This project is intended for **research, education, prototyping, and defensive security analysis**. Automated threat assessments are decision-support signals and should be reviewed with the underlying evidence before operational or incident-response action is taken.
