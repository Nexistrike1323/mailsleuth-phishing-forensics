# MailSleuth

**Phishing Email Forensics & Evidence-Based Threat Assessment**

MailSleuth is a local-first email security investigation platform designed to inspect `.eml` files, identify suspicious indicators, preserve evidence, and produce structured threat assessments.

## Features

- **Email parsing:** Extracts sender, recipients, subject, Reply-To, Return-Path, timestamps, message IDs, and relevant headers.
- **Sender analysis:** Identifies inconsistencies between sender identity and reply paths.
- **Authentication analysis:** Parses SPF, DKIM, and DMARC results from supplied Authentication-Results headers.
- **URL analysis:** Detects suspicious URL characteristics, including IP-based hosts, punycode, URL shorteners, and unusual schemes.
- **Attachment analysis:** Calculates SHA-256 hashes and checks file signatures, MIME mismatches, and risky extensions without executing attachments.
- **Evidence-based assessment:** Generates findings, severity levels, and a deterministic risk score.
- **Case management:** Stores investigation records in SQLite.
- **Reports:** Exports JSON and Markdown investigation reports.
- **Dashboard:** React, TypeScript, and Vite interface backed by FastAPI.
- **Local processing:** Email analysis runs locally; no cloud upload or external reputation lookup is required.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Frontend | React, TypeScript, Vite |
| Database | SQLite |
| Analysis | Python email parser, static heuristics, SHA-256 |
| Testing | Pytest |
| API server | Uvicorn |

## Project Structure

```text
MailSleuth/
├── src/mailsleuth/
│   ├── analyzers/
│   ├── core/
│   ├── reporting/
│   ├── storage/
│   └── api.py
├── frontend/
├── tests/
├── rules/
├── samples/
├── reports/
├── pyproject.toml
├── setup_dashboard.sh
├── start_mailsleuth.sh
└── stop_mailsleuth.sh
```

## Requirements

- Python 3.12 or newer
- Node.js and npm
- Linux, WSL2, or another compatible development environment

## Installation

Clone the repository:

```bash
git clone https://github.com/Nexistrike1323/mailsleuth-phishing-forensics.git
cd mailsleuth-phishing-forensics
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python package and API dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install fastapi "uvicorn[standard]" python-multipart
```

Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

## Run the Dashboard

Start both services:

```bash
./start_mailsleuth.sh
```

Open:

- Dashboard: http://127.0.0.1:5173
- API documentation: http://127.0.0.1:8000/docs
- Health endpoint: http://127.0.0.1:8000/api/health

Stop both services:

```bash
./stop_mailsleuth.sh
```

## CLI Usage

Analyze an email:

```bash
mailsleuth analyze samples/example.eml
```

List investigation cases:

```bash
mailsleuth list
```

View a case:

```bash
mailsleuth show CASE_ID
```

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | API health |
| POST | `/api/analyze` | Analyze an uploaded EML file |
| GET | `/api/cases` | List investigation cases |
| GET | `/api/cases/{case_id}` | Retrieve case details |
| GET | `/api/reports/{case_id}/json` | Download JSON report |
| GET | `/api/reports/{case_id}/markdown` | Download Markdown report |

## Testing

Run the test suite:

```bash
python -m pytest -q
```

Compile Python modules:

```bash
python -m compileall -q src tests
```

Build the frontend:

```bash
cd frontend
npm run build
```

## Security and Scope

- Attachments are inspected statically and are not executed.
- URLs are analyzed using local heuristics; this does not establish whether a website is currently malicious.
- SPF, DKIM, and DMARC results are parsed from the supplied email headers. They are not independently verified by MailSleuth.
- Risk scores are deterministic triage scores, not probabilities or guarantees of maliciousness.
- The current implementation is a local investigation MVP, not a production email gateway or a replacement for a full SOC workflow.
- The API is intended for local use. Do not expose it publicly without adding authentication, authorization, and deployment hardening.

## License

No open-source license has been assigned yet. All rights reserved unless a license is added by the repository owner.
