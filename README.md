# Elastic AI Alert Confidence Scorer

## Project Goal /Overview

This project scores Elastic-style security alerts based on confidence. This repository is used to document the implementation journey of this project.

The goal is to help analysts understand whether an alert has enough supporting evidence, what context is missing, whether false-positive indicators exist, and which MITRE ATT&CK techniques may apply.

## Features

- Elastic-style alert JSON analysis
- Alert-type-aware scoring
- Environment-aware scoring
- Explainable score breakdown
- MITRE ATT&CK mapping
- False-positive notes
- Analyst next steps
- Safe local AI-style explanation
- Optional LLM explanation
- SQLite alert history
- React dashboard
- Docker support

## Architecture

```text
Elastic-style Alert JSON
        ↓
React Dashboard / API
        ↓
FastAPI Backend
        ↓
Alert Type Detection
        ↓
Evidence Extraction
        ↓
Confidence Scoring
        ↓
Environment Context
        ↓
MITRE ATT&CK Mapping
        ↓
AI-Style Explanation
        ↓
SQLite History
        ↓
Analyst Report

```

## Tech Stack
Python
FastAPI
SQLite
SQLAlchemy
React
Vite
Docker
Optional OpenAI API

## Running Locally
### Backend
python -m pip install -r requirements.txt
cd backend
python -m uvicorn main:app --reload

#### Backend docs:

http://127.0.0.1:8000/docs

### Frontend
cd frontend
npm install
npm run dev

#### Frontend:

http://127.0.0.1:5173

## Running with Docker Compose

Create a .env file from .env.example:
```
cp .env.example .env
```

Then run:

```
docker compose up --build
```
Open:
```
http://127.0.0.1:5173
```

## API Endpoints
Method	Endpoint	Description
GET	/	Project status
GET	/health	Health check
GET	/environment-context	Current environment context
POST	/score-alert	Core alert scoring
POST	/score-alert/report	Markdown report output
POST	/score-alert/explain	Local AI-style explanation
POST	/score-alert/llm-explain	Optional real LLM explanation
POST	/score-alert/full	Full analysis and history save
GET	/alerts/history	List saved analyses
GET	/alerts/history/{history_id}	Get one saved analysis
DELETE	/alerts/history/{history_id}	Delete saved analysis

## Sample Alerts

The project includes sample alerts for:

Suspicious PowerShell execution
Failed login brute force
Likely false positive PowerShell activity
Network connection to sensitive port
Suspicious file download
### Example Result
```
{
  "alert_name": "Multiple Failed Logins from External IP",
  "alert_type": "authentication",
  "confidence": {
    "score": 65,
    "level": "Medium"
  },
  "evidence": [
    "Failed authentication activity detected",
    "External source IP observed: 45.155.205.44",
    "Authentication activity targeted a VPN-related host",
    "Affected host is a critical asset: VPN-GATEWAY-01"
  ]
}
```

## Security Design

The LLM does not calculate the score.

The confidence score is produced by deterministic scoring logic. The LLM, when enabled, only explains the existing score, evidence, MITRE mapping, and analyst next steps.

Current Limitations
Uses Elastic-style sample JSON, not direct Elastic API integration yet.
Scoring logic is heuristic.
MITRE mapping is rule-based.
No authentication or user management.
No production deployment hardening.
LLM explanations require an API key.
Future Improvements
Connect directly to Elastic Security Alerts API
Add Elastic Cases integration
Add Attack Discovery validation
Add historical baselining
Add rule tuning recommendations
Add user authentication
Add export-to-PDF report feature
Add unit tests
Add CI/CD pipeline

---

## Safe Coding: Pydantic Input Validation

The API validates incoming alert JSON with Pydantic models before scoring.

This protects the scorer from malformed input while still allowing flexible Elastic/ECS-style fields.

Validated fields include:

- `rule.name`
- `rule.severity`
- `rule.risk_score`
- `host.name`
- `user.name`
- `process.name`
- `process.command_line`
- `event.category`
- `event.action`
- `source.ip`
- `destination.ip`
- `destination.port`
- `file.name`
- `file.path`
- `file.hash.sha256`

Invalid input returns a `422 Unprocessable Entity` response instead of reaching the scoring logic.

## Safe Coding: Request Size Limits

The backend limits incoming request body size before alert JSON reaches the scoring engine.

This helps prevent:

- oversized alert payloads
- unnecessary memory usage
- slow request processing
- accidental storage of huge payloads in SQLite history

Current default:

```text
MAX_REQUEST_BODY_BYTES=1000000
```
## Safe Coding: Secret Redaction Before History Storage

The backend redacts sensitive values before saving alert history to SQLite.

Redacted data includes:

- passwords
- API keys
- bearer tokens
- authorization headers
- client secrets
- private key blocks
- JWT-like tokens

Scoring still uses the original alert data during request processing, but only redacted copies are saved to history.

This reduces the risk of storing sensitive credentials in local history records.

## Safe Coding: Strict CORS

The backend restricts browser access to known frontend origins.

Default local development origins:

```text
http://127.0.0.1:5173
http://localhost:5173
```

## Safe Coding: Structured React Rendering

The frontend avoids rendering backend-generated reports as raw HTML.

Instead of using `dangerouslySetInnerHTML`, the dashboard renders analysis data through structured React components:

- score summary
- score breakdown
- scoring events
- evidence list
- missing context list
- false-positive notes
- MITRE ATT&CK mappings
- analyst next steps
- AI-style explanation
- LLM explanation as plain text

This keeps alert fields treated as untrusted text and helps reduce the risk of accidental cross-site scripting.

## Safe Coding: Parameter Validation for History Limits

The alert history endpoint validates the `limit` query parameter.

```python
limit: int = Query(default=25, ge=1, le=100)
```
## Safe Coding: Improved Database Session Handling

The backend uses a FastAPI database dependency to manage SQLite sessions.

A new database session is created for each request and automatically closed after the request finishes.

```python
def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
```
## Safe Coding: Non-Root Backend Container

The backend Docker image runs the FastAPI application as a non-root user.

The Dockerfile creates a dedicated application user:

```dockerfile
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app

USER appuser
```

## Safe Coding: Security Headers and Safe Logging

The backend adds basic security headers to every response:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

The backend also uses safe logging practices.

Logged events include:

- request start and completion
- alert analysis completion
- history lookup and deletion
- invalid API-key attempts
- database failures
- LLM explanation failures

The application avoids logging:

- raw alert JSON
- full command lines
- API keys
- passwords
- bearer tokens
- authorization headers
- private keys
- raw `.env` values

Detailed backend errors are logged server-side, while API users receive safe generic error messages.

## Security Scanning

Run Python dependency audit:

```bash
python -m pip_audit -r requirements.txt
```

Run Python security linting:

```bash
python -m bandit -r backend
```

Run frontend dependency audit:
```bash
cd frontend
npm audit
```

Run tests:

```bash
python -m pytest -v
```

## Safe Coding: Dependency, Secret, and Abuse-Case Testing

The project includes security checks for dependencies, source code, secrets, and abuse-case behavior.

Local commands:

```bash
python -m pytest -v
python -m pip-audit -r requirements.txt
python -m bandit -r backend
gitleaks detect --source . --verbose
cd frontend && npm audit
```
## ISO/IEC 27001:2022 Alignment

This project is not an ISO/IEC 27001-certified system by itself. ISO/IEC 27001 certification applies to an organization's information security management system.

However, this repository includes an ISO/IEC 27001:2022-aligned security package under:

```text
docs/iso27001/
```
