# ISO/IEC 27001 Scope

## Project

Elastic AI Alert Confidence Scorer

## Scope Statement

This ISO/IEC 27001-aligned security package applies to the design, development, testing, and maintenance of the Elastic AI Alert Confidence Scorer project.

The project includes:

- FastAPI backend
- React frontend
- SQLite alert history storage
- Optional OpenAI-based explanation layer
- Docker deployment files
- GitHub repository and CI/CD security checks

## Security Objectives

The project aims to protect:

- confidentiality of alert data
- integrity of scoring logic
- availability of the backend API
- confidentiality of API keys and environment secrets
- integrity of audit logs and alert history

## Out of Scope

The following are outside the project-level scope:

- employee HR processes
- physical office security
- enterprise-wide certification
- production cloud hosting controls not implemented in this repository
- formal third-party ISO certification audit