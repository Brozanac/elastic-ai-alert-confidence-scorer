# Risk Register

| ID | Risk | Asset | Impact | Likelihood | Current Controls | Risk Level | Treatment |
|---|---|---|---|---|---|---|---|
| R-001 | API key accidentally committed | `.env`, OpenAI key | High | Medium | `.gitignore`, Gitleaks, `.env.example` | Medium | Reduce |
| R-002 | Raw alert data exposed in logs | Backend logs | High | Medium | Safe logging, redaction, no raw alert logging | Medium | Reduce |
| R-003 | Unauthorized access to alert history | Alert history DB | High | Medium | `X-API-Key`, protected endpoints | Medium | Reduce |
| R-004 | Oversized request causes resource exhaustion | Backend API | Medium | Medium | Request size middleware | Medium | Reduce |
| R-005 | Malformed input crashes API | Backend API | Medium | Medium | Pydantic validation, abuse-case tests | Low | Reduce |
| R-006 | Vulnerable Python dependency | Backend | High | Medium | `pip-audit`, GitHub Actions | Medium | Reduce |
| R-007 | Vulnerable frontend dependency | Frontend | Medium | Medium | `npm audit`, GitHub Actions | Medium | Reduce |
| R-008 | LLM failure breaks alert scoring | LLM explanation layer | Medium | Medium | Safe LLM fallback, deterministic scoring remains valid | Low | Reduce |
| R-009 | Secrets exposed in stored history | SQLite DB | High | Medium | Redaction before database save | Medium | Reduce |
| R-010 | Container runs with excessive privileges | Docker backend | Medium | Medium | Non-root Docker user | Low | Reduce |