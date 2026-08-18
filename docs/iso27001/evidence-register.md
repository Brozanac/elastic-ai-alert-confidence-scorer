# Evidence Register

| Evidence ID | Evidence | Location | Related Control |
|---|---|---|---|
| E-001 | Input validation models | backend/schemas.py | A.8.28 |
| E-002 | Request size middleware | backend/request_limits.py | A.8.28 |
| E-003 | Safe error handling | backend/main.py | A.8.28 |
| E-004 | Secret redaction | backend/redaction.py | A.5.34 |
| E-005 | Protected history endpoints | backend/auth.py, backend/main.py | A.5.15 |
| E-006 | Safe frontend rendering | frontend/src/App.jsx | A.8.28 |
| E-007 | History limit validation | backend/main.py | A.8.28 |
| E-008 | Database session handling | backend/database.py | A.8.28 |
| E-009 | `.gitignore` secret exclusion | .gitignore | A.5.17 |
| E-010 | Non-root Docker backend | backend/Dockerfile | A.8.9 |
| E-011 | Security headers | backend/main.py | A.8.28 |
| E-012 | Safe backend logging | backend/app_logging.py, backend/main.py | A.8.15 |
| E-013 | Safe database failure logging | backend/database.py | A.8.15 |
| E-014 | Safe LLM failure logging | backend/llm_explainer.py | A.8.15 |
| E-015 | Dependency scanning | .github/workflows/security.yml | A.8.8 |
| E-016 | Secret scanning | Gitleaks, .github/workflows/security.yml | A.5.17 |
| E-017 | Abuse-case tests | tests/test_abuse_cases.py | A.8.28 |