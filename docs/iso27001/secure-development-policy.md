# Secure Development Policy

## Purpose

This policy defines secure development requirements for the Elastic AI Alert Confidence Scorer project.

## Requirements

All code changes should follow these rules:

1. Validate external input with Pydantic models.
2. Do not expose raw internal exceptions to API users.
3. Do not log raw alert JSON, command lines, passwords, tokens, API keys, or authorization headers.
4. Store secrets only in environment variables.
5. Keep `.env` out of Git.
6. Run abuse-case tests before merging.
7. Run dependency and secret scans before release.
8. Keep LLM output explainable and non-authoritative.
9. Do not allow the LLM to calculate or override the deterministic confidence score.
10. Use safe frontend rendering and avoid `dangerouslySetInnerHTML`.

## Required Checks

Before release:

```bash
python -m pytest -v
python -m pip_audit -r requirements.txt
python -m bandit -r backend
gitleaks detect --source . --verbose
cd frontend && npm audit

```


---

# 6. `docs/iso27001/access-control-policy.md`

```markdown
# Access Control Policy

## Purpose

Protect sensitive alert history and administrative functions.

## Controls

- Alert history endpoints require `X-API-Key` when `APP_API_KEY` is configured.
- API keys must be stored in `.env` or deployment secrets.
- API keys must not be committed to Git.
- Failed API key checks return generic unauthorized messages.
- API key values must never be logged.

## Protected Endpoints

- `GET /alerts/history`
- `GET /alerts/history/{history_id}`
- `DELETE /alerts/history/{history_id}`

## Production Improvement

For production use, replace demo API-key authentication with:

- named user accounts
- role-based access control
- audit logs per user
- key rotation
- least-privilege permissions