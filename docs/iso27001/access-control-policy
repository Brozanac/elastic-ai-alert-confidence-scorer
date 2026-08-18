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