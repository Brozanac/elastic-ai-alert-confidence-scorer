# Asset Inventory

| Asset | Type | Owner | Location | Classification | Protection Requirement |
|---|---|---|---|---|---|
| Backend API | Software | Project maintainer | backend/ | Internal | Secure coding, dependency scanning, logging |
| Frontend UI | Software | Project maintainer | frontend/ | Internal | Safe rendering, dependency scanning |
| Alert history database | Data | Project maintainer | backend/alert_history.db | Confidential | Redaction, access control, backup |
| `.env` file | Secret | Project maintainer | local only | Secret | Never committed, rotate if exposed |
| OpenAI API key | Secret | Project maintainer | environment variable | Secret | Never logged, never committed |
| APP_API_KEY | Secret | Project maintainer | environment variable | Secret | Required for history access |
| GitHub repository | Code repository | Project maintainer | GitHub | Internal/Public | Branch protection, scanning, reviews |
| Docker images | Runtime artifact | Project maintainer | local/GitHub | Internal | Non-root user, minimal base image |
| Security test suite | Evidence | Project maintainer | tests/ | Internal | Required before release |