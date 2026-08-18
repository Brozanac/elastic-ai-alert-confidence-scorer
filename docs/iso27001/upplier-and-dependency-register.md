# Supplier and Dependency Register

| Supplier / Dependency | Purpose | Risk | Control |
|---|---|---|---|
| OpenAI API | Optional LLM explanation | API outage, provider error, data exposure | Optional use, safe fallback, no scoring authority |
| FastAPI | Backend framework | Dependency vulnerability | pip-audit |
| SQLAlchemy | Database ORM | Dependency vulnerability | pip-audit |
| Uvicorn | ASGI server | Dependency vulnerability | pip-audit |
| React | Frontend UI | Dependency vulnerability | npm audit |
| Vite | Frontend tooling | Dependency vulnerability | npm audit |
| Docker base images | Container runtime | Image vulnerabilities | Minimal image, non-root user |
| GitHub Actions | CI security checks | CI failure, supply chain risk | Pin trusted actions, review workflow changes |