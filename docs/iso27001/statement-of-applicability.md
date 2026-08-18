# Statement of Applicability

This Statement of Applicability maps selected ISO/IEC 27001:2022 Annex A controls to this project.

| Control | Name | Applicable | Implementation |
|---|---|---:|---|
| A.5.1 | Policies for information security | Yes | Secure development, access control, logging, and vulnerability management documents are maintained under docs/iso27001/. |
| A.5.8 | Information security in project management | Yes | Security requirements are tracked as project tasks and tested through abuse-case tests. |
| A.5.9 | Inventory of information and associated assets | Yes | Asset inventory is documented in asset-inventory.md. |
| A.5.15 | Access control | Yes | Alert history endpoints require an API key when APP_API_KEY is configured. |
| A.5.16 | Identity management | Partially | Project uses API-key based access for local demo. Production should use named users and roles. |
| A.5.17 | Authentication information | Yes | Secrets are stored in environment variables and excluded from Git. |
| A.5.23 | Information security for use of cloud services | Partially | OpenAI API usage is optional, fails safely, and does not determine the score. |
| A.5.24 | Incident management planning and preparation | Yes | Incident response procedure is documented. |
| A.5.25 | Assessment and decision on information security events | Yes | Alert scoring logic assesses security events and produces confidence levels. |
| A.5.26 | Response to information security incidents | Yes | Analyst next steps are generated for investigated alerts. |
| A.5.28 | Collection of evidence | Yes | Alert evidence, scoring events, and history records are stored. |
| A.5.31 | Legal, statutory, regulatory, and contractual requirements | Partially | No real customer data should be used unless legal/privacy requirements are reviewed. |
| A.5.34 | Privacy and protection of personal information | Yes | Secret redaction is applied before database storage. |
| A.5.37 | Documented operating procedures | Yes | Local run, scanning, testing, and incident procedures are documented. |
| A.8.8 | Management of technical vulnerabilities | Yes | pip-audit, Bandit, npm audit, and Gitleaks are used. |
| A.8.9 | Configuration management | Yes | Environment variables and `.env.example` define configurable settings. |
| A.8.15 | Logging | Yes | Safe backend logging is implemented without raw alert or secret exposure. |
| A.8.16 | Monitoring activities | Partially | Backend logs security-relevant events. Production should centralize logs. |
| A.8.24 | Use of cryptography | Partially | HTTPS/TLS should be enforced in production deployment. |
| A.8.25 | Secure development life cycle | Yes | Security testing, scanning, validation, and documentation are part of development. |
| A.8.27 | Secure system architecture and engineering principles | Yes | Deterministic scoring is separated from optional LLM explanation. |
| A.8.28 | Secure coding | Yes | Input validation, safe error handling, safe logging, redaction, and abuse-case tests are implemented. |