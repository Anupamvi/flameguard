# Security Policy

## Reporting a Vulnerability

If you find a security issue in FlameGuard, report it privately to the project maintainers instead of opening a public issue with exploit details.

When reporting an issue:

- include a minimal reproduction
- redact secrets and credentials
- redact subscription IDs, workspace customer IDs, tenant names, private URLs, and internal hostnames
- avoid attaching raw production firewall exports unless they are sanitized

## What Not to Post Publicly

Do not include any of the following in issues, pull requests, or discussions:

- API keys or tokens
- real cloud account or subscription identifiers
- Log Analytics workspace customer IDs or tenant IDs from live environments
- tenant-specific endpoints
- live Azure resource IDs, resource group names, or firewall names copied from production
- internal email addresses
- raw configuration exports from live environments

## LLM Data Handling

FlameGuard can send structured firewall rule context to an external model provider. When you modify prompt-building, chat, audit, or generation flows:

- preserve the Azure identifier redaction performed by `backend/app/privacy.py`
- avoid adding raw deployment identifiers or secrets directly into prompts
- keep sample payloads and test fixtures synthetic or sanitized

## Supported Repo Hygiene

This repository is intended to remain safe for public open-source use. If you notice a committed secret or confidential deployment value, rotate the secret first and then remove it from the repository history through the appropriate incident response process.