# FlameGuard

FlameGuard is an open-source network security configuration and log audit tool with LLM-assisted analysis, explanation, and remediation support.

It ingests security configuration exports and log bundles, including Azure NSG, Azure Firewall, Azure WAF, and Microsoft Entra Global Secure Access inputs, normalizes vendor-specific data into a common model, runs audit and compliance checks, and exposes the results through a FastAPI backend and Next.js frontend.

## Open Source

FlameGuard is released under the MIT license. This repository is intended to be safe for public distribution:

- No live cloud secrets should be committed.
- No real subscription IDs, workspace customer IDs, tenant-specific hostnames, or private deployment values should be committed.
- Sample exports and deployment manifests in the repo should be sanitized before merging.

See [LICENSE](LICENSE), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).

## Features

- Multi-vendor parsing for Azure NSG, Azure Firewall configuration exports, Azure Firewall log exports, Azure WAF-style inputs, and Global Secure Access audit, deployment, and traffic log exports
- Deterministic rule checks for internet exposure, risky wildcard access, insecure protocols, wide CIDRs, wide port ranges, and shadowed rules
- Compliance checks for common frameworks alongside rule-level findings
- LLM-assisted audit findings for overly permissive rules, shadowing, contradictions, and best-practice gaps
- Natural-language rule explanation and policy chat
- Rule generation from intent
- Demo data seeding for local walkthroughs and UI smoke testing
- Risk visualization across parsed rules

## Architecture

- Backend: Python 3.12, FastAPI, SQLAlchemy, Alembic
- Frontend: Next.js, TypeScript, Tailwind CSS
- LLM providers: OpenAI-compatible APIs, including OpenAI and Azure AI Foundry
- Storage: SQLite by default; durable database backends can be added for production deployments

## Quick Start

### Local with Docker Compose

```bash
git clone https://github.com/your-org/flameguard.git
cd flameguard
cp .env.example .env
# Edit .env with either OPENAI_API_KEY or AZURE_* settings
docker compose up --build
```

- Backend API: http://localhost:8000/docs
- Frontend UI: http://localhost:3000

### Local Development

Backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Optional demo seed after the backend is running:

```bash
curl -X POST http://localhost:8000/api/v1/seed-demo
```

This seeds a realistic demo audit so the dashboard, audit detail page, and chat flow have data immediately.

## Configuration

Core settings are documented in [.env.example](.env.example).

- `LLM_PROVIDER`: `openai` or `azure`
- `OPENAI_API_KEY`: required when using direct OpenAI
- `AZURE_ENDPOINT`, `AZURE_API_KEY`, `AZURE_API_VERSION`: required when using Azure AI Foundry
- `LLM_MODEL`: model or deployment name
- `FLAMEGUARD_DB_PATH`: database file path
- `CORS_ORIGINS`: JSON array of allowed frontend origins
- `UPLOAD_MAX_SIZE_MB`: maximum JSON upload size accepted by the API
- `NEXT_PUBLIC_SITE_URL`: optional public site base URL for frontend metadata and shared links; set this to the Azure Front Door or custom domain URL in public deployments
- `RATE_LIMIT_ENABLED`, `*_RATE_LIMIT_REQUESTS`, `*_RATE_LIMIT_WINDOW_SECONDS`: public API throttling controls
- `TRUST_PROXY_HEADERS`, `TRUSTED_PROXY_CIDRS`: only trust forwarded client IP headers from known proxy networks
- `FRONT_DOOR_ORIGIN_TOKEN`: optional shared secret for Azure Front Door to prove a request came through the intended edge path before proxy headers are trusted
- `MAX_CONCURRENT_AUDIT_JOBS`: per-instance cap for concurrent background audit runs
- `ADMIN_API_TOKEN`: optional token required for protected delete and demo-seed routes

Never commit populated `.env` files or real secret values.

## Deployment

Sanitized deployment guidance is available in [docs/flameguard-deployment-guide.md](docs/flameguard-deployment-guide.md).

Tracked Container Apps manifests in this repository are examples only. Copy them to local override files or inject secrets through your deployment system instead of storing real values in git.

For the current public deployment model, use Azure Front Door as the public entrypoint and point the frontend at the Front Door API path rather than the backend Container App hostname directly. The accepted hardened state in this repo is Front Door routing plus the app-layer rate limits, audit-job caps, admin-token protection, and response hardening already implemented in the codebase.

If you publish share links, metadata previews, or URL shorteners for the app, point them at the Azure Front Door hostname or a custom domain bound to Front Door. Direct Container App hostnames now return `403 RBAC: access denied` by design.

If you keep Container Apps ingress `external: true`, use Container Apps IP security restrictions to allow only the current `AzureFrontDoor.Backend` IPv4 ranges and refresh that allowlist as the service tag changes. The deployment guide documents this flow and the repo now includes [scripts/sync-containerapp-ip-restrictions-to-afd.ps1](scripts/sync-containerapp-ip-restrictions-to-afd.ps1) to automate it.

As of 2026-04-07, the Standard Azure Front Door configuration used here does not have an attached AFD security policy. Managed/custom WAF policy creation is blocked in this environment by CDN WAF retirement errors, so additional edge WAF coverage requires a different supported Azure path or SKU.

## Sample Data

Public sample fixtures belong under backend/tests/fixtures or backend/tests/conftest.py and must stay synthetic or sanitized.

The azure-exports/ folder is local ignored scratch space for temporary export analysis only. Do not commit raw exports from live environments.

## Global Secure Access Inputs

FlameGuard now accepts Microsoft Entra Global Secure Access log exports in addition to the existing Azure network controls.

- Audit logs: filter Microsoft Entra audit logs to the `Global Secure Access` service, then export the results for upload.
- Deployment logs: export the `Global Secure Access > Monitor > Deployment logs` view.
- Traffic logs: export `NetworkAccessTrafficLogs` through Microsoft Entra diagnostic settings to a supported destination, then upload the resulting JSON or CSV-style export.

Microsoft Learn currently documents these paths in the `Global Secure Access logs and monitoring`, `How to access the Global Secure Access audit logs`, `How to use the Global Secure Access traffic logs`, and `How to use the Global Secure Access deployment logs` articles.

## Data Handling

When LLM features are enabled, FlameGuard sends structured rule context to the configured model provider. Azure subscription IDs, resource group names, tenant identifiers, and ARM path segments are sanitized before that payload is built, but you should still review provider retention policies and deployment settings before using the tool with sensitive configurations.

## Verification

Backend:

```bash
cd backend
python -m pytest tests/ -q
```

Frontend:

```bash
cd frontend
npm run build
```

Frontend smoke:

```bash
cd frontend
npm run test:smoke
```

GitHub Actions runs the backend pytest suite and the frontend smoke test on pushes and pull requests.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
