# FlameGuard

FlameGuard is an open-source firewall and network policy audit tool with LLM-assisted analysis, explanation, and remediation support.

It ingests firewall exports, NSG exports, and Azure Firewall log-export bundles, normalizes vendor-specific rules into a common model, runs audit and compliance checks, and exposes the results through a FastAPI backend and Next.js frontend.

## Open Source

FlameGuard is released under the MIT license. This repository is intended to be safe for public distribution:

- No live cloud secrets should be committed.
- No real subscription IDs, workspace customer IDs, tenant-specific hostnames, or private deployment values should be committed.
- Sample exports and deployment manifests in the repo should be sanitized before merging.

See [LICENSE](LICENSE), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).

## Features

- Multi-vendor parsing for Azure NSG, Azure Firewall configuration exports, Azure Firewall log exports, and Azure WAF-style inputs
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

Never commit populated `.env` files or real secret values.

## Deployment

Sanitized deployment guidance is available in [docs/flameguard-deployment-guide.md](docs/flameguard-deployment-guide.md).

Tracked Container Apps manifests in this repository are examples only. Copy them to local override files or inject secrets through your deployment system instead of storing real values in git.

## Sample Data

Public sample fixtures belong under backend/tests/fixtures or backend/tests/conftest.py and must stay synthetic or sanitized.

The azure-exports/ folder is local ignored scratch space for temporary export analysis only. Do not commit raw exports from live environments.

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

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
