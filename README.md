# FlameGuard

LLM-powered firewall rule auditor and policy generator.

FlameGuard ingests firewall configurations from Azure services (Firewall, NSG, WAF), uses Claude to audit rules for misconfigurations, explains findings in natural language, and generates new rules from plain English intent.

## Features

- **Multi-vendor parsing** — Azure Firewall, Azure NSG, Azure WAF (more coming)
- **LLM-powered audit** — Detects shadowed rules, overly permissive access, contradictions, and best practice violations
- **Compliance mapping** — CIS Azure Foundations Benchmark, PCI-DSS 4.0
- **Natural language explanations** — Understand any rule in plain English
- **Rule generation** — Describe what you want, get vendor-specific config
- **Policy chat** — Ask questions about your firewall policy
- **Risk heatmap** — Visual risk scoring across your entire ruleset

## Architecture

- **Backend:** Python 3.12 + FastAPI
- **Frontend:** Next.js 14 + TypeScript + Tailwind CSS
- **LLM:** Claude API (Anthropic)
- **Storage:** SQLite (portable to PostgreSQL)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/your-org/flameguard.git
cd flameguard

# Copy environment config
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Start with Docker Compose
docker-compose up

# Backend: http://localhost:8000/docs
# Frontend: http://localhost:3000
```

## Development

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Data Privacy

FlameGuard sends **normalized rule data** (not raw JSON configs) to the Claude API for analysis. Anthropic's API does not use customer data for model training. Raw firewall configurations are stored locally in SQLite and are never transmitted externally.

For deployments requiring data residency, a future release will support Azure OpenAI as an alternative LLM backend.

## License

MIT
