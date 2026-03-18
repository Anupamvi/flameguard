# FlameGuard — LLM-Powered Firewall Rule Auditor & Policy Generator

## Part 1: What Was Built

### Overview

FlameGuard is an open-source, full-stack application that ingests firewall configurations from Azure services, uses Claude AI to audit rules for misconfigurations, explains findings in natural language, and generates new rules from plain English intent.

**Problem:** Enterprise firewall rule management exceeds human cognitive capacity (17K+ rules common). Existing tools (Batfish, 360-FAAR) have no AI layer. FlameGuard fills this gap as an open-source, multi-vendor, LLM-powered auditor.

**Repository:** https://github.com/Anupamvi/flameguard

---

### Architecture

```
                      +-------------------+
                      |   Next.js 15 UI   |  (TypeScript, Tailwind, shadcn/ui)
                      |   Port 3000       |
                      +--------+----------+
                               |
                          REST / SSE
                               |
                      +--------v----------+
                      |  FastAPI Backend   |  (Python 3.12, SQLAlchemy, Alembic)
                      |  Port 8000        |
                      +---+------+--------+
                          |      |
                +---------+      +----------+
                |                           |
        +-------v--------+         +-------v--------+
        |  SQLite (local) |         |  Claude API    |
        |  6 tables       |         |  (Anthropic)   |
        +-----------------+         +----------------+
```

**Stack:**
| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 (App Router), TypeScript, Tailwind CSS, shadcn/ui, TanStack React Query, Recharts |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 + aiosqlite, Alembic, Anthropic SDK |
| Database | SQLite (file-based, portable to PostgreSQL) |
| LLM | Claude API (Anthropic) |
| Deploy | Docker Compose (local) / Azure Container Apps (cloud) |

---

### Supported Firewall Vendors (Phase 1)

| Vendor | Parser | What It Parses |
|--------|--------|---------------|
| **Azure NSG** | `AzureNSGParser` | Security rules from ARM templates and direct NSG exports. Handles singular/plural address prefix coalescing. |
| **Azure Firewall** | `AzureFirewallParser` | Modern policy format (`firewallPolicies/ruleCollectionGroups`) and classic format (`azureFirewalls`). Parses NetworkRule, ApplicationRule, NatRule types. |
| **Azure WAF** | `AzureWAFParser` | App Gateway and Front Door WAF custom rules. Extracts matchConditions, rate limit metadata. |

All parsers normalize rules into a **vendor-agnostic `NormalizedRule` format** with fields: action, direction, protocol, source/destination addresses and ports, priority, collection hierarchy, tags.

**Adding a new vendor = 1 file, 3 methods, 1 `@ParserRegistry.register` decorator. Zero changes elsewhere.**

---

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/upload` | Upload firewall config JSON, auto-detect vendor, parse rules, trigger async LLM audit |
| `GET` | `/api/v1/audit/{id}` | Get full audit report with findings, severity counts |
| `GET` | `/api/v1/audits` | Paginated audit history |
| `GET` | `/api/v1/rulesets/{id}/rules` | List parsed rules for a ruleset |
| `GET` | `/api/v1/rules/{id}/explain` | AI-generated plain-English rule explanation |
| `GET` | `/api/v1/audit/{id}/compliance` | CIS Azure + PCI-DSS compliance check results |
| `POST` | `/api/v1/generate` | Generate vendor-specific firewall rule from natural language intent |
| `POST` | `/api/v1/audit/{id}/chat` | SSE streaming chat about audit findings |

Interactive API docs available at `/docs` (Swagger UI).

---

### LLM Audit Pipeline

When a firewall config is uploaded, FlameGuard runs this pipeline in the background:

```
Upload JSON
    |
    v
auto_detect_vendor() --> Parser.parse() --> NormalizedRules --> DB
                                                                 |
                                                                 v
AuditPipeline.run(ruleset_id):
  1. Load rules from DB
  2. RuleSetChunker.chunk() --> chunks of ~50 rules, 5-rule overlap
  3. Per chunk: build prompt --> Claude API --> parse JSON findings
  4. Deduplicate findings across chunks
  5. Risk scoring pass (second Claude call with full context)
  6. ComplianceEngine.run() (deterministic, no LLM)
  7. Store AuditReport + Findings + ComplianceChecks
```

**Finding Categories:**
- `shadowed` — Rule made unreachable by higher-priority rule
- `overly_permissive` — Too-broad source/destination/port ranges
- `contradictory` — Conflicting rules exposing services unintentionally
- `unused` — Redundant or never-matched rules
- `best_practice` — Naming, documentation, configuration improvements

**Severity Levels:** CRITICAL > HIGH > MEDIUM > LOW > INFO

---

### Compliance Engine (Deterministic, No LLM)

Programmatic checks against parsed rules — no API calls, no cost, instant results.

**CIS Azure Foundations Benchmark v2.0:**

| Control | Check |
|---------|-------|
| CIS-6.1 | RDP access (port 3389) from Internet is restricted |
| CIS-6.2 | SSH access (port 22) from Internet is restricted |
| CIS-6.3 | No NSG allows unrestricted inbound access |
| CIS-6.4 | UDP from Internet is restricted |
| CIS-6.5 | HTTP/HTTPS management ports restricted |
| CIS-6.6 | Network Watcher enabled (N/A — rule-based only) |
| CIS-6.7 | Outbound traffic to Internet evaluated |
| CIS-6.8 | Explicit deny-all inbound rule exists |

**PCI DSS v4.0 Requirement 1:**

| Control | Check |
|---------|-------|
| PCI-1.2.1 | Restrict inbound with wildcard source and any protocol |
| PCI-1.3.1 | DMZ implementation (threshold: >3 rules from Internet) |
| PCI-1.3.2 | Limit inbound Internet traffic to DMZ only |
| PCI-1.3.4 | No unauthorized outbound to Internet on all ports |
| PCI-1.3.5 | Permit only established connections (N/A — stateful) |
| PCI-1.4.1 | Anti-spoofing measures (N/A — platform level) |

---

### Database Schema (6 Tables)

| Table | Purpose |
|-------|---------|
| `rulesets` | Uploaded configs: id, filename, vendor, raw_json, rule_count, uploaded_at |
| `rules` | Parsed normalized rules with all fields, risk_score, raw_json |
| `audit_reports` | Audit lifecycle: status (pending → parsing → auditing → scoring → completed/failed), severity counts, summary |
| `audit_findings` | Individual findings: severity, category, title, description, recommendation, confidence |
| `compliance_checks` | Framework results: CIS/PCI control checks with pass/fail/not_applicable status |
| `chat_messages` | Conversation history per audit: role (user/assistant), content |

---

### Frontend Pages

| Page | Features |
|------|----------|
| **Dashboard** (`/`) | Stats cards (total audits, critical findings, rules analyzed), recent audits table |
| **Upload** (`/upload`) | Drag-and-drop file dropzone, auto-redirect to audit on success |
| **Audit List** (`/audit`) | Paginated table with vendor, filename, findings count, status |
| **Audit Detail** (`/audit/[id]`) | Tabbed view: Overview, Rules, Findings, Compliance, Risk Heatmap |
| **Generate** (`/generate`) | Natural language intent form, vendor selector, syntax-highlighted JSON output with copy |
| **Chat** (`/chat`) | SSE streaming chat about audit findings |

---

### Test Coverage

- **45 backend tests passing** covering:
  - Parser tests: NSG (10), Firewall (9), WAF (7), Detector (4)
  - Compliance tests: CIS Azure (7), PCI-DSS (6)
  - API integration tests: Upload + query flow (7)
- Tests use real fixture files with intentional misconfigurations

---

### Key Files

```
flameguard/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI app factory, CORS, lifespan
│   │   ├── config.py                  # pydantic-settings (env vars)
│   │   ├── database.py                # SQLite async engine
│   │   ├── models/                    # SQLAlchemy ORM (6 tables)
│   │   ├── schemas/                   # Pydantic request/response schemas
│   │   ├── api/                       # 6 routers (upload, audit, rules, compliance, generate, chat)
│   │   ├── parsers/                   # 3 vendor parsers + auto-detector
│   │   ├── llm/                       # Claude client, pipeline, chunker, prompts
│   │   ├── compliance/                # CIS Azure + PCI-DSS engines
│   │   └── services/                  # audit_service, generate_service
│   └── tests/                         # 45 tests + fixtures
├── frontend/
│   └── src/
│       ├── app/                       # 6 pages (Next.js App Router)
│       ├── components/                # audit, layout, upload, ui components
│       ├── hooks/                     # TanStack Query hooks
│       └── lib/                       # API client, types, utils
├── docker-compose.yml
└── docs/
```

---
---

## Part 2: Step-by-Step Azure VM Deployment

This guide deploys FlameGuard on a single Azure VM using Docker Compose. This is simpler and cheaper than Container Apps for testing/demo purposes.

### Prerequisites

- Azure CLI (`az`) installed and logged in
- An Azure subscription
- An Anthropic API key (see Part 3)

### Step 1: Create the Azure VM

```bash
# Variables — adjust as needed
RESOURCE_GROUP="flameguard-rg"
VM_NAME="flameguard-vm"
LOCATION="eastus"
ADMIN_USER="flameguardadmin"

# Create resource group (skip if exists)
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create VM with Docker pre-installed (Ubuntu 22.04 LTS)
az vm create \
  --resource-group $RESOURCE_GROUP \
  --name $VM_NAME \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --admin-username $ADMIN_USER \
  --generate-ssh-keys \
  --public-ip-sku Standard \
  --output table

# Note the publicIpAddress from the output — you'll need it
```

### Step 2: Open Firewall Ports

```bash
# Open port 8000 (backend API) and 3000 (frontend)
az vm open-port --resource-group $RESOURCE_GROUP --name $VM_NAME --port 8000 --priority 1001
az vm open-port --resource-group $RESOURCE_GROUP --name $VM_NAME --port 3000 --priority 1002

# Optional: Open port 80 if you plan to add nginx reverse proxy later
# az vm open-port --resource-group $RESOURCE_GROUP --name $VM_NAME --port 80 --priority 1003
```

### Step 3: SSH into the VM

```bash
ssh $ADMIN_USER@<PUBLIC_IP>
```

### Step 4: Install Docker & Docker Compose

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to the docker group (avoids needing sudo for docker)
sudo usermod -aG docker $USER

# Install Docker Compose plugin
sudo apt install -y docker-compose-plugin

# Log out and back in for group change to take effect
exit
```

Then SSH back in:
```bash
ssh $ADMIN_USER@<PUBLIC_IP>

# Verify
docker --version
docker compose version
```

### Step 5: Clone the Repository

```bash
git clone https://github.com/Anupamvi/flameguard.git
cd flameguard
```

### Step 6: Configure Environment Variables

```bash
# Create .env file from the example
cp .env.example .env

# Edit with your actual values
nano .env
```

Set the following in `.env`:
```env
# REQUIRED: Your Anthropic API key (see Part 3 for how to get this)
ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here

# Database path (leave as default for Docker)
FLAMEGUARD_DB_PATH=/data/flameguard.db

# CORS: Update with your VM's public IP
CORS_ORIGINS=["http://<PUBLIC_IP>:3000"]

# Claude model to use
CLAUDE_MODEL=claude-sonnet-4-20250514

# Max upload size in MB
UPLOAD_MAX_SIZE_MB=50
```

Save and exit (`Ctrl+X`, `Y`, `Enter` in nano).

### Step 7: Update Frontend API URL

The frontend needs to know the backend URL. Edit `docker-compose.yml`:

```bash
nano docker-compose.yml
```

Change the `NEXT_PUBLIC_API_URL` environment variable under the `frontend` service:
```yaml
  frontend:
    ...
    environment:
      - NEXT_PUBLIC_API_URL=http://<PUBLIC_IP>:8000/api/v1
```

> **Important:** Replace `<PUBLIC_IP>` with your VM's actual public IP address.

### Step 8: Build and Start the Services

```bash
# Build and start both containers in detached mode
docker compose up --build -d

# Watch the logs to verify startup
docker compose logs -f
```

You should see:
```
flameguard-backend  | INFO  [alembic.runtime.migration] Running upgrade -> ab559c318c98, initial schema
flameguard-backend  | INFO:     Uvicorn running on http://0.0.0.0:8000
flameguard-frontend | ▲ Next.js 15.x
flameguard-frontend | - Local: http://localhost:3000
```

### Step 9: Verify the Deployment

From your local machine:

```bash
# Test backend API docs
curl http://<PUBLIC_IP>:8000/docs
# Should return HTML (Swagger UI page)

# Test upload endpoint
curl -X POST http://<PUBLIC_IP>:8000/api/v1/upload \
  -F 'file=@backend/tests/fixtures/azure_nsg_sample.json;type=application/json'
# Should return JSON with ruleset_id, audit_id, status, rule_count

# Test frontend
# Open in browser: http://<PUBLIC_IP>:3000
```

### Step 10: Useful Management Commands

```bash
# View running containers
docker compose ps

# View logs (follow mode)
docker compose logs -f backend
docker compose logs -f frontend

# Restart services
docker compose restart

# Stop services
docker compose down

# Rebuild after code changes
docker compose up --build -d

# Check disk usage
docker system df
```

### Optional: Set Up a Domain + HTTPS (Production)

For production use, add nginx as a reverse proxy with Let's Encrypt SSL:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx

# Configure nginx to proxy ports 3000 and 8000
# Then run: sudo certbot --nginx -d your-domain.com
```

Update `CORS_ORIGINS` and `NEXT_PUBLIC_API_URL` to use your domain.

### Optional: Auto-start on Reboot

```bash
# Enable Docker to start on boot
sudo systemctl enable docker

# Docker Compose services will auto-restart (restart: unless-stopped is in docker-compose.yml)
```

### Cost Estimate

| Resource | Spec | ~Monthly Cost |
|----------|------|---------------|
| Azure VM (Standard_B2s) | 2 vCPU, 4 GB RAM | ~$30/mo |
| Managed Disk (30 GB) | Standard SSD | ~$5/mo |
| Public IP | Static | ~$4/mo |
| **Total infrastructure** | | **~$39/mo** |
| Claude API usage | Per audit (~50 rules) | ~$0.10-0.50/audit |

---
---

## Part 3: Claude API Key Setup

### Option A: Anthropic API Key (Recommended for Production)

This is how FlameGuard is designed to work. The backend calls the Claude API directly.

**How to get an API key:**

1. Go to https://console.anthropic.com/
2. Sign up or log in
3. Navigate to **API Keys** in the left sidebar
4. Click **Create Key**
5. Name it (e.g., "flameguard") and copy the key
6. The key looks like: `sk-ant-api03-xxxxxxxxxxxx`

**How to set it:**

```bash
# In your .env file on the VM:
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# Or if using Azure Container Apps:
az containerapp update --name flameguard-backend --resource-group flameguard-rg \
  --set-env-vars "ANTHROPIC_API_KEY=sk-ant-api03-your-key-here"
```

**Pricing (as of 2025):**
| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|-------|----------------------|------------------------|
| Claude Sonnet 4 | $3.00 | $15.00 |
| Claude Haiku 4.5 | $0.80 | $4.00 |

A typical audit of 50 rules uses ~80K input + ~4K output tokens ≈ $0.10-0.30 per audit.

**To use a cheaper/faster model**, set in `.env`:
```env
CLAUDE_MODEL=claude-haiku-4-5-20251001
```

---

### Option B: Claude Code in VSCode — Will It Work?

**Short answer: No, not directly.**

Claude Code (the VSCode extension) is a development assistant that runs in your IDE. It does NOT expose an API that other applications can call. Here's why it won't work for FlameGuard:

| Feature | Claude Code (VSCode) | Anthropic API |
|---------|---------------------|---------------|
| Purpose | Interactive coding assistant | Programmatic API access |
| Authentication | Claude subscription (Pro/Team) | API key + usage-based billing |
| Access method | VSCode extension UI | HTTP REST API |
| Can other apps call it? | No | Yes |
| Billing | Monthly subscription | Pay-per-token |

**FlameGuard's backend** makes direct HTTP calls to `https://api.anthropic.com/v1/messages` using the Anthropic Python SDK. This requires an API key, not a Claude subscription.

**However, there are workarounds if you don't want to pay for API access:**

#### Workaround 1: Use FlameGuard Without the LLM (Free)

FlameGuard's **upload, parsing, and compliance checks work without any API key**:
- Upload and parse Azure Firewall/NSG/WAF configs
- View all parsed rules in the UI
- Run CIS Azure + PCI-DSS compliance checks (deterministic, no LLM)
- Browse and filter rules

Only these features require the API key:
- LLM audit findings (AI-detected misconfigurations)
- Rule explanations
- Rule generation from natural language
- Chat about findings

To run without LLM features, just leave `ANTHROPIC_API_KEY` empty or set to any placeholder. Uploads will parse successfully; the background audit will fail gracefully with status "failed" but all other features work.

#### Workaround 2: Use a Free/Local LLM (Requires Code Changes)

You could modify `backend/app/llm/client.py` to call a local LLM (e.g., Ollama with Llama 3) or a free-tier API instead of Claude. The client is a single file with two methods (`analyze` and `stream`). The prompts would need adjustment for non-Claude models.

#### Workaround 3: Anthropic API Free Tier

Anthropic offers a **free tier** for new API accounts with limited usage. Check https://console.anthropic.com/ — you may get $5-10 in free credits when you sign up, which is enough for ~50-100 audits.

---

### Security Notes on API Key Management

- **Never commit your API key to git.** The `.env` file is in `.gitignore`.
- **In Azure Container Apps**, use Container Apps secrets (not plain env vars) for production:
  ```bash
  az containerapp update --name flameguard-backend --resource-group flameguard-rg \
    --set-env-vars "ANTHROPIC_API_KEY=secretref:anthropic-key" \
    --secrets "anthropic-key=sk-ant-api03-your-key"
  ```
- **Anthropic's API does not train on customer data** (per their API terms). Normalized rule data (not raw JSON) is sent to the API. Document this for your users.
- **For data-residency-sensitive deployments**, consider Azure OpenAI as an alternative backend (Phase 2 planned).
