# FlameGuard Deployment Guide

This guide is written for the public open-source repository. It uses placeholders only and intentionally avoids tenant-specific identifiers, secrets, subscription IDs, and internal hostnames.

## Scope

This document covers:

- local development
- generic Azure Container Apps deployment steps
- safe handling of secrets and configuration
- publication rules for an open-source repo

## Deployment Principles

- Treat all manifests in git as sanitized templates.
- Inject secrets at deploy time through secret stores or local override files.
- Do not commit real subscription IDs, resource group names, private endpoints, or API keys.
- Do not commit raw firewall exports from live environments unless they are fully sanitized.
- The frontend emits a per-request CSP nonce; do not overwrite it with a conflicting static CSP at your ingress unless you preserve the nonce-based policy.

## Local Development

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker Desktop or another Docker runtime

### Start Locally

```bash
cp .env.example .env
# Populate either OPENAI_API_KEY or AZURE_* values
docker compose up --build
```

Endpoints:

- Backend: `http://localhost:8000/docs`
- Frontend: `http://localhost:3000`

Optional local verification:

```bash
cd backend
python -m pytest tests/ -q

cd ../frontend
npm run build
```

## Azure Container Apps

Use generic placeholders and substitute your own values locally:

```bash
RESOURCE_GROUP=<resource-group>
LOCATION=<azure-region>
ACR_NAME=<container-registry-name>
ENV_NAME=<container-apps-environment>
BACKEND_APP=<backend-app-name>
FRONTEND_APP=<frontend-app-name>
BACKEND_IMAGE=<registry>.azurecr.io/flameguard-backend:<tag>
FRONTEND_IMAGE=<registry>.azurecr.io/flameguard-frontend:<tag>
```

### Build Images

```bash
az acr build --registry $ACR_NAME --image flameguard-backend:<tag> --file backend/Dockerfile backend/
az acr build --registry $ACR_NAME --image flameguard-frontend:<tag> --file frontend/Dockerfile --build-arg NEXT_PUBLIC_API_URL=https://<front-door-host>/api/v1 frontend/
```

For public builds, also set `NEXT_PUBLIC_SITE_URL=https://<front-door-host>` or your Front Door custom domain so frontend metadata and shared links never fall back to the direct Container App origin.

### Secrets and Environment

For Azure AI Foundry or Azure OpenAI-compatible deployments, use values like these locally:

```bash
LLM_PROVIDER=azure
AZURE_ENDPOINT=https://<your-resource>.services.ai.azure.com
AZURE_API_KEY=<set-via-secret-store>
AZURE_API_VERSION=2024-12-01-preview
LLM_MODEL=<deployment-name>
CORS_ORIGINS=["https://<frontend-host>"]
UPLOAD_MAX_SIZE_MB=50
```

For direct OpenAI:

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=<set-via-secret-store>
LLM_MODEL=<model-name>
CORS_ORIGINS=["https://<frontend-host>"]
UPLOAD_MAX_SIZE_MB=50
```

The backend privacy layer sanitizes Azure subscription, resource group, and tenant identifiers before LLM-bound prompts are assembled. Keep treating raw exports as sensitive anyway, and do not use this sanitization step as a reason to commit live data.

### Public Deployment Hardening

For a public deployment, keep the UI public and harden the expensive or destructive backend surfaces:

- enable API rate limiting with `RATE_LIMIT_ENABLED=true`
- tune `UPLOAD_RATE_LIMIT_*`, `GENERATION_RATE_LIMIT_*`, `CHAT_RATE_LIMIT_*`, and `READ_RATE_LIMIT_*` for your expected traffic
- cap per-instance background audit fan-out with `MAX_CONCURRENT_AUDIT_JOBS`
- set `TRUST_PROXY_HEADERS=true` when running behind Container Apps ingress or another trusted reverse proxy
- keep `TRUSTED_PROXY_CIDRS` limited to the networks that should be allowed to supply forwarded client IP headers
- when Azure Front Door is the public edge, set a secret `FRONT_DOOR_ORIGIN_TOKEN` value in the backend and inject the same value on the backend route with a Front Door rules engine request-header action
- protect destructive routes with `ADMIN_API_TOKEN`; without it, `DELETE /api/v1/audit*` and `POST /api/v1/seed-demo` stay disabled

Current recommended public posture for this repo:

- publish the app through Azure Front Door and point the frontend at `https://<front-door-host>/api/v1`
- set `NEXT_PUBLIC_SITE_URL=https://<front-door-host>` so metadata, previews, and any derived public links use the Front Door hostname
- keep the direct Container Apps hostnames as implementation details rather than the advertised public URL
- rely on the in-app rate limiting, background job caps, admin-token protection, and response hardening already implemented in the backend and frontend

The frontend audit-delete UI is intended to stay off for public builds unless you explicitly enable an admin-capable frontend separately.

### Container Apps Manifest Usage

The tracked files [backend-container-app.yaml](../backend-container-app.yaml) and [container-env.yaml](../container-env.yaml) are sanitized examples only.

Recommended approach:

1. Copy the example manifest to a local ignored file such as `backend-container-app.local.yaml`.
2. Replace placeholders with your deployment values.
3. Inject secrets through Container Apps secrets instead of checking them into git.

If you customize the frontend ingress path, preserve the nonce-aware CSP behavior implemented by the frontend server and middleware files. Static CSP overrides that drop the nonce will break the app.

## Global Secure Access Exports

FlameGuard can now ingest Microsoft Entra Global Secure Access exports in addition to Azure Firewall, NSG, and WAF inputs.

Supported GSA log families:

- Audit logs filtered to the `Global Secure Access` service in Microsoft Entra audit logs
- Deployment logs from `Global Secure Access > Monitor > Deployment logs`
- Traffic log exports routed through Microsoft Entra diagnostic settings with the `NetworkAccessTrafficLogs` category enabled

Current Microsoft guidance points to these locations:

- `Global Secure Access > Monitor > Audit logs` or `Entra ID > Monitoring & health > Audit logs` with the `Global Secure Access` service filter
- `Global Secure Access > Monitor > Deployment logs`
- `Entra ID > Monitoring & health > Diagnostic settings` to export `NetworkAccessTrafficLogs` to Log Analytics, storage, Event Hubs, or partner destinations

For public-repo workflows, prefer uploading sanitized JSON or CSV exports rather than raw tenant archives. Traffic logs contain the most network-specific context, while audit and deployment logs capture forwarding-profile, remote-network, and related control-plane changes.

## Durable Storage

The default SQLite configuration is appropriate for local use and short-lived demos. For shared or production deployments:

- move the database off ephemeral container storage
- use a durable volume or a managed database
- treat uploaded configs and audit history as persistent application data

## Open-Source Publishing Checklist

Before pushing or opening a pull request:

- confirm no real API keys are present
- confirm no real subscription IDs or tenant-specific hostnames are present
- confirm sample exports are sanitized
- confirm `.env`, local overrides, and private manifests are ignored
- confirm docs use placeholders rather than live values

## Post-Deploy Smoke Checks

After a backend or frontend rollout:

1. Wait until `latestRevisionName` matches `latestReadyRevisionName` for each Container App.
2. Verify the backend health endpoint returns success through the Front Door hostname.
3. Verify the frontend root route and key app routes load successfully through the Front Door hostname.
4. Optionally seed demo data with `POST /api/v1/seed-demo` and confirm `/api/v1/audits` returns records.

Example checks:

```bash
az containerapp show --name <backend-app-name> --resource-group <resource-group> --query "{latest:properties.latestRevisionName,ready:properties.latestReadyRevisionName}" --output json
az containerapp show --name <frontend-app-name> --resource-group <resource-group> --query "{latest:properties.latestRevisionName,ready:properties.latestReadyRevisionName}" --output json

curl https://<backend-host>/api/v1/health
curl https://<backend-host>/api/v1/audits
curl https://<frontend-host>/
curl -X POST https://<backend-host>/api/v1/seed-demo
```

## Repo Hygiene

Use the following conventions in public commits:

- `.env.example` may contain placeholder settings only
- `*.local.yaml` and `*.local.yml` should remain untracked
- sanitized sample data may live under backend/tests/fixtures or backend/tests/conftest.py
- azure-exports/ and private/ should remain local-only scratch locations
- never paste customer or internal cloud inventory into issues or pull requests