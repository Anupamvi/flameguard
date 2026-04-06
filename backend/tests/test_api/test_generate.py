import pytest
from httpx import ASGITransport, AsyncClient

from app.database import engine
from app.main import app
from app.models import Base


@pytest.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestGenerateEndpoints:
    @pytest.mark.asyncio
    async def test_generate_endpoint_normalizes_vendor_and_returns_backend_shape(self, client, monkeypatch):
        captured: dict[str, str | None] = {}

        async def fake_generate_rule(*, intent: str, vendor: str, context: str | None = None):
            captured["intent"] = intent
            captured["vendor"] = vendor
            captured["context"] = context
            return {
                "config": {"name": "generated-rule"},
                "explanation": "",
                "warnings": [],
                "is_valid": True,
            }

        monkeypatch.setattr("app.api.generate.generate_rule_from_intent", fake_generate_rule)

        resp = await client.post(
            "/api/v1/generate",
            json={
                "intent": "Allow HTTPS from 10.0.0.0/24",
                "vendor": "Azure NSG",
                "context": "Environment: prod",
            },
        )

        assert resp.status_code == 200
        assert captured == {
            "intent": "Allow HTTPS from 10.0.0.0/24",
            "vendor": "azure_nsg",
            "context": "Environment: prod",
        }
        assert resp.json() == {
            "config": {"name": "generated-rule"},
            "explanation": "Generated a AZURE NSG rule from the provided description and validated that it can be parsed back into FlameGuard's normalized rule format.",
            "warnings": [],
            "is_valid": True,
        }

    @pytest.mark.asyncio
    async def test_frontend_generate_endpoint_matches_dashboard_contract(self, client, monkeypatch):
        captured: dict[str, str | None] = {}

        async def fake_generate_rule(*, intent: str, vendor: str, context: str | None = None):
            captured["intent"] = intent
            captured["vendor"] = vendor
            captured["context"] = context
            return {
                "config": {"name": "generated-rule", "priority": 300},
                "explanation": "",
                "warnings": [],
                "is_valid": True,
            }

        monkeypatch.setattr("app.api.generate.generate_rule_from_intent", fake_generate_rule)

        resp = await client.post(
            "/api/v1/rules/generate",
            json={
                "description": "Allow HTTPS from 10.0.0.0/24",
                "vendor": "Azure Firewall",
                "severity": "high",
                "category": "network-access",
            },
        )

        assert resp.status_code == 200
        assert captured == {
            "intent": "Allow HTTPS from 10.0.0.0/24",
            "vendor": "azure_firewall",
            "context": "Requested severity: high\nCategory: network-access",
        }
        assert resp.json() == {
            "rule": {"name": "generated-rule", "priority": 300},
            "explanation": "Generated a AZURE FIREWALL rule from the provided description and validated that it can be parsed back into FlameGuard's normalized rule format.",
            "confidence": 0.95,
        }