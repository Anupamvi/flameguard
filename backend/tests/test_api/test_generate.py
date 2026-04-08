import json

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import async_session
from app.database import engine
from app.main import app
from app.models import Base
from app.models.audit import AuditFinding, AuditReport
from app.models.rule import Rule, RuleSet
from app.services import generate_service


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
            "warnings": [],
        }

    @pytest.mark.asyncio
    async def test_generate_rule_from_audit_finding_uses_finding_context(self, client, monkeypatch):
        captured: dict[str, str | None] = {}

        async def fake_generate_rule(*, intent: str, vendor: str, context: str | None = None):
            captured["intent"] = intent
            captured["vendor"] = vendor
            captured["context"] = context
            return {
                "config": {"name": "generated-rule", "priority": 150},
                "explanation": "",
                "warnings": [],
                "is_valid": True,
            }

        monkeypatch.setattr("app.api.generate.generate_rule_from_intent", fake_generate_rule)

        ruleset_id = "10000000-0000-0000-0000-000000000001"
        rule_id = "10000000-0000-0000-0000-000000000002"
        audit_id = "10000000-0000-0000-0000-000000000003"
        finding_id = "10000000-0000-0000-0000-000000000004"

        async with async_session() as session:
            session.add(
                RuleSet(
                    id=ruleset_id,
                    filename="alice@example.com-prod-export.json",
                    vendor="azure_waf",
                    raw_json="{}",
                    rule_count=1,
                )
            )
            session.add(
                Rule(
                    id=rule_id,
                    ruleset_id=ruleset_id,
                    original_id="rule-1",
                    name="deny-bot-pattern",
                    action="deny",
                    direction="inbound",
                    protocol="HTTPS",
                    source_addresses=json.dumps(["198.51.100.24"]),
                    source_ports=json.dumps(["*"]),
                    dest_addresses=json.dumps(["shop.contoso.com"]),
                    dest_ports=json.dumps(["443"]),
                    priority=100,
                    description="subscriptionName: Finance Prod blocks one attacker IP only",
                    enabled=True,
                    tags=json.dumps({"userName": "alice@example.com"}),
                    raw_json="{}",
                )
            )
            session.add(
                AuditReport(
                    id=audit_id,
                    ruleset_id=ruleset_id,
                    status="completed",
                )
            )
            session.add(
                AuditFinding(
                    id=finding_id,
                    audit_id=audit_id,
                    rule_id=rule_id,
                    related_rule_ids=json.dumps([rule_id]),
                    severity="high",
                    category="best_practice",
                    title="Rules hardcode a single bot IP",
                    description="User name: alice@example.com hardcodes a single attacker IP and is easy to evade.",
                    recommendation="subscriptionName: Finance Prod should rely on WAF signatures instead of fixed attacker IPs.",
                )
            )
            await session.commit()

        resp = await client.post(f"/api/v1/audit/{audit_id}/findings/{finding_id}/generate-rule")

        assert resp.status_code == 200
        assert captured["vendor"] == "azure_waf"
        assert captured["intent"] is not None
        assert "Rules hardcode a single bot IP" in captured["intent"]
        assert captured["context"] is not None
        assert "Requested severity: high" in captured["context"]
        assert "Category: best_practice" in captured["context"]
        assert "Affected rule count: 1" in captured["context"]
        assert "deny-bot-pattern" in captured["context"]
        assert "198.51.100.24" in captured["context"]
        assert "alice@example.com" not in captured["context"]
        assert "Finance Prod" not in captured["context"]
        assert "[redacted-user]" in captured["context"]
        assert "[redacted-subscription-name]" in captured["context"]
        assert resp.json() == {
            "rule": {"name": "generated-rule", "priority": 150},
            "explanation": "Generated a AZURE WAF rule from the provided description and validated that it can be parsed back into FlameGuard's normalized rule format.",
            "confidence": 0.95,
            "warnings": [],
        }


@pytest.mark.asyncio
async def test_generate_service_scopes_nsg_exception_sources(monkeypatch):
    class FakeParser:
        def parse(self, data):
            return [data]

    class FakeClaudeClient:
        async def analyze(self, **kwargs):
            return "{}"

    def fake_parse_generate_response(_raw):
        return {
            "config": {
                "name": "deny-ssh-inbound-from-internet-except-vpn-10-5-0-0-16",
                "properties": {
                    "access": "Deny",
                    "direction": "Inbound",
                    "protocol": "Tcp",
                    "priority": 300,
                    "sourceAddressPrefix": "*",
                    "sourceAddressPrefixes": [],
                    "sourcePortRange": "*",
                    "sourcePortRanges": [],
                    "destinationAddressPrefix": "10.1.0.0/24",
                    "destinationAddressPrefixes": [],
                    "destinationPortRange": "22",
                    "destinationPortRanges": [],
                },
            },
            "explanation": "",
            "warnings": [],
        }

    monkeypatch.setattr("app.services.generate_service.ClaudeClient", FakeClaudeClient)
    monkeypatch.setattr("app.services.generate_service.parse_generate_response", fake_parse_generate_response)
    monkeypatch.setattr("app.services.generate_service.ParserRegistry.get", lambda _vendor: FakeParser())
    monkeypatch.setattr(generate_service.settings, "llm_provider", "test")

    result = await generate_service.generate_rule(
        intent="Block all inbound SSH (port 22) except from VPN subnet 10.5.0.0/16",
        vendor="azure_nsg",
    )

    assert result["is_valid"] is True
    assert result["config"]["name"].startswith("allow-")
    assert result["config"]["properties"]["access"] == "Allow"
    assert result["config"]["properties"]["sourceAddressPrefix"] == "10.5.0.0/16"
    assert result["config"]["properties"]["sourceAddressPrefixes"] == []
    assert any("Adjusted the NSG rule" in warning for warning in result["warnings"])