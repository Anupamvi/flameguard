import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
import json

from app.database import async_session
from app.main import app
from app.database import engine
from app.models import Base
from app.models.rule import Rule, RuleSet


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


class TestUploadEndpoint:
    @pytest.mark.asyncio
    async def test_upload_nsg(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "rb") as f:
            resp = await client.post("/api/v1/upload", files={"file": ("nsg.json", f, "application/json")})
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_nsg"
        assert data["rule_count"] == 16
        assert data["status"] == "parsing"
        assert data["ruleset_id"]
        assert data["audit_id"]

    @pytest.mark.asyncio
    async def test_upload_firewall(self, client):
        with open("tests/fixtures/azure_firewall_sample.json", "rb") as f:
            resp = await client.post("/api/v1/upload", files={"file": ("fw.json", f, "application/json")})
        assert resp.status_code == 201
        assert resp.json()["vendor"] == "azure_firewall"

    @pytest.mark.asyncio
    async def test_upload_firewall_log_export(self, client, firewall_log_export_normalized):
        payload = json.dumps(firewall_log_export_normalized).encode("utf-8")
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("fw-logs.json", payload, "application/json")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_firewall"
        assert data["rule_count"] == 3

    @pytest.mark.asyncio
    async def test_upload_waf(self, client):
        with open("tests/fixtures/azure_waf_sample.json", "rb") as f:
            resp = await client.post("/api/v1/upload", files={"file": ("waf.json", f, "application/json")})
        assert resp.status_code == 201
        assert resp.json()["vendor"] == "azure_waf"

    @pytest.mark.asyncio
    async def test_upload_invalid_json(self, client):
        resp = await client.post("/api/v1/upload", files={"file": ("bad.json", b"not json", "application/json")})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_upload_unknown_vendor(self, client):
        resp = await client.post("/api/v1/upload", files={"file": ("unknown.json", b'{"foo": "bar"}', "application/json")})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_rules_after_upload(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "rb") as f:
            resp = await client.post("/api/v1/upload", files={"file": ("nsg.json", f, "application/json")})
        ruleset_id = resp.json()["ruleset_id"]

        resp = await client.get(f"/api/v1/rulesets/{ruleset_id}/rules")
        assert resp.status_code == 200
        rules = resp.json()
        assert len(rules) == 16

    @pytest.mark.asyncio
    async def test_get_audit_after_upload(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "rb") as f:
            resp = await client.post("/api/v1/upload", files={"file": ("nsg.json", f, "application/json")})
        audit_id = resp.json()["audit_id"]

        resp = await client.get(f"/api/v1/audit/{audit_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] in ("parsing", "auditing", "scoring", "completed", "failed")

    @pytest.mark.asyncio
    async def test_list_audits(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "rb") as f:
            await client.post("/api/v1/upload", files={"file": ("nsg.json", f, "application/json")})

        resp = await client.get("/api/v1/audits")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    @pytest.mark.asyncio
    async def test_upload_sanitizes_stored_azure_metadata(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "rb") as f:
            resp = await client.post("/api/v1/upload", files={"file": ("nsg.json", f, "application/json")})

        ruleset_id = resp.json()["ruleset_id"]

        async with async_session() as session:
            ruleset = await session.get(RuleSet, ruleset_id)
            assert ruleset is not None
            assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in ruleset.raw_json
            assert "rg-prod-networking" not in ruleset.raw_json
            assert "[redacted-subscription]" in ruleset.raw_json
            assert "[redacted-resource-group]" in ruleset.raw_json

            result = await session.execute(select(Rule).where(Rule.ruleset_id == ruleset_id))
            rules = result.scalars().all()
            assert rules
            assert all(
                rule.raw_json and "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in rule.raw_json
                for rule in rules
            )
