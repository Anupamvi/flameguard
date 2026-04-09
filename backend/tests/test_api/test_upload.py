import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
import gzip
import json

from app.config import settings as app_settings
from app.database import async_session
from app.main import app
from app.database import engine
from app.models import Base
from app.models.audit import AuditFinding, AuditReport
from app.models.chat import ChatMessage
from app.models.compliance import ComplianceCheck
from app.models.rule import Rule, RuleSet
from app.privacy_backfill import backfill_privacy_redactions


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
    async def test_upload_waf_log_export(self, client, waf_log_export_raw):
        payload = json.dumps(waf_log_export_raw).encode("utf-8")
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("application-gateway-logs.json", payload, "application/json")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_waf"
        assert data["rule_count"] == 1

    @pytest.mark.asyncio
    async def test_upload_appgw_waf_csv_log_export(self, client, waf_log_export_appgw_csv):
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("AppGW-WAF_SampleLogs_data.csv", waf_log_export_appgw_csv, "text/csv")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_waf"
        assert data["rule_count"] == 1

    @pytest.mark.asyncio
    async def test_upload_gzipped_nsg(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "rb") as f:
            payload = gzip.compress(f.read())

        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("nsg.json.gz", payload, "application/gzip")},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_nsg"
        assert data["rule_count"] == 16

    @pytest.mark.asyncio
    async def test_upload_gzipped_appgw_waf_csv_log_export(self, client, waf_log_export_appgw_csv):
        payload = gzip.compress(waf_log_export_appgw_csv)
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("AppGW-WAF_SampleLogs_data.csv.gz", payload, "application/gzip")},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_waf"
        assert data["rule_count"] == 1

    @pytest.mark.asyncio
    async def test_upload_frontdoor_waf_csv_log_export(self, client, waf_log_export_afd_csv):
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("AFD-WAF_SampleLogs_data.csv", waf_log_export_afd_csv, "text/csv")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_waf"
        assert data["rule_count"] == 1

    @pytest.mark.asyncio
    async def test_upload_text_nsg(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "r", encoding="utf-8") as f:
            resp = await client.post(
                "/api/v1/upload/text",
                json={"filename": "nsg.json", "content": f.read()},
            )

        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_nsg"
        assert data["rule_count"] == 16

    @pytest.mark.asyncio
    async def test_upload_text_appgw_waf_csv_log_export(self, client, waf_log_export_appgw_csv):
        resp = await client.post(
            "/api/v1/upload/text",
            json={
                "filename": "AppGW-WAF_SampleLogs_data.csv",
                "content": waf_log_export_appgw_csv.decode("utf-8"),
            },
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_waf"
        assert data["rule_count"] == 1

    @pytest.mark.asyncio
    async def test_upload_gsa_traffic_log_export(self, client, gsa_traffic_log_export_raw):
        payload = json.dumps(gsa_traffic_log_export_raw).encode("utf-8")
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("gsa-traffic.json", payload, "application/json")},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_gsa"
        assert data["rule_count"] == 1

    @pytest.mark.asyncio
    async def test_upload_gsa_audit_csv_log_export(self, client, gsa_audit_log_export_csv):
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("global-secure-access-audit.csv", gsa_audit_log_export_csv, "text/csv")},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_gsa"
        assert data["rule_count"] == 1

    @pytest.mark.asyncio
    async def test_upload_empty_waf_log_export_uses_filename_fallback(self, client, waf_log_export_empty_raw):
        payload = json.dumps(waf_log_export_empty_raw).encode("utf-8")
        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("contoso-waf-samples-2026-04-06.json", payload, "application/json")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "azure_waf"
        assert data["rule_count"] == 0
        assert data["parse_warnings"] == ["No rules found in the uploaded configuration"]

    @pytest.mark.asyncio
    async def test_upload_invalid_json(self, client):
        resp = await client.post("/api/v1/upload", files={"file": ("bad.json", b"not json", "application/json")})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_upload_gzip_bomb_is_rejected_before_full_expansion(self, client, monkeypatch):
        monkeypatch.setattr(app_settings, "upload_max_size_mb", 1)
        payload = gzip.compress(b"A" * ((1024 * 1024) + 64))

        resp = await client.post(
            "/api/v1/upload",
            files={"file": ("oversized.json.gz", payload, "application/gzip")},
        )

        assert resp.status_code == 413
        assert resp.json()["detail"].startswith("File too large")

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
        assert resp.json()[0]["findings"] == []

    @pytest.mark.asyncio
    async def test_upload_sanitizes_stored_azure_metadata(self, client):
        with open("tests/fixtures/azure_nsg_sample.json", "rb") as f:
            resp = await client.post("/api/v1/upload", files={"file": ("nsg.json", f, "application/json")})

        ruleset_id = resp.json()["ruleset_id"]

        async with async_session() as session:
            ruleset = await session.get(RuleSet, ruleset_id)
            assert ruleset is not None
            assert "00000000-0000-0000-0000-000000000000" not in ruleset.raw_json
            assert "rg-sample-networking" not in ruleset.raw_json
            assert "[redacted-subscription]" in ruleset.raw_json
            assert "[redacted-resource-group]" in ruleset.raw_json

            result = await session.execute(select(Rule).where(Rule.ruleset_id == ruleset_id))
            rules = result.scalars().all()
            assert rules
            assert all(
                rule.raw_json and "00000000-0000-0000-0000-000000000000" not in rule.raw_json
                for rule in rules
            )

    @pytest.mark.asyncio
    async def test_audit_related_endpoints_scrub_existing_sensitive_text(self, client):
        ruleset_id = "20000000-0000-0000-0000-000000000001"
        rule_id = "20000000-0000-0000-0000-000000000002"
        audit_id = "20000000-0000-0000-0000-000000000003"
        finding_id = "20000000-0000-0000-0000-000000000004"
        compliance_id = "20000000-0000-0000-0000-000000000005"

        async with async_session() as session:
            session.add(
                RuleSet(
                    id=ruleset_id,
                    filename="alice@example.com-finance-prod.json",
                    vendor="azure_nsg",
                    raw_json="{}",
                    rule_count=1,
                )
            )
            session.add(
                Rule(
                    id=rule_id,
                    ruleset_id=ruleset_id,
                    original_id="/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/Finance Prod/providers/Microsoft.Network/networkSecurityGroups/example",
                    name="Allow alice@example.com HTTPS",
                    action="allow",
                    direction="inbound",
                    protocol="TCP",
                    source_addresses=json.dumps(["198.51.100.24"]),
                    source_ports=json.dumps(["*"]),
                    dest_addresses=json.dumps(["10.0.0.4"]),
                    dest_ports=json.dumps(["443"]),
                    priority=100,
                    collection_name="subscriptionName: Finance Prod",
                    description="owner: alice@example.com",
                    enabled=True,
                    tags=json.dumps({
                        "userName": "alice@example.com",
                        "subscriptionName": "Finance Prod",
                    }),
                    raw_json="{}",
                )
            )
            session.add(
                AuditReport(
                    id=audit_id,
                    ruleset_id=ruleset_id,
                    status="completed",
                    summary="owner: alice@example.com subscriptionName: Finance Prod",
                    error_message="subscription id: 11111111-2222-3333-4444-555555555555",
                    total_findings=1,
                    high_count=1,
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
                    title="userName: alice@example.com",
                    description="subscriptionName: Finance Prod",
                    recommendation="owner: alice@example.com",
                )
            )
            session.add(
                ComplianceCheck(
                    id=compliance_id,
                    audit_id=audit_id,
                    framework="soc2",
                    control_id="CC6.6",
                    control_title="Review owner: alice@example.com",
                    status="fail",
                    evidence="subscriptionName: Finance Prod",
                    affected_rule_ids=json.dumps([rule_id]),
                )
            )
            await session.commit()

        audit_resp = await client.get(f"/api/v1/audit/{audit_id}")
        assert audit_resp.status_code == 200
        audit_body = json.dumps(audit_resp.json())
        assert "alice@example.com" not in audit_body
        assert "Finance Prod" not in audit_body
        assert "11111111-2222-3333-4444-555555555555" not in audit_body
        assert "[redacted-user]" in audit_body
        assert "[redacted-subscription-name]" in audit_body
        assert "[redacted-subscription]" in audit_body

        audits_resp = await client.get("/api/v1/audits")
        assert audits_resp.status_code == 200
        listed_audit = next(item for item in audits_resp.json() if item["id"] == audit_id)
        listed_body = json.dumps(listed_audit)
        assert "alice@example.com" not in listed_body
        assert "Finance Prod" not in listed_body
        assert "[redacted-user]" in listed_body

        rules_resp = await client.get(f"/api/v1/rulesets/{ruleset_id}/rules")
        assert rules_resp.status_code == 200
        rules_body = json.dumps(rules_resp.json())
        assert "alice@example.com" not in rules_body
        assert "Finance Prod" not in rules_body
        assert "11111111-2222-3333-4444-555555555555" not in rules_body
        assert "198.51.100.24" in rules_body
        assert "[redacted-user]" in rules_body
        assert "[redacted-subscription-name]" in rules_body

        compliance_resp = await client.get(f"/api/v1/audit/{audit_id}/compliance")
        assert compliance_resp.status_code == 200
        compliance_body = json.dumps(compliance_resp.json())
        assert "alice@example.com" not in compliance_body
        assert "Finance Prod" not in compliance_body
        assert "[redacted-user]" in compliance_body
        assert "[redacted-subscription-name]" in compliance_body

    @pytest.mark.asyncio
    async def test_privacy_backfill_rewrites_existing_sensitive_rows(self):
        ruleset_id = "30000000-0000-0000-0000-000000000001"
        rule_id = "30000000-0000-0000-0000-000000000002"
        audit_id = "30000000-0000-0000-0000-000000000003"
        finding_id = "30000000-0000-0000-0000-000000000004"
        compliance_id = "30000000-0000-0000-0000-000000000005"
        chat_id = "30000000-0000-0000-0000-000000000006"

        async with async_session() as session:
            session.add(
                RuleSet(
                    id=ruleset_id,
                    filename="alice@example.com-finance-prod.json",
                    vendor="azure_nsg",
                    raw_json=json.dumps({
                        "subscriptionName": "Finance Prod",
                        "owner": "alice@example.com",
                    }),
                    rule_count=1,
                )
            )
            session.add(
                Rule(
                    id=rule_id,
                    ruleset_id=ruleset_id,
                    original_id="/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/Finance Prod/providers/Microsoft.Network/networkSecurityGroups/example",
                    name="Allow alice@example.com HTTPS",
                    action="allow",
                    direction="inbound",
                    protocol="TCP",
                    source_addresses=json.dumps(["198.51.100.24"]),
                    source_ports=json.dumps(["*"]),
                    dest_addresses=json.dumps(["10.0.0.4"]),
                    dest_ports=json.dumps(["443"]),
                    priority=100,
                    collection_name="subscriptionName: Finance Prod",
                    description="owner: alice@example.com",
                    enabled=True,
                    tags=json.dumps({"userName": "alice@example.com"}),
                    raw_json=json.dumps({"subscriptionName": "Finance Prod"}),
                )
            )
            session.add(
                AuditReport(
                    id=audit_id,
                    ruleset_id=ruleset_id,
                    status="completed",
                    summary="owner: alice@example.com subscriptionName: Finance Prod",
                    error_message="subscription id: 11111111-2222-3333-4444-555555555555",
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
                    title="userName: alice@example.com",
                    description="subscriptionName: Finance Prod",
                    recommendation="owner: alice@example.com",
                )
            )
            session.add(
                ComplianceCheck(
                    id=compliance_id,
                    audit_id=audit_id,
                    framework="soc2",
                    control_id="CC6.6",
                    control_title="Review owner: alice@example.com",
                    status="fail",
                    evidence="subscriptionName: Finance Prod",
                    affected_rule_ids=json.dumps([rule_id]),
                )
            )
            session.add(
                ChatMessage(
                    id=chat_id,
                    audit_id=audit_id,
                    role="assistant",
                    content="owner: alice@example.com subscriptionName: Finance Prod",
                )
            )
            await session.commit()

            result = await backfill_privacy_redactions(session)
            assert result == {
                "rulesets": 1,
                "rules": 1,
                "audits": 1,
                "findings": 1,
                "compliance_checks": 1,
                "chat_messages": 1,
                "rows_updated": 6,
            }

            await session.refresh(await session.get(RuleSet, ruleset_id))
            await session.refresh(await session.get(Rule, rule_id))
            await session.refresh(await session.get(AuditReport, audit_id))
            await session.refresh(await session.get(AuditFinding, finding_id))
            await session.refresh(await session.get(ComplianceCheck, compliance_id))
            await session.refresh(await session.get(ChatMessage, chat_id))

            ruleset = await session.get(RuleSet, ruleset_id)
            rule = await session.get(Rule, rule_id)
            audit = await session.get(AuditReport, audit_id)
            finding = await session.get(AuditFinding, finding_id)
            compliance = await session.get(ComplianceCheck, compliance_id)
            chat = await session.get(ChatMessage, chat_id)

            serialized = json.dumps(
                {
                    "ruleset": {
                        "filename": ruleset.filename,
                        "raw_json": ruleset.raw_json,
                    },
                    "rule": {
                        "original_id": rule.original_id,
                        "name": rule.name,
                        "collection_name": rule.collection_name,
                        "description": rule.description,
                        "tags": rule.tags,
                        "raw_json": rule.raw_json,
                    },
                    "audit": {
                        "summary": audit.summary,
                        "error_message": audit.error_message,
                    },
                    "finding": {
                        "title": finding.title,
                        "description": finding.description,
                        "recommendation": finding.recommendation,
                    },
                    "compliance": {
                        "control_title": compliance.control_title,
                        "evidence": compliance.evidence,
                    },
                    "chat": chat.content,
                }
            )

            assert "alice@example.com" not in serialized
            assert "Finance Prod" not in serialized
            assert "11111111-2222-3333-4444-555555555555" not in serialized
            assert "[redacted-user]" in serialized
            assert "[redacted-subscription-name]" in serialized
            assert "[redacted-subscription]" in serialized
