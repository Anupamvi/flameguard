import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app import security as security_module
from app.database import async_session, engine
from app.main import app
from app.models import Base
from app.models.audit import AuditReport
from app.models.rule import RuleSet
from app.schemas.audit import UploadResponse
from app.security import ADMIN_TOKEN_HEADER, get_client_address


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


@pytest.mark.asyncio
async def test_upload_text_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(security_module.settings, "upload_rate_limit_requests", 1)
    monkeypatch.setattr(security_module.settings, "upload_rate_limit_window_seconds", 60)

    async def fake_store_upload(*, raw_content, filename, vendor_hint, background_tasks, db):
        return UploadResponse(
            ruleset_id="10000000-0000-0000-0000-000000000001",
            audit_id="10000000-0000-0000-0000-000000000002",
            status="parsing",
            rule_count=1,
            vendor="azure_nsg",
            parse_warnings=[],
        )

    monkeypatch.setattr("app.api.upload._store_upload", fake_store_upload)

    payload = {"filename": "nsg.json", "content": "{}"}

    first = await client.post("/api/v1/upload/text", json=payload)
    second = await client.post("/api/v1/upload/text", json=payload)

    assert first.status_code == 201
    assert second.status_code == 429
    assert "Retry-After" in second.headers
    assert second.json()["detail"].startswith("Too many upload requests")


@pytest.mark.asyncio
async def test_delete_routes_require_admin_token(client, monkeypatch):
    monkeypatch.setattr(security_module.settings, "admin_api_token", "super-secret")

    ruleset_id = "20000000-0000-0000-0000-000000000001"
    audit_id = "20000000-0000-0000-0000-000000000002"

    async with async_session() as session:
        session.add(
            RuleSet(
                id=ruleset_id,
                filename="sample.json",
                vendor="azure_nsg",
                raw_json="{}",
                rule_count=0,
            )
        )
        session.add(
            AuditReport(
                id=audit_id,
                ruleset_id=ruleset_id,
                status="completed",
            )
        )
        await session.commit()

    blocked = await client.delete(f"/api/v1/audit/{audit_id}")
    allowed = await client.delete(
        f"/api/v1/audit/{audit_id}",
        headers={ADMIN_TOKEN_HEADER: "super-secret"},
    )

    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Administrative token required for this route."
    assert allowed.status_code == 200
    assert allowed.json()["deleted_audit_ids"] == [audit_id]


def _build_request(client_host: str, headers: dict[str, str] | None = None) -> Request:
    encoded_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/api/v1/audits",
            "raw_path": b"/api/v1/audits",
            "query_string": b"",
            "headers": encoded_headers,
            "client": (client_host, 443),
            "server": ("testserver", 443),
        }
    )


def test_proxy_headers_trusted_for_private_proxy(monkeypatch):
    monkeypatch.setattr(security_module.settings, "trust_proxy_headers", True)
    monkeypatch.setattr(security_module.settings, "trusted_proxy_cidrs", "10.0.0.0/8")

    request = _build_request("10.1.2.3", {"X-Forwarded-For": "198.51.100.24, 10.1.2.3"})

    assert get_client_address(request) == "198.51.100.24"


def test_proxy_headers_ignored_for_public_client(monkeypatch):
    monkeypatch.setattr(security_module.settings, "trust_proxy_headers", True)
    monkeypatch.setattr(security_module.settings, "trusted_proxy_cidrs", "10.0.0.0/8")

    request = _build_request("203.0.113.20", {"X-Forwarded-For": "198.51.100.24"})

    assert get_client_address(request) == "203.0.113.20"


def test_front_door_origin_token_enables_trusted_client_ip(monkeypatch):
    monkeypatch.setattr(security_module.settings, "trust_proxy_headers", True)
    monkeypatch.setattr(security_module.settings, "front_door_origin_token", "origin-secret")

    request = _build_request(
        "10.1.2.3",
        {
            "X-FlameGuard-Origin-Token": "origin-secret",
            "X-Azure-ClientIP": "198.51.100.24",
            "X-Forwarded-For": "1.1.1.1, 198.51.100.24",
        },
    )

    assert get_client_address(request) == "198.51.100.24"


def test_front_door_origin_token_is_required_before_trusting_proxy_headers(monkeypatch):
    monkeypatch.setattr(security_module.settings, "trust_proxy_headers", True)
    monkeypatch.setattr(security_module.settings, "front_door_origin_token", "origin-secret")

    request = _build_request(
        "10.1.2.3",
        {
            "X-Azure-ClientIP": "198.51.100.24",
            "X-Forwarded-For": "198.51.100.24",
        },
    )

    assert get_client_address(request) == "10.1.2.3"