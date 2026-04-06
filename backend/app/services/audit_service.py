from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditReport
from app.models.rule import Rule, RuleSet
from app.parsers.base import NormalizedRule, ParserRegistry, VendorType
from app.parsers.detector import auto_detect_vendor
from app.privacy import sanitize_azure_json, sanitize_azure_text


async def upload_and_parse(
    raw_content: str,
    filename: str,
    vendor_hint: str | None,
    db: AsyncSession,
) -> tuple[RuleSet, AuditReport, list[str]]:
    """Parse uploaded JSON, store ruleset + rules, create pending audit.

    Returns (ruleset, audit_report, parse_warnings).
    """
    parse_warnings: list[str] = []

    # Parse JSON
    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object at the top level")

    # Detect or use hinted vendor
    if vendor_hint:
        try:
            vendor = VendorType(vendor_hint)
            parser = ParserRegistry.get(vendor)
        except (ValueError, KeyError):
            raise ValueError(f"Unknown vendor: {vendor_hint}. Supported: {', '.join(v.value for v in ParserRegistry.all_vendors())}")
    else:
        parser, vendor = auto_detect_vendor(data)

    # Parse rules
    normalized_rules = parser.parse(data)
    if not normalized_rules:
        parse_warnings.append("No rules found in the uploaded configuration")

    sanitized_ruleset_json = sanitize_azure_json(data)

    # Create RuleSet
    ruleset_id = str(uuid.uuid4())
    ruleset = RuleSet(
        id=ruleset_id,
        filename=filename,
        vendor=vendor.value,
        raw_json=sanitized_ruleset_json,
        rule_count=len(normalized_rules),
    )
    db.add(ruleset)

    # Create Rule rows
    for nr in normalized_rules:
        rule = Rule(
            id=str(uuid.uuid4()),
            ruleset_id=ruleset_id,
            original_id=sanitize_azure_text(nr.original_id) if nr.original_id else None,
            name=nr.name,
            action=nr.action.value,
            direction=nr.direction.value,
            protocol=nr.protocol,
            source_addresses=json.dumps(nr.source_addresses),
            source_ports=json.dumps(nr.source_ports),
            dest_addresses=json.dumps(nr.destination_addresses),
            dest_ports=json.dumps(nr.destination_ports),
            priority=nr.priority,
            collection_name=nr.collection_name,
            collection_priority=nr.collection_priority,
            description=nr.description,
            enabled=nr.enabled,
            tags=json.dumps(nr.tags),
            raw_json=sanitize_azure_json(nr.raw_json),
        )
        db.add(rule)

    # Create pending AuditReport
    audit_id = str(uuid.uuid4())
    audit = AuditReport(
        id=audit_id,
        ruleset_id=ruleset_id,
        status="parsing",
    )
    db.add(audit)

    await db.commit()
    await db.refresh(ruleset)
    await db.refresh(audit)

    return ruleset, audit, parse_warnings


async def run_audit_pipeline(audit_id: str, ruleset_id: str, db: AsyncSession) -> None:
    """Create a ClaudeClient and AuditPipeline, then run the full audit.

    This is the entry point called from background tasks after upload.
    """
    from app.llm.client import ClaudeClient
    from app.llm.pipeline import AuditPipeline

    llm = ClaudeClient()
    pipeline = AuditPipeline(db=db, llm=llm)
    await pipeline.run(audit_id=audit_id, ruleset_id=ruleset_id)
