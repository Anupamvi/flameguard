from __future__ import annotations

import csv
import json
import uuid
from io import StringIO
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditReport
from app.models.rule import Rule, RuleSet
from app.parsers.azure_gsa import AzureGSAParser
from app.parsers.azure_waf import AzureWAFParser
from app.parsers.base import NormalizedRule, ParserRegistry, VendorType
from app.parsers.detector import auto_detect_vendor
from app.privacy import (
    sanitize_azure_data,
    sanitize_azure_json,
    sanitize_azure_text,
    sanitize_optional_azure_text,
)


def _parse_uploaded_payload(raw_content: str, filename: str) -> dict[str, Any]:
    extension = Path(filename).suffix.lower()
    if extension == ".csv":
        return _parse_csv_log_export(raw_content)

    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if isinstance(data, list):
        return {"records": data}

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object or array at the top level")

    return data


def _parse_csv_log_export(raw_content: str) -> dict[str, Any]:
    reader = csv.DictReader(StringIO(raw_content))
    if not reader.fieldnames:
        raise ValueError("CSV upload is missing a header row")

    columns = [_normalize_csv_header(name) for name in reader.fieldnames]
    rows: list[dict[str, Any]] = []
    for raw_row in reader:
        if raw_row is None:
            continue
        normalized_row = {
            _normalize_csv_header(name): value
            for name, value in raw_row.items()
            if name is not None
        }
        if all(value in (None, "") for value in normalized_row.values()):
            continue
        rows.append(normalized_row)

    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [{"name": name, "type": "string"} for name in columns],
                "rows": rows,
            }
        ]
    }


def _normalize_csv_header(name: str) -> str:
    normalized = str(name).lstrip("\ufeff").strip()
    if normalized.endswith(" [UTC]"):
        normalized = normalized[: -len(" [UTC]")]
    return normalized


def _infer_vendor_from_filename(filename: str, data: dict[str, Any]) -> VendorType | None:
    normalized_filename = filename.lower()
    if "waf" not in normalized_filename:
        gsa_parser = AzureGSAParser()
        if any(
            token in normalized_filename
            for token in (
                "global secure access",
                "global-secure-access",
                "global_secure_access",
                "globalsecureaccess",
            )
        ) and gsa_parser.looks_like_ambiguous_log_export(data):
            return VendorType.AZURE_GSA
        return None

    waf_parser = AzureWAFParser()
    if waf_parser.looks_like_ambiguous_log_export(data):
        return VendorType.AZURE_WAF

    return None


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

    data = _parse_uploaded_payload(raw_content, filename)

    # Detect or use hinted vendor
    if vendor_hint:
        try:
            vendor = VendorType(vendor_hint)
            parser = ParserRegistry.get(vendor)
        except (ValueError, KeyError):
            raise ValueError(f"Unknown vendor: {vendor_hint}. Supported: {', '.join(v.value for v in ParserRegistry.all_vendors())}")
    else:
        try:
            parser, vendor = auto_detect_vendor(data)
        except ValueError:
            inferred_vendor = _infer_vendor_from_filename(filename, data)
            if inferred_vendor is None:
                raise ValueError(
                    "Unrecognized upload format. Supported inputs are Azure Firewall, Azure NSG, Azure WAF, and Global Secure Access exports, plus supported Azure WAF and Global Secure Access CSV log exports."
                )
            vendor = inferred_vendor
            parser = ParserRegistry.get(vendor)

    # Parse rules
    normalized_rules = parser.parse(data)
    if not normalized_rules:
        parse_warnings.append("No rules found in the uploaded configuration")

    sanitized_ruleset_json = sanitize_azure_json(data)

    # Create RuleSet
    ruleset_id = str(uuid.uuid4())
    ruleset = RuleSet(
        id=ruleset_id,
        filename=sanitize_azure_text(filename),
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
            name=sanitize_azure_text(nr.name),
            action=nr.action.value,
            direction=nr.direction.value,
            protocol=nr.protocol,
            source_addresses=json.dumps(nr.source_addresses),
            source_ports=json.dumps(nr.source_ports),
            dest_addresses=json.dumps(nr.destination_addresses),
            dest_ports=json.dumps(nr.destination_ports),
            priority=nr.priority,
            collection_name=sanitize_optional_azure_text(nr.collection_name),
            collection_priority=nr.collection_priority,
            description=sanitize_optional_azure_text(nr.description),
            enabled=nr.enabled,
            tags=json.dumps(sanitize_azure_data(nr.tags)),
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
