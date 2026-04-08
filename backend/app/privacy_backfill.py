from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditFinding, AuditReport
from app.models.chat import ChatMessage
from app.models.compliance import ComplianceCheck
from app.models.rule import Rule, RuleSet
from app.privacy import sanitize_azure_data, sanitize_azure_text, sanitize_optional_azure_text


def _sanitize_json_blob(value: str | None) -> str | None:
    if value is None:
        return None

    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return sanitize_azure_text(value)

    return json.dumps(sanitize_azure_data(parsed))


def _set_if_changed(record: object, field_name: str, updated_value: str | None) -> bool:
    current_value = getattr(record, field_name)
    if current_value == updated_value:
        return False
    setattr(record, field_name, updated_value)
    return True


async def backfill_privacy_redactions(db: AsyncSession) -> dict[str, int]:
    counts = {
        "rulesets": 0,
        "rules": 0,
        "audits": 0,
        "findings": 0,
        "compliance_checks": 0,
        "chat_messages": 0,
        "rows_updated": 0,
    }

    rulesets = (await db.execute(select(RuleSet))).scalars().all()
    for ruleset in rulesets:
        changed = False
        changed |= _set_if_changed(ruleset, "filename", sanitize_azure_text(ruleset.filename))
        changed |= _set_if_changed(ruleset, "raw_json", _sanitize_json_blob(ruleset.raw_json))
        if changed:
            counts["rulesets"] += 1

    rules = (await db.execute(select(Rule))).scalars().all()
    for rule in rules:
        changed = False
        changed |= _set_if_changed(rule, "original_id", sanitize_optional_azure_text(rule.original_id))
        changed |= _set_if_changed(rule, "name", sanitize_azure_text(rule.name))
        changed |= _set_if_changed(rule, "collection_name", sanitize_optional_azure_text(rule.collection_name))
        changed |= _set_if_changed(rule, "description", sanitize_optional_azure_text(rule.description))
        changed |= _set_if_changed(rule, "tags", _sanitize_json_blob(rule.tags))
        changed |= _set_if_changed(rule, "raw_json", _sanitize_json_blob(rule.raw_json))
        if changed:
            counts["rules"] += 1

    audits = (await db.execute(select(AuditReport))).scalars().all()
    for audit in audits:
        changed = False
        changed |= _set_if_changed(audit, "summary", sanitize_optional_azure_text(audit.summary))
        changed |= _set_if_changed(audit, "error_message", sanitize_optional_azure_text(audit.error_message))
        if changed:
            counts["audits"] += 1

    findings = (await db.execute(select(AuditFinding))).scalars().all()
    for finding in findings:
        changed = False
        changed |= _set_if_changed(finding, "title", sanitize_azure_text(finding.title))
        changed |= _set_if_changed(finding, "description", sanitize_azure_text(finding.description))
        changed |= _set_if_changed(
            finding,
            "recommendation",
            sanitize_optional_azure_text(finding.recommendation),
        )
        if changed:
            counts["findings"] += 1

    compliance_checks = (await db.execute(select(ComplianceCheck))).scalars().all()
    for compliance_check in compliance_checks:
        changed = False
        changed |= _set_if_changed(
            compliance_check,
            "control_title",
            sanitize_azure_text(compliance_check.control_title),
        )
        changed |= _set_if_changed(
            compliance_check,
            "evidence",
            sanitize_optional_azure_text(compliance_check.evidence),
        )
        if changed:
            counts["compliance_checks"] += 1

    chat_messages = (await db.execute(select(ChatMessage))).scalars().all()
    for chat_message in chat_messages:
        if _set_if_changed(chat_message, "content", sanitize_azure_text(chat_message.content)):
            counts["chat_messages"] += 1

    counts["rows_updated"] = (
        counts["rulesets"]
        + counts["rules"]
        + counts["audits"]
        + counts["findings"]
        + counts["compliance_checks"]
        + counts["chat_messages"]
    )

    await db.commit()
    return counts