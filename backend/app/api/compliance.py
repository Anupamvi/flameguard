import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.compliance.engine import get_compliance_engine
from app.database import get_db
from app.models.audit import AuditReport
from app.models.compliance import ComplianceCheck
from app.models.rule import Rule, RuleSet
from app.parsers.base import NormalizedRule, RuleAction, RuleDirection, VendorType
from app.privacy import sanitize_azure_text, sanitize_optional_azure_text
from app.schemas.compliance import ComplianceCheckOut, ComplianceSummary
from app.security import read_rate_limit

router = APIRouter()


def _db_rule_to_normalized(rule: Rule) -> NormalizedRule:
    """Convert a DB Rule row to a NormalizedRule."""

    def _json_list(val: str | None) -> list[str]:
        if not val:
            return []
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return []

    def _json_dict(val: str | None) -> dict:
        if not val:
            return {}
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return {}

    return NormalizedRule(
        original_id=rule.original_id or rule.id,
        name=rule.name,
        vendor=VendorType(rule.ruleset.vendor) if rule.ruleset else VendorType.AZURE_FIREWALL,
        action=RuleAction(rule.action),
        direction=RuleDirection(rule.direction),
        protocol=rule.protocol or "Any",
        source_addresses=_json_list(rule.source_addresses),
        source_ports=_json_list(rule.source_ports),
        destination_addresses=_json_list(rule.dest_addresses),
        destination_ports=_json_list(rule.dest_ports),
        priority=rule.priority,
        collection_name=rule.collection_name,
        collection_priority=rule.collection_priority,
        description=rule.description or "",
        enabled=rule.enabled,
        tags=_json_dict(rule.tags),
    )


def _build_summaries(checks: list[ComplianceCheck]) -> list[ComplianceSummary]:
    """Group ComplianceCheck rows by framework into ComplianceSummary objects."""
    by_framework: dict[str, list[ComplianceCheck]] = {}
    for c in checks:
        by_framework.setdefault(c.framework, []).append(c)

    summaries: list[ComplianceSummary] = []
    for fw, fw_checks in sorted(by_framework.items()):
        passed = sum(1 for c in fw_checks if c.status == "pass")
        failed = sum(1 for c in fw_checks if c.status == "fail")
        na = sum(1 for c in fw_checks if c.status == "not_applicable")

        check_outs = []
        for c in fw_checks:
            affected = []
            if c.affected_rule_ids:
                try:
                    affected = json.loads(c.affected_rule_ids)
                except (json.JSONDecodeError, TypeError):
                    affected = []
            check_outs.append(ComplianceCheckOut(
                id=c.id,
                framework=c.framework,
                control_id=c.control_id,
                control_title=sanitize_azure_text(c.control_title),
                status=c.status,
                evidence=sanitize_optional_azure_text(c.evidence),
                affected_rule_ids=affected,
            ))

        summaries.append(ComplianceSummary(
            framework=fw,
            total_controls=len(fw_checks),
            passed=passed,
            failed=failed,
            not_applicable=na,
            checks=check_outs,
        ))

    return summaries


@router.get("/audit/{audit_id}/compliance", response_model=list[ComplianceSummary], dependencies=[Depends(read_rate_limit)])
async def get_compliance(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[ComplianceSummary]:
    """Get compliance summary for an audit, grouped by framework."""
    try:
        uuid.UUID(audit_id)
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid audit_id format")
    # Verify audit exists
    report = await db.get(AuditReport, audit_id)
    if not report:
        raise HTTPException(404, "Audit not found")

    # Check if compliance checks already exist
    existing = await db.execute(
        select(ComplianceCheck).where(ComplianceCheck.audit_id == audit_id)
    )
    checks = list(existing.scalars().all())

    if checks:
        return _build_summaries(checks)

    # Run compliance engine on the ruleset's rules
    ruleset = await db.get(RuleSet, report.ruleset_id)
    if not ruleset:
        raise HTTPException(404, "Ruleset not found for this audit")

    result = await db.execute(
        select(Rule).where(Rule.ruleset_id == ruleset.id)
    )
    db_rules = result.scalars().all()
    for r in db_rules:
        r.ruleset = ruleset

    normalized = [_db_rule_to_normalized(r) for r in db_rules]

    engine = get_compliance_engine()
    results = engine.run(normalized)

    # Store results in DB
    new_checks: list[ComplianceCheck] = []
    for cr in results:
        check = ComplianceCheck(
            audit_id=audit_id,
            framework=cr.framework,
            control_id=cr.control_id,
            control_title=sanitize_azure_text(cr.control_title),
            status=cr.status,
            evidence=sanitize_optional_azure_text(cr.evidence),
            affected_rule_ids=json.dumps(cr.affected_rule_ids) if cr.affected_rule_ids else None,
        )
        db.add(check)
        new_checks.append(check)

    await db.commit()
    # Refresh to get generated IDs
    for c in new_checks:
        await db.refresh(c)

    return _build_summaries(new_checks)
