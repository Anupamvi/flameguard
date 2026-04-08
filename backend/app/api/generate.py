"""POST /generate and /rules/generate -- natural-language to vendor policy rule."""

import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

logger = logging.getLogger(__name__)

from app.database import get_db
from app.models.audit import AuditFinding, AuditReport
from app.models.rule import Rule
from app.privacy import sanitize_azure_text, sanitize_optional_azure_text
from app.schemas.generate import (
    FrontendRuleGenRequest,
    FrontendRuleGenResponse,
    RuleGenRequest,
    RuleGenResponse,
)
from app.security import generation_rate_limit
from app.services.generate_service import generate_rule as generate_rule_from_intent

router = APIRouter()

_GENERATION_CONTEXT_RULE_LIMIT = 8

_VENDOR_ALIASES = {
    "azure nsg": "azure_nsg",
    "nsg": "azure_nsg",
    "azure firewall": "azure_firewall",
    "firewall": "azure_firewall",
    "azure waf": "azure_waf",
    "waf": "azure_waf",
}


def _normalize_vendor(vendor: str) -> str:
    normalized = vendor.strip().lower().replace("_", " ").replace("-", " ")
    return _VENDOR_ALIASES.get(normalized, normalized.replace(" ", "_"))


def _build_explanation(result: dict[str, Any], vendor: str) -> str:
    explanation = result["explanation"].strip()
    if explanation:
        return explanation

    normalized_vendor = vendor.replace("_", " ").upper()
    if result["is_valid"]:
        return (
            f"Generated a {normalized_vendor} rule from the provided description and "
            "validated that it can be parsed back into FlameGuard's normalized rule format."
        )

    return (
        f"Generated a {normalized_vendor} rule from the provided description, but FlameGuard "
        "could not fully validate the result. Review the JSON before applying it."
    )


def _build_confidence(result: dict[str, Any]) -> float:
    if result["is_valid"] and not result["warnings"]:
        return 0.95
    if result["is_valid"]:
        return 0.85
    if not result["warnings"]:
        return 0.7
    return 0.55


async def _run_generation(intent: str, vendor: str, context: str | None = None) -> tuple[str, dict[str, Any]]:
    normalized_vendor = _normalize_vendor(vendor)

    try:
        result = await generate_rule_from_intent(
            intent=intent,
            vendor=normalized_vendor,
            context=context,
        )
    except RuntimeError as exc:
        logger.error("Rule generation service error: %s", exc)
        raise HTTPException(status_code=503, detail="Rule generation service is temporarily unavailable")
    except ValueError as exc:
        logger.warning("Rule generation ValueError: %s", exc)
        message = str(exc)
        if message.startswith("Unknown vendor"):
            detail = message
        elif (
            "Generate response is not valid JSON" in message
            or "Expected a JSON object" in message
            or "'config' must be a JSON object" in message
            or "LLM returned empty content" in message
        ):
            detail = "Generation failed: the model returned an invalid rule payload. Please try again."
        else:
            detail = f"Generation failed: {message}"
        raise HTTPException(status_code=400, detail=detail)

    return normalized_vendor, result


def _validate_uuid(value: str, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail=f"Invalid {name} format")


def _parse_json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _finding_related_rule_ids(finding: AuditFinding) -> list[str]:
    related_rule_ids = _parse_json_list(finding.related_rule_ids)
    if finding.rule_id and finding.rule_id not in related_rule_ids:
        related_rule_ids.insert(0, finding.rule_id)
    return related_rule_ids


def _rule_generation_summary(rule: Rule) -> dict[str, Any]:
    return {
        "name": sanitize_azure_text(rule.name),
        "action": rule.action,
        "direction": rule.direction,
        "protocol": rule.protocol or "Any",
        "source_addresses": _parse_json_list(rule.source_addresses),
        "source_ports": _parse_json_list(rule.source_ports),
        "destination_addresses": _parse_json_list(rule.dest_addresses),
        "destination_ports": _parse_json_list(rule.dest_ports),
        "priority": rule.priority,
        "collection_name": sanitize_optional_azure_text(rule.collection_name),
        "description": sanitize_optional_azure_text(rule.description),
    }


def _build_finding_generation_inputs(
    report: AuditReport,
    finding: AuditFinding,
    related_rules: list[Rule],
    total_related_rules: int,
) -> tuple[str, str]:
    safe_title = sanitize_azure_text(finding.title)
    safe_description = sanitize_azure_text(finding.description)
    safe_recommendation = sanitize_optional_azure_text(finding.recommendation)

    intent_parts = [
        f"Generate a safer {report.ruleset.vendor.replace('_', ' ')} rule that remediates this audit finding.",
        f"Finding: {safe_title}.",
        safe_description,
    ]
    if safe_recommendation:
        intent_parts.append(f"Recommended action: {safe_recommendation}.")

    context_parts = [
        f"Requested severity: {finding.severity}",
        f"Category: {finding.category}",
        f"Audit filename: {sanitize_azure_text(report.ruleset.filename)}",
        f"Finding title: {safe_title}",
        f"Finding description: {safe_description}",
        f"Finding recommendation: {safe_recommendation or 'None provided'}",
    ]
    if total_related_rules:
        context_parts.append(f"Affected rule count: {total_related_rules}")
    if related_rules:
        context_parts.append("Representative affected rules:")
        context_parts.append(json.dumps([_rule_generation_summary(rule) for rule in related_rules], indent=2))
    context_parts.append(
        "Generate one safer replacement or compensating rule that addresses the risky pattern above while preserving legitimate traffic where possible."
    )
    context_parts.append(
        "Prefer durable matching criteria over fixed attacker IPs when the finding indicates brittle IP-based blocking or attacker IP churn."
    )

    intent = " ".join(part.strip() for part in intent_parts if part and part.strip())
    return intent, "\n".join(context_parts)


@router.post("/generate", response_model=RuleGenResponse, dependencies=[Depends(generation_rate_limit)])
async def generate_rule_endpoint(request: RuleGenRequest) -> RuleGenResponse:
    """Generate a vendor policy rule from a natural-language intent."""
    normalized_vendor, result = await _run_generation(
        intent=request.intent,
        vendor=request.vendor,
        context=request.context,
    )

    return RuleGenResponse(
        config=result["config"],
        explanation=_build_explanation(result, normalized_vendor),
        warnings=result["warnings"],
        is_valid=result["is_valid"],
    )


@router.post("/rules/generate", response_model=FrontendRuleGenResponse, dependencies=[Depends(generation_rate_limit)])
async def generate_rule_for_frontend(request: FrontendRuleGenRequest) -> FrontendRuleGenResponse:
    """Generate a rule using the request/response contract expected by the dashboard UI."""
    context = f"Requested severity: {request.severity}\nCategory: {request.category.strip() or 'general'}"
    normalized_vendor, result = await _run_generation(
        intent=request.description,
        vendor=request.vendor,
        context=context,
    )

    return FrontendRuleGenResponse(
        rule=result["config"],
        explanation=_build_explanation(result, normalized_vendor),
        confidence=_build_confidence(result),
        warnings=result["warnings"],
    )


@router.post(
    "/audit/{audit_id}/findings/{finding_id}/generate-rule",
    response_model=FrontendRuleGenResponse,
    dependencies=[Depends(generation_rate_limit)],
)
async def generate_rule_from_audit_finding(
    audit_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> FrontendRuleGenResponse:
    _validate_uuid(audit_id, "audit_id")
    _validate_uuid(finding_id, "finding_id")

    result = await db.execute(
        select(AuditReport)
        .options(selectinload(AuditReport.findings))
        .options(selectinload(AuditReport.ruleset))
        .where(AuditReport.id == audit_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Audit not found")
    if report.ruleset is None:
        raise HTTPException(status_code=404, detail="Ruleset not found for audit")

    finding = next((item for item in report.findings if item.id == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found for audit")

    related_rule_ids = _finding_related_rule_ids(finding)
    related_rule_count = len(related_rule_ids)

    rule_query = select(Rule).where(Rule.ruleset_id == report.ruleset_id)
    if related_rule_ids:
        rule_query = rule_query.where(Rule.id.in_(related_rule_ids))

    rules_result = await db.execute(
        rule_query.order_by(Rule.priority.asc().nullslast(), Rule.name.asc()).limit(_GENERATION_CONTEXT_RULE_LIMIT)
    )
    related_rules = list(rules_result.scalars().all())

    intent, context = _build_finding_generation_inputs(
        report,
        finding,
        related_rules,
        related_rule_count,
    )
    normalized_vendor, result = await _run_generation(
        intent=intent,
        vendor=report.ruleset.vendor,
        context=context,
    )

    return FrontendRuleGenResponse(
        rule=result["config"],
        explanation=_build_explanation(result, normalized_vendor),
        confidence=_build_confidence(result),
        warnings=result["warnings"],
    )
