import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.rule import Rule, RuleSet
from app.schemas.rule import RuleExplainResponse, RuleOut

router = APIRouter()


def _rule_to_out(rule: Rule) -> RuleOut:
    def _parse_json_list(val: str | None) -> list[str]:
        if not val:
            return []
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return []

    def _parse_json_dict(val: str | None) -> dict[str, str]:
        if not val:
            return {}
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return {}

    # Get vendor from the ruleset
    vendor = ""
    if rule.ruleset:
        vendor = rule.ruleset.vendor

    return RuleOut(
        id=rule.id,
        original_id=rule.original_id or "",
        name=rule.name,
        vendor=vendor,
        action=rule.action,
        direction=rule.direction,
        protocol=rule.protocol,
        source_addresses=_parse_json_list(rule.source_addresses),
        source_ports=_parse_json_list(rule.source_ports),
        destination_addresses=_parse_json_list(rule.dest_addresses),
        destination_ports=_parse_json_list(rule.dest_ports),
        priority=rule.priority,
        collection_name=rule.collection_name,
        collection_priority=rule.collection_priority,
        description=rule.description or "",
        enabled=rule.enabled,
        risk_score=rule.risk_score,
        tags=_parse_json_dict(rule.tags),
    )


@router.get("/rulesets/{ruleset_id}/rules", response_model=list[RuleOut])
async def list_rules(
    ruleset_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[RuleOut]:
    """List all parsed rules in a ruleset."""
    try:
        uuid.UUID(ruleset_id)
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid ruleset_id format")
    # Verify ruleset exists
    rs = await db.get(RuleSet, ruleset_id)
    if not rs:
        raise HTTPException(404, "Ruleset not found")

    result = await db.execute(
        select(Rule).where(Rule.ruleset_id == ruleset_id).order_by(Rule.priority.asc().nullslast())
    )
    rules = result.scalars().all()

    # Need to set ruleset for vendor
    for r in rules:
        r.ruleset = rs

    return [_rule_to_out(r) for r in rules]


@router.get("/rules/{rule_id}/explain", response_model=RuleExplainResponse)
async def explain_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
) -> RuleExplainResponse:
    """Get an AI-generated plain-English explanation of a rule."""
    try:
        uuid.UUID(rule_id)
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid rule_id format")
    from app.llm.client import ClaudeClient
    from app.llm.prompts.explain import SYSTEM_EXPLAIN, USER_EXPLAIN_TEMPLATE
    from app.llm.response_parser import parse_explain_response

    rule = await db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")

    # Load ruleset for vendor info
    ruleset = await db.get(RuleSet, rule.ruleset_id)
    if not ruleset:
        raise HTTPException(404, "Ruleset not found")
    rule.ruleset = ruleset

    rule_out = _rule_to_out(rule)
    rule_json = json.dumps(rule_out.model_dump(), indent=2)

    # Grab a few nearby rules for context (same ruleset, nearby priority)
    result = await db.execute(
        select(Rule)
        .where(Rule.ruleset_id == rule.ruleset_id, Rule.id != rule_id)
        .order_by(Rule.priority.asc().nullslast())
        .limit(5)
    )
    context_rules = result.scalars().all()
    for r in context_rules:
        r.ruleset = ruleset
    context_json = json.dumps([_rule_to_out(r).model_dump() for r in context_rules], indent=2)

    try:
        llm = ClaudeClient()
    except RuntimeError as e:
        raise HTTPException(503, str(e))

    user_prompt = USER_EXPLAIN_TEMPLATE.format(
        vendor=ruleset.vendor,
        rule_json=rule_json,
        context_rules_json=context_json,
    )

    raw = await llm.analyze(system=SYSTEM_EXPLAIN, user=user_prompt)
    parsed = parse_explain_response(raw)

    return RuleExplainResponse(
        rule_id=rule_id,
        explanation=parsed["explanation"],
        concerns=parsed["concerns"],
    )
