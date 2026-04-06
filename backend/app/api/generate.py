"""POST /generate and /rules/generate -- natural-language to firewall rule."""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

from app.schemas.generate import (
    FrontendRuleGenRequest,
    FrontendRuleGenResponse,
    RuleGenRequest,
    RuleGenResponse,
)
from app.services.generate_service import generate_rule as generate_rule_from_intent

router = APIRouter()

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


@router.post("/generate", response_model=RuleGenResponse)
async def generate_rule_endpoint(request: RuleGenRequest) -> RuleGenResponse:
    """Generate a firewall rule from a natural-language intent."""
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


@router.post("/rules/generate", response_model=FrontendRuleGenResponse)
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
    )
