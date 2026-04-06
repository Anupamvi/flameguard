"""Service layer for natural-language rule generation."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.config import settings
from app.llm.client import ClaudeClient
from app.llm.prompts.generate import (
    SYSTEM_GENERATE,
    USER_GENERATE_TEMPLATE,
    VENDOR_SCHEMA_HINTS,
)
from app.llm.response_parser import parse_generate_response
from app.parsers.base import ParserRegistry, VendorType

logger = logging.getLogger(__name__)

# Mapping from raw vendor strings to the containers parsers expect.
# Each parser's parse() expects the generated config wrapped in a structure
# it can traverse via its _extract_* helpers.
_VENDOR_CONTAINERS: dict[VendorType, callable] = {
    VendorType.AZURE_FIREWALL: lambda cfg: {
        "type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
        "properties": {
            "priority": 200,
            "ruleCollections": [
                {
                    "name": "generated-collection",
                    "priority": 1000,
                    "action": {"type": cfg.get("action", "Deny")},
                    "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                    "rules": [cfg],
                }
            ],
        },
    },
    VendorType.AZURE_NSG: lambda cfg: {
        "type": "Microsoft.Network/networkSecurityGroups",
        "properties": {
            "securityRules": [cfg] if "properties" in cfg else [{"name": cfg.get("name", "rule"), "properties": cfg}],
        },
    },
    VendorType.AZURE_WAF: lambda cfg: {
        "type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
        "properties": {
            "customRules": [cfg],
        },
    },
}


async def generate_rule(
    intent: str,
    vendor: str,
    context: str | None = None,
) -> dict[str, Any]:
    """Generate a firewall rule config from natural-language intent.

    Returns
    -------
    dict with keys: config, explanation, warnings, is_valid
    """
    # --- Validate vendor ---
    try:
        vendor_type = VendorType(vendor)
    except ValueError:
        valid = [v.value for v in VendorType]
        raise ValueError(f"Unknown vendor '{vendor}'. Valid vendors: {valid}")

    # Ensure a parser is registered for this vendor
    ParserRegistry.get(vendor_type)

    # --- Build prompt ---
    schema_hint = VENDOR_SCHEMA_HINTS.get(vendor, "No schema hint available.")
    user_prompt = USER_GENERATE_TEMPLATE.format(
        vendor=vendor,
        intent=intent,
        context=context or "None",
        vendor_schema_hint=schema_hint,
    )

    # --- Call LLM ---
    if settings.llm_provider == "azure" and not settings.azure_api_key:
        raise RuntimeError("AZURE_API_KEY is not configured")
    if settings.llm_provider == "openai" and not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")

    llm = ClaudeClient()
    raw_response = await llm.analyze(
        system=SYSTEM_GENERATE,
        user=user_prompt,
        response_format={"type": "json_object"},
    )

    # --- Parse response ---
    parsed = parse_generate_response(raw_response)
    config = parsed["config"]
    explanation = parsed["explanation"]
    warnings = parsed["warnings"]

    # --- Round-trip validation ---
    is_valid = False
    try:
        parser = ParserRegistry.get(vendor_type)
        container_fn = _VENDOR_CONTAINERS.get(vendor_type)
        if container_fn:
            wrapped = container_fn(config)
            normalized = parser.parse(wrapped)
            is_valid = len(normalized) > 0
        else:
            is_valid = False
            warnings.append("Round-trip validation not available for this vendor.")
    except Exception as exc:
        logger.warning("Round-trip validation failed: %s", exc)
        warnings.append(f"Round-trip validation failed: {exc}")

    return {
        "config": config,
        "explanation": explanation,
        "warnings": warnings,
        "is_valid": is_valid,
    }
