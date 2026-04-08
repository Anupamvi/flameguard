"""Service layer for natural-language rule generation."""

from __future__ import annotations

import json
import logging
import re
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

_SOURCE_RANGE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_SCOPED_SOURCE_HINTS = (
    "except from",
    "except for",
    "only from",
    "allow only from",
    "restricted to",
    "limit to",
)


def _extract_intent_source_ranges(intent: str) -> list[str]:
    seen: list[str] = []
    for match in _SOURCE_RANGE_RE.findall(intent):
        if match not in seen:
            seen.append(match)
    return seen


def _nsg_properties(config: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(config, dict):
        return None
    properties = config.get("properties")
    if isinstance(properties, dict):
        return properties
    return config


def _read_nsg_sources(props: dict[str, Any]) -> list[str]:
    plural = props.get("sourceAddressPrefixes")
    if isinstance(plural, list) and plural:
        return [str(value) for value in plural]
    singular = props.get("sourceAddressPrefix")
    if isinstance(singular, str) and singular:
        return [singular]
    return ["*"]


def _write_nsg_sources(props: dict[str, Any], sources: list[str]) -> None:
    if len(sources) <= 1:
        props["sourceAddressPrefix"] = sources[0] if sources else "*"
        props["sourceAddressPrefixes"] = []
        return

    props["sourceAddressPrefix"] = ""
    props["sourceAddressPrefixes"] = sources


def _rewrite_name_for_allow(name: Any) -> Any:
    if not isinstance(name, str) or not name:
        return name

    normalized = name
    replacements = (
        ("deny-", "allow-"),
        ("block-", "allow-"),
        ("deny_", "allow_"),
        ("block_", "allow_"),
    )
    lower_name = normalized.lower()
    for prefix, replacement in replacements:
        if lower_name.startswith(prefix):
            return replacement + normalized[len(prefix):]
    return normalized


def _apply_nsg_source_scope_guardrail(intent: str, config: dict[str, Any], warnings: list[str]) -> None:
    intent_lower = intent.lower()
    if not any(hint in intent_lower for hint in _SCOPED_SOURCE_HINTS):
        return

    sources = _extract_intent_source_ranges(intent)
    if not sources:
        return

    props = _nsg_properties(config)
    if props is None:
        return

    direction = str(props.get("direction", "Inbound")).lower()
    if direction != "inbound":
        return

    current_sources = _read_nsg_sources(props)
    current_access = str(props.get("access", "Allow")).lower()
    needs_source_fix = current_sources == ["*"] or any(source not in current_sources for source in sources)
    needs_access_fix = current_access == "deny"

    if not needs_source_fix and not needs_access_fix:
        return

    _write_nsg_sources(props, sources)
    if needs_access_fix:
        props["access"] = "Allow"
        config["name"] = _rewrite_name_for_allow(config.get("name"))

    warnings.append(
        "Adjusted the NSG rule to allow only the requested source range because an inbound deny rule with a wildcard source would block the exception traffic too. Azure NSGs rely on lower-priority or default deny rules to block all other sources."
    )


def _apply_generation_guardrails(vendor_type: VendorType, intent: str, config: dict[str, Any], warnings: list[str]) -> None:
    if vendor_type == VendorType.AZURE_NSG:
        _apply_nsg_source_scope_guardrail(intent, config, warnings)


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
    warnings = list(parsed["warnings"])

    _apply_generation_guardrails(vendor_type, intent, config, warnings)

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
