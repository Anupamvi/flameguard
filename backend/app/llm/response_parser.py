"""Parse and validate JSON responses from Claude."""

from __future__ import annotations

import json
import re
from typing import Any

# Keys required on every finding object
_REQUIRED_FINDING_KEYS = {
    "category",
    "severity",
    "title",
    "description",
    "affected_rules",
    "recommendation",
    "confidence",
}

_VALID_CATEGORIES = {"shadowed", "overly_permissive", "contradictory", "unused", "best_practice"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _strip_markdown_fences(text: str) -> str:
    """Remove ```json ... ``` or ``` ... ``` wrappers if present."""
    text = text.strip()
    # Match ```json\n...\n``` or ```\n...\n```
    m = re.match(r"^```(?:json)?\s*\n?(.*?)\n?\s*```$", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return text


def parse_audit_response(raw: str) -> list[dict[str, Any]]:
    """Parse an audit response from Claude into a list of finding dicts.

    Handles markdown fences, extracts the ``findings`` array, and validates
    required keys on each finding.

    Returns
    -------
    list[dict]
        Validated finding dicts.

    Raises
    ------
    ValueError
        If the response cannot be parsed or is structurally invalid.
    """
    cleaned = _strip_markdown_fences(raw)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"Claude response is not valid JSON: {e}\nRaw: {cleaned[:500]}")

    # Accept either {"findings": [...]} or bare [...]
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("findings")
        if findings is None:
            raise ValueError(
                f"Expected a 'findings' key in the response. Keys found: {list(data.keys())}"
            )
    else:
        raise ValueError(f"Unexpected response type: {type(data).__name__}")

    if not isinstance(findings, list):
        raise ValueError(f"'findings' must be an array, got {type(findings).__name__}")

    validated: list[dict[str, Any]] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue  # skip malformed entries

        missing = _REQUIRED_FINDING_KEYS - set(f.keys())
        if missing:
            # Attempt to salvage -- fill missing optional fields with defaults
            for key in missing:
                if key == "confidence":
                    f["confidence"] = 0.5
                elif key == "recommendation":
                    f["recommendation"] = ""
                elif key == "affected_rules":
                    f["affected_rules"] = []
                else:
                    # Truly required field missing -- skip this finding
                    break
            else:
                missing = _REQUIRED_FINDING_KEYS - set(f.keys())

        if missing:
            continue

        # Normalize enums
        f["category"] = str(f["category"]).lower().strip()
        f["severity"] = str(f["severity"]).lower().strip()

        if f["category"] not in _VALID_CATEGORIES:
            f["category"] = "best_practice"
        if f["severity"] not in _VALID_SEVERITIES:
            f["severity"] = "medium"

        # Clamp confidence
        try:
            f["confidence"] = max(0.0, min(1.0, float(f["confidence"])))
        except (TypeError, ValueError):
            f["confidence"] = 0.5

        # Ensure affected_rules is a list of strings
        if not isinstance(f["affected_rules"], list):
            f["affected_rules"] = [str(f["affected_rules"])]
        f["affected_rules"] = [str(r) for r in f["affected_rules"]]

        validated.append(f)

    return validated


def parse_risk_response(raw: str) -> dict[str, Any]:
    """Parse the risk-scoring / executive-summary response."""
    cleaned = _strip_markdown_fences(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"Risk response is not valid JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object for the risk response")

    return {
        "executive_summary": data.get("executive_summary", ""),
        "risk_level": data.get("risk_level", "medium"),
        "top_concerns": data.get("top_concerns", []),
    }


def parse_explain_response(raw: str) -> dict[str, Any]:
    """Parse an explain-rule response."""
    cleaned = _strip_markdown_fences(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"Explain response is not valid JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object for the explain response")

    return {
        "explanation": data.get("explanation", ""),
        "concerns": data.get("concerns", []),
    }


def parse_generate_response(raw: str) -> dict[str, Any]:
    """Parse a rule-generation response from Claude.

    Expects Claude to return JSON (possibly wrapped in markdown fences).
    The response may be:
    - A bare config object (the generated vendor rule JSON)
    - A wrapper: {"config": {...}, "explanation": "...", "warnings": [...]}

    Returns
    -------
    dict with keys: config (dict), explanation (str), warnings (list[str])
    """
    cleaned = _strip_markdown_fences(raw)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"Generate response is not valid JSON: {e}\nRaw: {cleaned[:500]}")

    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object, got {type(data).__name__}")

    # If the response has an explicit "config" key, use the structured format
    if "config" in data:
        config = data["config"]
        explanation = data.get("explanation", "")
        warnings = data.get("warnings", [])
    else:
        # Treat the entire object as the config (Claude returned just the rule JSON)
        config = data
        explanation = ""
        warnings = []

    if not isinstance(config, dict):
        raise ValueError(f"'config' must be a JSON object, got {type(config).__name__}")

    if not isinstance(warnings, list):
        warnings = [str(warnings)]
    else:
        warnings = [str(w) for w in warnings]

    return {
        "config": config,
        "explanation": str(explanation),
        "warnings": warnings,
    }
