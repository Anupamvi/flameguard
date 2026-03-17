from __future__ import annotations

from typing import Any

from app.parsers.base import (
    BaseParser,
    NormalizedRule,
    ParserRegistry,
    RuleAction,
    RuleDirection,
    VendorType,
)


@ParserRegistry.register
class AzureWAFParser(BaseParser):
    """Parser for Azure WAF Policy configurations (custom rules only).

    Handles:
    - App Gateway WAF: Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies
    - Front Door WAF: Microsoft.Network/FrontDoorWebApplicationFirewallPolicies
    - ARM templates containing either resource type

    Phase 1 scope: custom rules only. Managed rule set overrides deferred to Phase 2.
    """

    vendor = VendorType.AZURE_WAF

    _APPGW_TYPE = "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
    _FD_TYPE = "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies"

    def can_parse(self, data: dict[str, Any]) -> bool:
        rtype = data.get("type", "")
        if rtype in (self._APPGW_TYPE, self._FD_TYPE):
            return True
        for r in data.get("resources", []):
            if r.get("type") in (self._APPGW_TYPE, self._FD_TYPE):
                return True
        return False

    def parse(self, data: dict[str, Any]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []
        for waf_resource in self._extract_waf_resources(data):
            props = waf_resource.get("properties", {})
            waf_type = waf_resource.get("type", self._APPGW_TYPE)

            for custom_rule in props.get("customRules", []):
                rule = self._parse_custom_rule(custom_rule, waf_type)
                if rule:
                    rules.append(rule)

        return rules

    def generate(self, normalized: NormalizedRule) -> dict[str, Any]:
        action_map = {
            RuleAction.ALLOW: "Allow",
            RuleAction.DENY: "Block",
            RuleAction.LOG: "Log",
        }
        match_conditions = []
        if normalized.source_addresses and normalized.source_addresses != ["*"]:
            match_conditions.append({
                "matchVariables": [{"variableName": "RemoteAddr", "selector": None}],
                "operator": "IPMatch",
                "negationConditon": False,
                "matchValues": normalized.source_addresses,
                "transforms": [],
            })
        if normalized.destination_ports and normalized.destination_ports != ["*"]:
            match_conditions.append({
                "matchVariables": [{"variableName": "RequestUri", "selector": None}],
                "operator": "Contains",
                "negationConditon": False,
                "matchValues": normalized.destination_ports,
                "transforms": ["Lowercase"],
            })

        if not match_conditions:
            match_conditions.append({
                "matchVariables": [{"variableName": "RemoteAddr", "selector": None}],
                "operator": "IPMatch",
                "negationConditon": True,
                "matchValues": ["127.0.0.1"],
                "transforms": [],
            })

        return {
            "name": normalized.name,
            "priority": normalized.priority or 100,
            "ruleType": "MatchRule",
            "state": "Enabled" if normalized.enabled else "Disabled",
            "action": action_map.get(normalized.action, "Block"),
            "matchConditions": match_conditions,
        }

    # ── Internals ──

    def _extract_waf_resources(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        rtype = data.get("type", "")
        if rtype in (self._APPGW_TYPE, self._FD_TYPE):
            return [data]
        return [r for r in data.get("resources", []) if r.get("type") in (self._APPGW_TYPE, self._FD_TYPE)]

    def _parse_custom_rule(self, rule: dict[str, Any], waf_type: str) -> NormalizedRule | None:
        name = rule.get("name", "")
        action_raw = rule.get("action", "Block").lower()
        state = rule.get("state", "Enabled")
        rule_type = rule.get("ruleType", "MatchRule")

        # Map WAF actions
        action_map = {"allow": RuleAction.ALLOW, "block": RuleAction.DENY, "log": RuleAction.LOG}
        action = action_map.get(action_raw, RuleAction.DENY)

        # Extract source IPs and match details from conditions
        source_addresses: list[str] = []
        match_details: list[str] = []
        all_match_values: list[str] = []

        for mc in rule.get("matchConditions", []):
            variables = mc.get("matchVariables", [])
            operator = mc.get("operator", "")
            negation = mc.get("negationConditon", False)
            values = mc.get("matchValues", [])
            transforms = mc.get("transforms", [])

            var_names = [v.get("variableName", "") for v in variables]
            selectors = [v.get("selector", "") for v in variables if v.get("selector")]

            # Track source addresses
            if "RemoteAddr" in var_names and operator == "IPMatch" and not negation:
                source_addresses.extend(values)

            # Build human-readable match detail
            neg_prefix = "NOT " if negation else ""
            var_str = ", ".join(var_names)
            sel_str = f"[{', '.join(selectors)}]" if selectors else ""
            trans_str = f" (transforms: {', '.join(transforms)})" if transforms else ""
            detail = f"{var_str}{sel_str} {neg_prefix}{operator} {values[:3]}{'...' if len(values) > 3 else ''}{trans_str}"
            match_details.append(detail)
            all_match_values.extend(values)

        # WAF is always inbound
        tags: dict[str, str] = {
            "rule_type": rule_type,
            "waf_type": "appgw" if "ApplicationGateway" in waf_type else "frontdoor",
            "match_conditions": "; ".join(match_details),
        }

        if rule_type == "RateLimitRule":
            tags["rate_limit_duration"] = rule.get("rateLimitDuration", "")
            tags["rate_limit_threshold"] = str(rule.get("rateLimitThreshold", ""))

        return NormalizedRule(
            original_id=name,
            name=name,
            vendor=VendorType.AZURE_WAF,
            action=action,
            direction=RuleDirection.INBOUND,
            protocol="HTTP/HTTPS",
            source_addresses=source_addresses if source_addresses else ["*"],
            source_ports=["*"],
            destination_addresses=["*"],  # WAF protects the app behind it
            destination_ports=["80", "443"],
            priority=rule.get("priority"),
            description=f"WAF {rule_type}: {'; '.join(match_details)}",
            enabled=state == "Enabled",
            raw_json=rule,
            tags=tags,
        )
