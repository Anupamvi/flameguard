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
class AzureFirewallParser(BaseParser):
    """Parser for Azure Firewall configurations.

    Handles:
    - Modern: Microsoft.Network/firewallPolicies/ruleCollectionGroups
    - Classic: Microsoft.Network/azureFirewalls
    - ARM templates containing either resource type
    """

    vendor = VendorType.AZURE_FIREWALL

    _POLICY_RCG_TYPE = "Microsoft.Network/firewallPolicies/ruleCollectionGroups"
    _CLASSIC_TYPE = "Microsoft.Network/azureFirewalls"

    def can_parse(self, data: dict[str, Any]) -> bool:
        rtype = data.get("type", "")
        if rtype in (self._POLICY_RCG_TYPE, self._CLASSIC_TYPE):
            return True
        for r in data.get("resources", []):
            if r.get("type") in (self._POLICY_RCG_TYPE, self._CLASSIC_TYPE):
                return True
        # Array of rule collection groups
        if isinstance(data.get("value"), list):
            return any(v.get("type") == self._POLICY_RCG_TYPE for v in data["value"])
        return False

    def parse(self, data: dict[str, Any]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []

        # Direct resource
        rtype = data.get("type", "")
        if rtype == self._POLICY_RCG_TYPE:
            rules.extend(self._parse_rcg(data))
        elif rtype == self._CLASSIC_TYPE:
            rules.extend(self._parse_classic(data))
        else:
            # ARM template or list response
            for r in data.get("resources", data.get("value", [])):
                rt = r.get("type", "")
                if rt == self._POLICY_RCG_TYPE:
                    rules.extend(self._parse_rcg(r))
                elif rt == self._CLASSIC_TYPE:
                    rules.extend(self._parse_classic(r))

        return rules

    def generate(self, normalized: NormalizedRule) -> dict[str, Any]:
        return {
            "ruleType": "NetworkRule",
            "name": normalized.name,
            "description": normalized.description,
            "ipProtocols": [normalized.protocol] if normalized.protocol != "Any" else ["Any"],
            "sourceAddresses": normalized.source_addresses or ["*"],
            "sourceIpGroups": [],
            "destinationAddresses": normalized.destination_addresses or ["*"],
            "destinationIpGroups": [],
            "destinationFqdns": [],
            "destinationPorts": normalized.destination_ports or ["*"],
        }

    # ── Modern policy format ──

    def _parse_rcg(self, rcg: dict[str, Any]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []
        props = rcg.get("properties", {})
        group_priority = props.get("priority", 0)
        group_name = rcg.get("name", "")

        for rc in props.get("ruleCollections", []):
            rc_name = rc.get("name", "")
            rc_priority = rc.get("priority", 0)
            rc_action_raw = rc.get("action", {}).get("type", "Deny")
            rc_type = rc.get("ruleCollectionType", "")

            for rule_data in rc.get("rules", []):
                rule_type = rule_data.get("ruleType", "")
                if rule_type == "NetworkRule":
                    rules.extend(self._parse_network_rule(
                        rule_data, rc_action_raw, rc_name, rc_priority, group_name, group_priority
                    ))
                elif rule_type == "ApplicationRule":
                    rules.extend(self._parse_application_rule(
                        rule_data, rc_action_raw, rc_name, rc_priority, group_name, group_priority
                    ))
                elif rule_type == "NatRule":
                    rules.extend(self._parse_nat_rule(
                        rule_data, rc_name, rc_priority, group_name, group_priority
                    ))

        return rules

    def _parse_network_rule(
        self, rule: dict[str, Any], action: str,
        rc_name: str, rc_priority: int, group_name: str, group_priority: int,
    ) -> list[NormalizedRule]:
        protocols = rule.get("ipProtocols", ["Any"])
        proto_str = "/".join(protocols) if len(protocols) > 1 else protocols[0] if protocols else "Any"

        return [NormalizedRule(
            original_id=rule.get("name", ""),
            name=rule.get("name", ""),
            vendor=VendorType.AZURE_FIREWALL,
            action=RuleAction(action.lower()),
            direction=RuleDirection.BOTH,  # Firewall rules are bidirectional by nature
            protocol=proto_str,
            source_addresses=rule.get("sourceAddresses", []) + rule.get("sourceIpGroups", []),
            source_ports=["*"],  # Azure Firewall doesn't filter on source ports for network rules
            destination_addresses=rule.get("destinationAddresses", []) + rule.get("destinationFqdns", []) + rule.get("destinationIpGroups", []),
            destination_ports=rule.get("destinationPorts", ["*"]),
            priority=rc_priority,
            collection_name=rc_name,
            collection_priority=group_priority,
            description=rule.get("description", ""),
            enabled=True,
            raw_json=rule,
            tags={"rule_type": "NetworkRule", "group": group_name, "collection": rc_name},
        )]

    def _parse_application_rule(
        self, rule: dict[str, Any], action: str,
        rc_name: str, rc_priority: int, group_name: str, group_priority: int,
    ) -> list[NormalizedRule]:
        protocols = rule.get("protocols", [])
        proto_parts = [f"{p.get('protocolType', 'Https')}:{p.get('port', 443)}" for p in protocols]
        proto_str = "/".join(proto_parts) if proto_parts else "Https:443"

        targets = rule.get("targetFqdns", []) + rule.get("fqdnTags", []) + rule.get("webCategories", [])

        return [NormalizedRule(
            original_id=rule.get("name", ""),
            name=rule.get("name", ""),
            vendor=VendorType.AZURE_FIREWALL,
            action=RuleAction(action.lower()),
            direction=RuleDirection.OUTBOUND,
            protocol=proto_str,
            source_addresses=rule.get("sourceAddresses", []) + rule.get("sourceIpGroups", []),
            source_ports=["*"],
            destination_addresses=targets,
            destination_ports=[str(p.get("port", 443)) for p in protocols] if protocols else ["443"],
            priority=rc_priority,
            collection_name=rc_name,
            collection_priority=group_priority,
            description=rule.get("description", ""),
            enabled=True,
            raw_json=rule,
            tags={"rule_type": "ApplicationRule", "group": group_name, "collection": rc_name},
        )]

    def _parse_nat_rule(
        self, rule: dict[str, Any],
        rc_name: str, rc_priority: int, group_name: str, group_priority: int,
    ) -> list[NormalizedRule]:
        protocols = rule.get("ipProtocols", ["TCP"])
        proto_str = "/".join(protocols) if len(protocols) > 1 else protocols[0] if protocols else "TCP"

        translated = rule.get("translatedAddress", "")
        translated_port = rule.get("translatedPort", "")

        return [NormalizedRule(
            original_id=rule.get("name", ""),
            name=rule.get("name", ""),
            vendor=VendorType.AZURE_FIREWALL,
            action=RuleAction.ALLOW,  # NAT/DNAT is always allow
            direction=RuleDirection.INBOUND,
            protocol=proto_str,
            source_addresses=rule.get("sourceAddresses", []) + rule.get("sourceIpGroups", []),
            source_ports=["*"],
            destination_addresses=rule.get("destinationAddresses", []),
            destination_ports=rule.get("destinationPorts", ["*"]),
            priority=rc_priority,
            collection_name=rc_name,
            collection_priority=group_priority,
            description=rule.get("description", ""),
            enabled=True,
            raw_json=rule,
            tags={
                "rule_type": "NatRule",
                "group": group_name,
                "collection": rc_name,
                "translated_address": translated,
                "translated_port": str(translated_port),
            },
        )]

    # ── Classic firewall format ──

    def _parse_classic(self, fw: dict[str, Any]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []
        props = fw.get("properties", {})

        for rc in props.get("networkRuleCollections", []):
            rc_name = rc.get("name", "")
            rc_priority = rc.get("properties", {}).get("priority", 0)
            rc_action = rc.get("properties", {}).get("action", {}).get("type", "Deny")
            for rule in rc.get("properties", {}).get("rules", []):
                protocols = rule.get("protocols", ["Any"])
                proto_str = "/".join(protocols)
                rules.append(NormalizedRule(
                    original_id=rule.get("name", ""),
                    name=rule.get("name", ""),
                    vendor=VendorType.AZURE_FIREWALL,
                    action=RuleAction(rc_action.lower()),
                    direction=RuleDirection.BOTH,
                    protocol=proto_str,
                    source_addresses=rule.get("sourceAddresses", []),
                    source_ports=["*"],
                    destination_addresses=rule.get("destinationAddresses", []) + rule.get("destinationFqdns", []),
                    destination_ports=rule.get("destinationPorts", ["*"]),
                    priority=rc_priority,
                    collection_name=rc_name,
                    description=rule.get("description", ""),
                    raw_json=rule,
                    tags={"rule_type": "NetworkRule", "format": "classic", "collection": rc_name},
                ))

        for rc in props.get("applicationRuleCollections", []):
            rc_name = rc.get("name", "")
            rc_priority = rc.get("properties", {}).get("priority", 0)
            rc_action = rc.get("properties", {}).get("action", {}).get("type", "Deny")
            for rule in rc.get("properties", {}).get("rules", []):
                protocols = rule.get("protocols", [])
                targets = rule.get("targetFqdns", []) + rule.get("fqdnTags", [])
                rules.append(NormalizedRule(
                    original_id=rule.get("name", ""),
                    name=rule.get("name", ""),
                    vendor=VendorType.AZURE_FIREWALL,
                    action=RuleAction(rc_action.lower()),
                    direction=RuleDirection.OUTBOUND,
                    protocol="/".join(f"{p.get('protocolType', 'Https')}:{p.get('port', 443)}" for p in protocols) or "Https:443",
                    source_addresses=rule.get("sourceAddresses", []),
                    source_ports=["*"],
                    destination_addresses=targets,
                    destination_ports=[str(p.get("port", 443)) for p in protocols] if protocols else ["443"],
                    priority=rc_priority,
                    collection_name=rc_name,
                    description=rule.get("description", ""),
                    raw_json=rule,
                    tags={"rule_type": "ApplicationRule", "format": "classic", "collection": rc_name},
                ))

        for rc in props.get("natRuleCollections", []):
            rc_name = rc.get("name", "")
            rc_priority = rc.get("properties", {}).get("priority", 0)
            for rule in rc.get("properties", {}).get("rules", []):
                protocols = rule.get("protocols", ["TCP"])
                rules.append(NormalizedRule(
                    original_id=rule.get("name", ""),
                    name=rule.get("name", ""),
                    vendor=VendorType.AZURE_FIREWALL,
                    action=RuleAction.ALLOW,
                    direction=RuleDirection.INBOUND,
                    protocol="/".join(protocols),
                    source_addresses=rule.get("sourceAddresses", []),
                    source_ports=["*"],
                    destination_addresses=rule.get("destinationAddresses", []),
                    destination_ports=rule.get("destinationPorts", ["*"]),
                    priority=rc_priority,
                    collection_name=rc_name,
                    description=rule.get("description", ""),
                    raw_json=rule,
                    tags={
                        "rule_type": "NatRule",
                        "format": "classic",
                        "collection": rc_name,
                        "translated_address": rule.get("translatedAddress", ""),
                        "translated_port": str(rule.get("translatedPort", "")),
                    },
                ))

        return rules
