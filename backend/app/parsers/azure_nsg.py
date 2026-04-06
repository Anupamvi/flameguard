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
class AzureNSGParser(BaseParser):
    """Parser for Azure Network Security Group configurations.

    Handles both direct NSG exports (`az network nsg show`) and
    ARM template resources of type Microsoft.Network/networkSecurityGroups.
    """

    vendor = VendorType.AZURE_NSG

    _RESOURCE_TYPE = "Microsoft.Network/networkSecurityGroups"

    def can_parse(self, data: dict[str, Any]) -> bool:
        if data.get("type") == self._RESOURCE_TYPE:
            return True
        # ARM template with resources array
        for r in data.get("resources", []):
            if r.get("type") == self._RESOURCE_TYPE:
                return True
        # Flat Azure CLI export (az network nsg show)
        if "securityRules" in data or "defaultSecurityRules" in data:
            return True
        return False

    def parse(self, data: dict[str, Any]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []
        for nsg in self._extract_nsg_resources(data):
            props = nsg.get("properties", {})
            for sr in props.get("securityRules", []):
                rule = self._parse_rule(sr)
                if rule:
                    rules.append(rule)
            for sr in props.get("defaultSecurityRules", []):
                rule = self._parse_rule(sr, is_default=True)
                if rule:
                    rules.append(rule)
        return rules

    def generate(self, normalized: NormalizedRule) -> dict[str, Any]:
        props: dict[str, Any] = {
            "access": "Allow" if normalized.action == RuleAction.ALLOW else "Deny",
            "direction": "Inbound" if normalized.direction == RuleDirection.INBOUND else "Outbound",
            "protocol": normalized.protocol if normalized.protocol != "Any" else "*",
            "priority": normalized.priority or 100,
        }
        # Source
        if len(normalized.source_addresses) <= 1:
            props["sourceAddressPrefix"] = normalized.source_addresses[0] if normalized.source_addresses else "*"
            props["sourceAddressPrefixes"] = []
        else:
            props["sourceAddressPrefix"] = ""
            props["sourceAddressPrefixes"] = normalized.source_addresses

        # Source ports
        if len(normalized.source_ports) <= 1:
            props["sourcePortRange"] = normalized.source_ports[0] if normalized.source_ports else "*"
            props["sourcePortRanges"] = []
        else:
            props["sourcePortRange"] = ""
            props["sourcePortRanges"] = normalized.source_ports

        # Destination
        if len(normalized.destination_addresses) <= 1:
            props["destinationAddressPrefix"] = normalized.destination_addresses[0] if normalized.destination_addresses else "*"
            props["destinationAddressPrefixes"] = []
        else:
            props["destinationAddressPrefix"] = ""
            props["destinationAddressPrefixes"] = normalized.destination_addresses

        # Destination ports
        if len(normalized.destination_ports) <= 1:
            props["destinationPortRange"] = normalized.destination_ports[0] if normalized.destination_ports else "*"
            props["destinationPortRanges"] = []
        else:
            props["destinationPortRange"] = ""
            props["destinationPortRanges"] = normalized.destination_ports

        if normalized.description:
            props["description"] = normalized.description

        return {"name": normalized.name, "properties": props}

    # ── Internals ──

    def _extract_nsg_resources(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract NSG resource(s) from either direct export or ARM template."""
        if data.get("type") == self._RESOURCE_TYPE:
            # ARM-style with nested properties dict
            if "properties" in data:
                return [data]
            # Flat Azure CLI export (`az network nsg show`) has type but
            # rules sit at the top level instead of under properties.
            return [{"properties": {
                "securityRules": data.get("securityRules", []),
                "defaultSecurityRules": data.get("defaultSecurityRules", []),
            }}]
        arm = [r for r in data.get("resources", []) if r.get("type") == self._RESOURCE_TYPE]
        if arm:
            return arm
        # Flat Azure CLI export without type field
        if "securityRules" in data or "defaultSecurityRules" in data:
            return [{"properties": {
                "securityRules": data.get("securityRules", []),
                "defaultSecurityRules": data.get("defaultSecurityRules", []),
            }}]
        return []

    def _parse_rule(self, sr: dict[str, Any], is_default: bool = False) -> NormalizedRule | None:
        props = sr.get("properties") or sr  # flat CLI exports have props at rule level
        access = props.get("access", "Deny").lower()
        direction = props.get("direction", "Inbound").lower()

        tags: dict[str, str] = {}
        if is_default:
            tags["default_rule"] = "true"

        return NormalizedRule(
            original_id=sr.get("name", ""),
            name=sr.get("name", ""),
            vendor=VendorType.AZURE_NSG,
            action=RuleAction(access),
            direction=RuleDirection(direction),
            protocol=self._normalize_protocol(props.get("protocol", "*")),
            source_addresses=self._coalesce_list(props, "sourceAddressPrefix", "sourceAddressPrefixes"),
            source_ports=self._coalesce_list(props, "sourcePortRange", "sourcePortRanges"),
            destination_addresses=self._coalesce_list(props, "destinationAddressPrefix", "destinationAddressPrefixes"),
            destination_ports=self._coalesce_list(props, "destinationPortRange", "destinationPortRanges"),
            priority=props.get("priority"),
            description=props.get("description", ""),
            enabled=True,
            raw_json=sr,
            tags=tags,
        )

    @staticmethod
    def _coalesce_list(props: dict[str, Any], singular_key: str, plural_key: str) -> list[str]:
        """Azure NSG uses singular when one value, plural array when multiple."""
        plural = props.get(plural_key, [])
        if plural:
            return list(plural)
        singular = props.get(singular_key)
        if singular:
            return [singular]
        return ["*"]

    @staticmethod
    def _normalize_protocol(proto: str) -> str:
        if proto == "*":
            return "Any"
        return proto
