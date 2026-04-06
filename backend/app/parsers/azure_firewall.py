from __future__ import annotations

from ipaddress import ip_address
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
    _LOG_EXPORT_KEYS = ("dnsSamples", "applicationSamples", "diagnosticsSamples")
    _FIREWALL_LOG_TYPES = {
        "AZFWApplicationRule",
        "AZFWDnsQuery",
        "AZFWFatFlow",
        "AZFWFlowTrace",
        "AZFWIdpsSignature",
        "AZFWNatRule",
        "AZFWNetworkRule",
        "AZFWThreatIntel",
        "AzureDiagnostics",
    }

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
        if self._contains_firewall_log_rows(self._extract_log_rows(data)):
            return True
        if self._looks_like_log_export(data):
            return True
        return False

    def parse(self, data: dict[str, Any]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []

        if self._contains_firewall_log_rows(self._extract_log_rows(data)) or self._looks_like_log_export(data):
            return self._parse_log_export(data)

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

    def _parse_log_export(self, data: dict[str, Any]) -> list[NormalizedRule]:
        direct_rows = self._extract_log_rows(data)
        if self._contains_firewall_log_rows(direct_rows):
            return self._parse_log_rows(direct_rows)

        rules: list[NormalizedRule] = []
        for key in self._LOG_EXPORT_KEYS:
            rows = self._extract_log_rows(data.get(key))
            rules.extend(self._parse_log_rows(rows))
        return rules

    def _parse_log_rows(self, rows: list[dict[str, Any]]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []
        for row in rows:
            if self._is_dns_log_row(row):
                rules.append(self._parse_dns_log_row(row))
                continue
            if self._is_application_log_row(row):
                rules.append(self._parse_application_log_row(row))
                continue
            if self._looks_like_firewall_log_row(row):
                rules.append(self._parse_generic_log_row(row))
        return rules

    def _parse_dns_log_row(self, row: dict[str, Any]) -> NormalizedRule:
        query_name = self._trim(str(row.get("QueryName") or "observed-dns-query"))
        query_type = str(row.get("QueryType") or "DNS")
        response_code = str(row.get("ResponseCode") or "")
        time_generated = str(row.get("TimeGenerated") or "")

        description_parts = [f"Observed DNS query ({query_type})"]
        if response_code:
            description_parts.append(f"response={response_code}")
        if time_generated:
            description_parts.append(f"time={time_generated}")

        return NormalizedRule(
            original_id=self._build_log_id("dns", row.get("QueryId"), time_generated),
            name=self._trim(f"DNS query {query_name}"),
            vendor=VendorType.AZURE_FIREWALL,
            action=RuleAction.LOG,
            direction=RuleDirection.OUTBOUND,
            protocol=self._normalize_protocol(row.get("Protocol")),
            source_addresses=self._list_value(row.get("SourceIp")),
            source_ports=self._list_value(row.get("SourcePort"), default="53"),
            destination_addresses=[query_name],
            destination_ports=["53"],
            description="; ".join(description_parts),
            enabled=True,
            raw_json=row,
            tags={
                "rule_type": "DnsQueryLog",
                "log_type": str(row.get("Type") or "AZFWDnsQuery"),
                "response_code": response_code or "unknown",
            },
        )

    def _parse_application_log_row(self, row: dict[str, Any]) -> NormalizedRule:
        destination = self._first_non_empty(row, "Fqdn", "TargetUrl", "DestinationIp", "DestinationIp_s") or "*"
        action = self._coerce_rule_action(row.get("Action"), default=RuleAction.LOG)
        rule_name = self._first_non_empty(row, "Rule")
        collection = self._first_non_empty(row, "RuleCollection")
        group = self._first_non_empty(row, "RuleCollectionGroup")
        policy = self._first_non_empty(row, "Policy")
        time_generated = str(row.get("TimeGenerated") or "")
        description_parts = [f"Observed application traffic to {destination}"]
        if action != RuleAction.LOG:
            description_parts.append(f"action={action.value}")
        if time_generated:
            description_parts.append(f"time={time_generated}")

        return NormalizedRule(
            original_id=self._build_log_id("app", rule_name or destination, time_generated),
            name=self._trim(rule_name or f"Observed app traffic to {destination}"),
            vendor=VendorType.AZURE_FIREWALL,
            action=action,
            direction=RuleDirection.OUTBOUND,
            protocol=self._normalize_protocol(row.get("Protocol")),
            source_addresses=self._list_value(row.get("SourceIp")),
            source_ports=self._list_value(row.get("SourcePort"), default="*"),
            destination_addresses=[self._trim(destination)],
            destination_ports=self._list_value(row.get("DestinationPort"), default="443"),
            collection_name=self._trim(collection) if collection else None,
            description="; ".join(description_parts),
            enabled=True,
            raw_json=row,
            tags={
                "rule_type": "ApplicationRuleLog",
                "log_type": str(row.get("Type") or "AZFWApplicationRule"),
                "group": group or "",
                "collection": collection or "",
                "policy": policy or "",
            },
        )

    def _parse_generic_log_row(self, row: dict[str, Any]) -> NormalizedRule:
        source = self._first_non_empty(row, "SourceIp", "SourceIP") or "*"
        destination = self._first_non_empty(
            row,
            "Fqdn",
            "Fqdn_s",
            "TargetUrl",
            "TargetUrl_s",
            "DestinationIp",
            "DestinationIp_s",
        ) or "*"
        action = self._coerce_rule_action(row.get("Action") or row.get("Action_s"), default=RuleAction.LOG)
        category = self._first_non_empty(row, "Category", "Type") or "AzureFirewallLog"
        rule_name = self._first_non_empty(row, "Rule", "Rule_s")
        collection = self._first_non_empty(row, "RuleCollection", "RuleCollection_s")
        group = self._first_non_empty(row, "RuleCollectionGroup", "RuleCollectionGroup_s")
        policy = self._first_non_empty(row, "Policy", "Policy_s")
        reason = self._first_non_empty(row, "ActionReason", "ActionReason_s", "msg_s", "ResultDescription")
        time_generated = str(row.get("TimeGenerated") or "")

        description_parts = [f"Observed {category} traffic"]
        if reason:
            description_parts.append(reason)
        if time_generated:
            description_parts.append(f"time={time_generated}")

        return NormalizedRule(
            original_id=self._build_log_id("log", rule_name or category, time_generated),
            name=self._trim(rule_name or f"Observed {category} traffic"),
            vendor=VendorType.AZURE_FIREWALL,
            action=action,
            direction=self._coerce_direction(row, source, destination),
            protocol=self._normalize_protocol(row.get("Protocol") or row.get("Protocol_s")),
            source_addresses=[source],
            source_ports=self._list_value(row.get("SourcePort") or row.get("SourcePort_d"), default="*"),
            destination_addresses=[self._trim(destination)],
            destination_ports=self._list_value(row.get("DestinationPort") or row.get("DestinationPort_d"), default="*"),
            collection_name=self._trim(collection) if collection else None,
            description="; ".join(description_parts),
            enabled=True,
            raw_json=row,
            tags={
                "rule_type": "ObservedTrafficLog",
                "log_type": category,
                "group": group or "",
                "collection": collection or "",
                "policy": policy or "",
            },
        )

    def _looks_like_log_export(self, data: dict[str, Any]) -> bool:
        if not any(key in data for key in self._LOG_EXPORT_KEYS):
            return False
        if any(self._contains_firewall_log_rows(self._extract_log_rows(data.get(key))) for key in self._LOG_EXPORT_KEYS):
            return True
        return bool(data.get("workspaceCustomerId") or data.get("workspace"))

    def _contains_firewall_log_rows(self, rows: list[dict[str, Any]]) -> bool:
        return any(self._looks_like_firewall_log_row(row) for row in rows)

    def _looks_like_firewall_log_row(self, row: dict[str, Any]) -> bool:
        row_type = str(row.get("Type") or row.get("Category") or "")
        if row_type in self._FIREWALL_LOG_TYPES:
            return True
        if row.get("QueryName") and row.get("SourceIp"):
            return True
        if (row.get("Fqdn") or row.get("TargetUrl")) and row.get("SourceIp"):
            return True
        if (row.get("SourceIP") or row.get("SourceIp")) and (row.get("DestinationIp_s") or row.get("DestinationIp")):
            return True
        return False

    def _is_dns_log_row(self, row: dict[str, Any]) -> bool:
        return str(row.get("Type") or "") == "AZFWDnsQuery" or bool(row.get("QueryName"))

    def _is_application_log_row(self, row: dict[str, Any]) -> bool:
        row_type = str(row.get("Type") or "")
        return row_type == "AZFWApplicationRule" or bool(row.get("Fqdn") or row.get("TargetUrl"))

    def _extract_log_rows(self, section: Any) -> list[dict[str, Any]]:
        if isinstance(section, list):
            return [item for item in section if isinstance(item, dict)]
        if not isinstance(section, dict):
            return []
        if isinstance(section.get("tables"), list):
            rows: list[dict[str, Any]] = []
            for table in section["tables"]:
                rows.extend(self._table_to_rows(table))
            return rows
        if isinstance(section.get("rows"), list) and isinstance(section.get("columns"), list):
            return self._table_to_rows(section)
        return []

    def _table_to_rows(self, table: dict[str, Any]) -> list[dict[str, Any]]:
        columns = [str(column.get("name") or f"col_{idx}") for idx, column in enumerate(table.get("columns", []))]
        rows: list[dict[str, Any]] = []
        for raw_row in table.get("rows", []):
            if isinstance(raw_row, dict):
                rows.append(raw_row)
                continue
            if not isinstance(raw_row, list):
                continue
            item = {
                columns[idx]: raw_row[idx] if idx < len(raw_row) else None
                for idx in range(len(columns))
            }
            rows.append(item)
        return rows

    def _coerce_rule_action(self, value: Any, default: RuleAction = RuleAction.LOG) -> RuleAction:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return default
        if normalized in RuleAction._value2member_map_:
            return RuleAction(normalized)
        if normalized in {"allowed", "allow"}:
            return RuleAction.ALLOW
        if normalized in {"blocked", "block", "deny", "denied", "drop", "dropped", "reject", "rejected"}:
            return RuleAction.DENY
        if normalized in {"log", "logged"}:
            return RuleAction.LOG
        return default

    def _coerce_direction(self, row: dict[str, Any], source: str, destination: str) -> RuleDirection:
        raw_direction = str(row.get("direction_s") or "").strip().lower()
        if raw_direction in RuleDirection._value2member_map_:
            return RuleDirection(raw_direction)
        if row.get("Fqdn") or row.get("TargetUrl") or row.get("QueryName"):
            return RuleDirection.OUTBOUND
        source_private = self._is_private_ip(source)
        destination_private = self._is_private_ip(destination)
        if source_private and not destination_private:
            return RuleDirection.OUTBOUND
        if destination_private and not source_private:
            return RuleDirection.INBOUND
        return RuleDirection.BOTH

    @staticmethod
    def _normalize_protocol(value: Any) -> str:
        protocol = str(value or "Any").strip()
        if not protocol or protocol == "*" or protocol.lower() == "any":
            return "Any"
        return protocol.upper()

    @staticmethod
    def _first_non_empty(row: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = row.get(key)
            if value not in (None, ""):
                return str(value)
        return None

    def _list_value(self, value: Any, default: str = "*") -> list[str]:
        if value in (None, ""):
            return [default]
        if isinstance(value, list):
            items = [str(item) for item in value if item not in (None, "")]
            return items or [default]
        return [str(value)]

    def _build_log_id(self, prefix: str, primary: Any, fallback: Any) -> str:
        if primary not in (None, ""):
            return self._trim(f"{prefix}:{primary}")
        if fallback not in (None, ""):
            return self._trim(f"{prefix}:{fallback}")
        return prefix

    @staticmethod
    def _trim(value: str, max_length: int = 255) -> str:
        return value[:max_length]

    @staticmethod
    def _is_private_ip(value: str) -> bool:
        try:
            return ip_address(value).is_private
        except ValueError:
            return False

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
