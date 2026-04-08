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
    _LOG_EXPORT_KEYS = ("sampleLogs",)
    _WAF_LOG_CATEGORIES = {
        "ApplicationGatewayFirewallLog",
        "FrontDoorWebApplicationFirewallLog",
        "FrontdoorWebApplicationFirewallLog",
    }
    _AMBIGUOUS_SCHEMA_HINTS = {
        "clientIP_s",
        "clientIp_s",
        "HostName_s",
        "hostName_s",
        "hostname_s",
        "listenerName_s",
        "requestUri_s",
        "originalRequestUriWithArgs_s",
        "transactionId_g",
    }

    def can_parse(self, data: dict[str, Any]) -> bool:
        rtype = data.get("type", "")
        if rtype in (self._APPGW_TYPE, self._FD_TYPE):
            return True
        for r in data.get("resources", []):
            if r.get("type") in (self._APPGW_TYPE, self._FD_TYPE):
                return True
        if self._looks_like_waf_bundle(data):
            return True
        if self._contains_waf_log_rows(self._extract_log_rows(data)):
            return True
        if any(self._contains_waf_log_rows(self._extract_log_rows(data.get(key))) for key in self._LOG_EXPORT_KEYS):
            return True
        return False

    def parse(self, data: dict[str, Any]) -> list[NormalizedRule]:
        if self._contains_waf_log_rows(self._extract_log_rows(data)) or self._looks_like_waf_bundle(data):
            return self._parse_log_export(data)

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

    def looks_like_ambiguous_log_export(self, data: dict[str, Any]) -> bool:
        if self._looks_like_waf_bundle(data):
            return True
        if self._looks_like_waf_log_schema(data):
            return True
        return any(self._looks_like_waf_log_schema(data.get(key)) for key in self._LOG_EXPORT_KEYS)

    # ── Internals ──

    def _parse_log_export(self, data: dict[str, Any]) -> list[NormalizedRule]:
        direct_rows = self._extract_log_rows(data)
        if direct_rows:
            return self._parse_log_rows(direct_rows)

        rules: list[NormalizedRule] = []
        for key in self._LOG_EXPORT_KEYS:
            rows = self._extract_log_rows(data.get(key))
            rules.extend(self._parse_log_rows(rows))
        return rules

    def _extract_waf_resources(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        rtype = data.get("type", "")
        if rtype in (self._APPGW_TYPE, self._FD_TYPE):
            return [data]
        return [r for r in data.get("resources", []) if r.get("type") in (self._APPGW_TYPE, self._FD_TYPE)]

    def _parse_log_rows(self, rows: list[dict[str, Any]]) -> list[NormalizedRule]:
        grouped: dict[tuple, NormalizedRule] = {}

        for row in rows:
            if not self._looks_like_waf_log_row(row):
                continue

            parsed = self._parse_log_row(row)
            signature = self._build_log_signature(parsed)
            representative = grouped.get(signature)
            if representative is None:
                parsed.tags["event_count"] = "1"
                grouped[signature] = parsed
                continue

            event_count = int(representative.tags.get("event_count", "1")) + 1
            representative.tags["event_count"] = str(event_count)
            representative.source_addresses = self._merge_unique_values(
                representative.source_addresses,
                parsed.source_addresses,
            )
            representative.source_ports = self._merge_unique_values(
                representative.source_ports,
                parsed.source_ports,
            )

        condensed = sorted(
            grouped.values(),
            key=lambda rule: (-int(rule.tags.get("event_count", "1")), rule.name),
        )
        for rule in condensed:
            event_count = int(rule.tags.get("event_count", "1"))
            if event_count > 1:
                rule.description = f"Observed in {event_count} matching WAF log events. {rule.description}"
        return condensed

    def _parse_log_row(self, row: dict[str, Any]) -> NormalizedRule:
        category = self._first_non_empty(row, "Category", "category") or "ApplicationGatewayFirewallLog"
        request_uri = self._first_non_empty(row, "requestUri_s", "originalRequestUriWithArgs_s")
        hostname = self._first_non_empty(row, "HostName_s", "hostName_s", "hostname_s", "host_s", "host", "originalHost_s")
        listener_name = self._first_non_empty(row, "listenerName_s")
        client_ip = self._first_non_empty(row, "clientIP_s", "clientIp_s", "CallerIPAddress") or "*"
        transaction_id = self._first_non_empty(row, "transactionId_g", "CorrelationId")
        rule_name = self._first_non_empty(row, "ruleName_s", "ruleId_s")
        time_generated = self._first_non_empty(row, "TimeGenerated", "timeStamp_t") or ""
        action = self._coerce_log_action(
            self._first_non_empty(row, "action_s", "Action_s", "Action", "ResultType", "RecommendedAction_s")
        )
        destination_ports = self._coerce_destination_ports(row, request_uri)
        message = self._first_non_empty(row, "Message", "details_message_s", "ResultDescription")
        source_port = self._first_non_empty(row, "clientPort_d", "clientPort_s")

        description_parts = [f"Observed {category}"]
        if request_uri:
            description_parts.append(f"uri={request_uri}")
        if message:
            description_parts.append(message)
        if time_generated:
            description_parts.append(f"time={time_generated}")

        rule_label = rule_name or request_uri or hostname or "Observed WAF event"
        target = hostname or listener_name or "*"

        tags = {
            "rule_type": "ObservedWAFLog",
            "log_category": category,
            "listener_name": listener_name or "",
            "transaction_id": transaction_id or "",
            "hostname": hostname or "",
        }

        for source_key, tag_key in (
            ("ruleId_s", "rule_id"),
            ("ruleSetType_s", "rule_set_type"),
            ("ruleSetVersion_s", "rule_set_version"),
            ("site_s", "site"),
        ):
            value = self._first_non_empty(row, source_key)
            if value:
                tags[tag_key] = value

        return NormalizedRule(
            original_id=self._build_log_id("waf", rule_name or transaction_id, time_generated),
            name=self._trim(rule_label),
            vendor=VendorType.AZURE_WAF,
            action=action,
            direction=RuleDirection.INBOUND,
            protocol="HTTPS" if destination_ports == ["443"] else "HTTP/HTTPS",
            source_addresses=[client_ip],
            source_ports=self._list_value(source_port, default="*"),
            destination_addresses=[self._trim(target)],
            destination_ports=destination_ports,
            priority=self._coerce_priority(row.get("priority_d")),
            description="; ".join(description_parts),
            enabled=True,
            raw_json=row,
            tags=tags,
        )

    def _looks_like_waf_bundle(self, data: dict[str, Any]) -> bool:
        if not isinstance(data, dict):
            return False
        if isinstance(data.get("wafResources"), list):
            return True
        if isinstance(data.get("diagnosticSettings"), list):
            return any(
                any(category in self._WAF_LOG_CATEGORIES for category in setting.get("categories", []))
                for setting in data["diagnosticSettings"]
                if isinstance(setting, dict)
            )
        return False

    def _contains_waf_log_rows(self, rows: list[dict[str, Any]]) -> bool:
        return any(self._looks_like_waf_log_row(row) for row in rows)

    def _looks_like_waf_log_row(self, row: dict[str, Any]) -> bool:
        category = str(row.get("Category") or row.get("category") or "")
        if category in self._WAF_LOG_CATEGORIES:
            return True
        client_ip = self._first_non_empty(row, "clientIP_s", "clientIp_s", "CallerIPAddress")
        request_uri = self._first_non_empty(row, "requestUri_s", "originalRequestUriWithArgs_s")
        destination = self._first_non_empty(row, "HostName_s", "hostName_s", "hostname_s", "host_s", "listenerName_s")
        return bool(client_ip and request_uri and destination)

    def _looks_like_waf_log_schema(self, section: Any) -> bool:
        column_names = self._extract_column_names(section)
        if not column_names or "Category" not in column_names:
            return False
        return len(self._AMBIGUOUS_SCHEMA_HINTS & column_names) >= 3

    def _extract_column_names(self, section: Any) -> set[str]:
        if not isinstance(section, dict):
            return set()
        if isinstance(section.get("tables"), list):
            column_names: set[str] = set()
            for table in section["tables"]:
                column_names.update(self._extract_column_names(table))
            return column_names
        if isinstance(section.get("columns"), list):
            return {str(column.get("name") or "") for column in section["columns"] if isinstance(column, dict)}
        return set()

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
            rows.append({
                columns[idx]: raw_row[idx] if idx < len(raw_row) else None
                for idx in range(len(columns))
            })
        return rows

    @staticmethod
    def _build_log_signature(rule: NormalizedRule) -> tuple:
        return (
            rule.name,
            rule.action.value,
            rule.protocol,
            tuple(rule.destination_addresses),
            tuple(rule.destination_ports),
            rule.tags.get("rule_id", ""),
            rule.tags.get("hostname", ""),
            rule.tags.get("log_category", ""),
        )

    @staticmethod
    def _merge_unique_values(existing: list[str], incoming: list[str], limit: int = 5) -> list[str]:
        merged: list[str] = []
        for value in [*existing, *incoming]:
            if value not in merged:
                merged.append(value)
            if len(merged) >= limit:
                break
        return merged

    @staticmethod
    def _coerce_log_action(value: Any) -> RuleAction:
        normalized = str(value or "").strip().lower()
        if any(token in normalized for token in ("block", "deny", "prevent")):
            return RuleAction.DENY
        if any(token in normalized for token in ("allow", "permit")):
            return RuleAction.ALLOW
        return RuleAction.LOG

    def _coerce_destination_ports(self, row: dict[str, Any], request_uri: str | None) -> list[str]:
        ssl_enabled = str(row.get("sslEnabled_s") or "").strip().lower()
        uri = str(request_uri or "").strip().lower()
        if ssl_enabled in {"true", "1", "yes", "enabled"} or uri.startswith("https://"):
            return ["443"]
        if ssl_enabled in {"false", "0", "no", "disabled"} or uri.startswith("http://"):
            return ["80"]
        return ["80", "443"]

    @staticmethod
    def _coerce_priority(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

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
