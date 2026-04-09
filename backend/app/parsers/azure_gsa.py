from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from app.parsers.base import (
    BaseParser,
    NormalizedRule,
    ParserRegistry,
    RuleAction,
    RuleDirection,
    VendorType,
)


@ParserRegistry.register
class AzureGSAParser(BaseParser):
    """Parser for Microsoft Entra Global Secure Access log exports.

    Supports three observed-log families:
    - Entra audit logs filtered to the Global Secure Access service
    - Global Secure Access deployment logs
    - Global Secure Access traffic log exports
    """

    vendor = VendorType.AZURE_GSA

    _AUDIT_SERVICE = "global secure access"
    _TRAFFIC_CATEGORY_HINTS = {
        "networkaccesstrafficlogs",
        "networkaccesstraffic",
        "globalsecureaccesstraffic",
    }
    _AUDIT_CATEGORY_HINTS = {
        "forwardingprofile",
        "forwardingprofiles",
        "filteringpolicy",
        "remotenetwork",
        "remote network",
        "auditlogssettings",
        "conditionalaccesssettings",
        "crosstenantaccesssettings",
        "trafficforwardingprofiles",
        "ipforwardingoptions",
    }
    _DEPLOYMENT_TYPE_HINTS = {
        "forwardingprofile",
        "filteringprofile",
        "remotenetwork",
        "auditlogssettings",
        "crosstenantaccesssettings",
        "conditionalaccesssettings",
        "ipforwardingoptions",
    }

    def can_parse(self, data: dict[str, Any]) -> bool:
        if self.looks_like_ambiguous_log_export(data):
            return True
        return any(self._classify_row(row) is not None for row in self._extract_rows(data))

    def parse(self, data: dict[str, Any]) -> list[NormalizedRule]:
        rules: list[NormalizedRule] = []

        for row in self._extract_rows(data):
            row_type = self._classify_row(row)
            if row_type == "traffic":
                rules.append(self._parse_traffic_row(row))
            elif row_type == "audit":
                rules.append(self._parse_audit_row(row))
            elif row_type == "deployment":
                rules.append(self._parse_deployment_row(row))

        return rules

    def generate(self, normalized: NormalizedRule) -> dict[str, Any]:
        if normalized.raw_json:
            return normalized.raw_json

        return {
            "name": normalized.name,
            "vendor": normalized.vendor.value,
            "action": normalized.action.value,
            "collection": normalized.collection_name,
            "description": normalized.description,
            "tags": normalized.tags,
        }

    def looks_like_ambiguous_log_export(self, data: dict[str, Any]) -> bool:
        column_names = self._extract_column_names(data)
        if not column_names:
            return False

        if "loggedbyservice" in column_names and (
            "activitydisplayname" in column_names or "activity" in column_names
        ):
            return True

        if {"activity", "status", "requestid", "type"}.issubset(column_names):
            return True

        if (
            {"connectionid", "action"}.issubset(column_names)
            and column_names
            & {
                "destinationfqdn",
                "destinationip",
                "requesturl",
                "url",
                "destinationhost",
            }
        ):
            return True

        return False

    def _classify_row(self, row: dict[str, Any]) -> str | None:
        fields = self._normalize_fields(row)

        if self._is_traffic_row(fields):
            return "traffic"
        if self._is_audit_row(fields):
            return "audit"
        if self._is_deployment_row(fields):
            return "deployment"
        return None

    def _is_traffic_row(self, fields: dict[str, Any]) -> bool:
        category = self._string(
            self._get(fields, "category", "logcategory", "logtype", "tablename")
        ).lower()
        if category in self._TRAFFIC_CATEGORY_HINTS:
            return True

        has_identifier = bool(
            self._get(fields, "connectionid", "transactionid", "sessionid", "flowcorrelationid")
        )
        has_action = bool(self._get(fields, "action", "result"))
        has_destination = bool(
            self._get(
                fields,
                "destinationfqdn",
                "destinationip",
                "requesturl",
                "url",
                "destinationhost",
            )
        )
        if has_identifier and has_action and has_destination:
            return True

        # Connection-summary records use plain "id" as the connection identifier
        if (
            not has_identifier
            and has_action
            and has_destination
            and bool(self._get(fields, "id"))
            and bool(self._get(fields, "traffictype"))
        ):
            return True

        return False

    def _is_audit_row(self, fields: dict[str, Any]) -> bool:
        service = self._string(self._get(fields, "loggedbyservice", "service")).lower()
        if service == self._AUDIT_SERVICE:
            return bool(
                self._get(fields, "activitydisplayname", "activity", "operationtype")
                or self._get(fields, "category")
            )

        activity = self._string(
            self._get(fields, "activitydisplayname", "activity", "operationtype")
        ).lower()
        category = self._string(self._get(fields, "category")).lower()
        return any(hint in f"{activity} {category}" for hint in self._AUDIT_CATEGORY_HINTS)

    def _is_deployment_row(self, fields: dict[str, Any]) -> bool:
        deployment_type = self._string(self._get(fields, "type")).lower()
        if deployment_type and deployment_type in self._DEPLOYMENT_TYPE_HINTS:
            return bool(self._get(fields, "activity") and self._get(fields, "status"))

        return bool(
            self._get(fields, "activity")
            and self._get(fields, "status")
            and self._get(fields, "requestid")
            and self._get(fields, "type")
        )

    def _parse_traffic_row(self, row: dict[str, Any]) -> NormalizedRule:
        fields = self._normalize_fields(row)
        timestamp = self._string(
            self._get(fields, "activitydatetime", "timegenerated", "timestamp", "date")
        )
        connection_id = self._string(self._get(fields, "connectionid", "flowcorrelationid")) or self._string(self._get(fields, "id"))
        transaction_id = self._string(self._get(fields, "transactionid"))
        session_id = self._string(self._get(fields, "sessionid"))
        traffic_type = self._string(self._get(fields, "traffictype", "profile", "servicetype"))
        device_category = self._string(self._get(fields, "devicecategory", "devicekind"))
        user_principal_name = self._string(
            self._get(fields, "userprincipalname", "upn", "identity")
        )
        source_ip = self._string(
            self._get(fields, "sourceip", "originalip", "clientip", "publicipaddress")
        )
        source_port = self._string(self._get(fields, "sourceport", "clientport"))
        destination = self._derive_destination(fields)
        destination_port = self._derive_destination_port(fields)
        protocol = self._string(self._get(fields, "protocol", "transportprotocol", "l4protocol")) or "Any"
        action = self._coerce_action(self._get(fields, "action", "result"))

        description_parts = ["Observed Global Secure Access traffic"]
        if traffic_type:
            description_parts.append(f"traffic_type={traffic_type}")
        if user_principal_name:
            description_parts.append(f"user={user_principal_name}")
        if device_category:
            description_parts.append(f"device={device_category}")
        if timestamp:
            description_parts.append(f"time={timestamp}")

        display_target = destination or "unknown-destination"
        name = f"GSA traffic to {display_target}"

        return NormalizedRule(
            original_id=self._build_log_id("gsa-traffic", transaction_id or connection_id, timestamp),
            name=name,
            vendor=VendorType.AZURE_GSA,
            action=action,
            direction=RuleDirection.OUTBOUND,
            protocol=protocol,
            source_addresses=[source_ip or "*"],
            source_ports=[source_port or "*"],
            destination_addresses=[display_target],
            destination_ports=[destination_port or "*"],
            collection_name=traffic_type or "Global Secure Access traffic",
            description="; ".join(description_parts),
            enabled=True,
            raw_json=row,
            tags={
                "log_type": "traffic",
                "connection_id": connection_id,
                "transaction_id": transaction_id,
                "session_id": session_id,
                "traffic_type": traffic_type,
                "device_category": device_category,
                "user_principal_name": user_principal_name,
            },
        )

    def _parse_audit_row(self, row: dict[str, Any]) -> NormalizedRule:
        fields = self._normalize_fields(row)
        timestamp = self._string(
            self._get(fields, "activitydatetime", "timegenerated", "date", "timestamp")
        )
        category = self._string(self._get(fields, "category"))
        activity = self._string(
            self._get(fields, "activitydisplayname", "activity", "operationtype")
        )
        service = self._string(self._get(fields, "loggedbyservice", "service")) or "Global Secure Access"
        result = self._string(self._get(fields, "result", "status"))
        result_reason = self._string(
            self._get(fields, "resultreason", "statusreason", "errormessage", "failurereason")
        )
        initiated_by = self._extract_initiated_by(row, fields)
        targets = self._extract_targets(row, fields)
        correlation_id = self._string(self._get(fields, "id", "requestid", "correlationid"))

        description_parts = [f"Observed {service} audit event"]
        if category:
            description_parts.append(f"category={category}")
        if result:
            description_parts.append(f"result={result}")
        if initiated_by:
            description_parts.append(f"initiated_by={initiated_by}")
        if targets:
            description_parts.append(f"targets={', '.join(targets[:3])}")
        if result_reason:
            description_parts.append(result_reason)
        if timestamp:
            description_parts.append(f"time={timestamp}")

        return NormalizedRule(
            original_id=self._build_log_id("gsa-audit", correlation_id or activity, timestamp),
            name=activity or "Global Secure Access audit event",
            vendor=VendorType.AZURE_GSA,
            action=RuleAction.LOG,
            direction=RuleDirection.BOTH,
            protocol="ControlPlane",
            source_addresses=[initiated_by or "*"] if initiated_by else ["*"],
            source_ports=["*"],
            destination_addresses=targets or [category or "*"],
            destination_ports=["*"],
            collection_name=category or "Global Secure Access audit",
            description="; ".join(description_parts),
            enabled=True,
            raw_json=row,
            tags={
                "log_type": "audit",
                "service": service,
                "category": category,
                "result": result,
                "initiated_by": initiated_by,
                "correlation_id": correlation_id,
            },
        )

    def _parse_deployment_row(self, row: dict[str, Any]) -> NormalizedRule:
        fields = self._normalize_fields(row)
        timestamp = self._string(
            self._get(fields, "date", "activitydatetime", "timegenerated", "timestamp")
        )
        activity = self._string(self._get(fields, "activity"))
        status = self._string(self._get(fields, "status"))
        change_type = self._string(self._get(fields, "type"))
        initiated_by = self._string(self._get(fields, "initiatedby"))
        request_id = self._string(self._get(fields, "requestid", "correlationid"))
        error_message = self._string(self._get(fields, "errormessages", "error", "errormessage"))

        description_parts = ["Observed Global Secure Access deployment event"]
        if status:
            description_parts.append(f"status={status}")
        if initiated_by:
            description_parts.append(f"initiated_by={initiated_by}")
        if error_message:
            description_parts.append(error_message)
        if timestamp:
            description_parts.append(f"time={timestamp}")

        return NormalizedRule(
            original_id=self._build_log_id("gsa-deployment", request_id or activity, timestamp),
            name=activity or "Global Secure Access deployment event",
            vendor=VendorType.AZURE_GSA,
            action=RuleAction.LOG,
            direction=RuleDirection.BOTH,
            protocol="ControlPlane",
            source_addresses=[initiated_by or "*"] if initiated_by else ["*"],
            source_ports=["*"],
            destination_addresses=[change_type or "*"] if change_type else ["*"],
            destination_ports=["*"],
            collection_name="Global Secure Access deployment",
            description="; ".join(description_parts),
            enabled=True,
            raw_json=row,
            tags={
                "log_type": "deployment",
                "status": status,
                "type": change_type,
                "request_id": request_id,
                "initiated_by": initiated_by,
            },
        )

    def _extract_rows(self, section: Any) -> list[dict[str, Any]]:
        if isinstance(section, list):
            return [item for item in section if isinstance(item, dict)]
        if not isinstance(section, dict):
            return []

        rows: list[dict[str, Any]] = []

        if isinstance(section.get("tables"), list):
            for table in section["tables"]:
                rows.extend(self._table_to_rows(table))

        if isinstance(section.get("rows"), list) and isinstance(section.get("columns"), list):
            rows.extend(self._table_to_rows(section))

        for key in ("records", "value", "items", "auditLogs", "deploymentLogs", "trafficLogs", "logs"):
            value = section.get(key)
            if isinstance(value, list):
                rows.extend(item for item in value if isinstance(item, dict))

        if rows:
            return rows

        if self._looks_like_direct_row(section):
            return [section]

        return []

    def _extract_column_names(self, section: Any) -> set[str]:
        if not isinstance(section, dict):
            return set()
        if isinstance(section.get("tables"), list):
            names: set[str] = set()
            for table in section["tables"]:
                names.update(self._extract_column_names(table))
            return names
        if isinstance(section.get("columns"), list):
            return {
                self._canonicalize_key(column.get("name") or "")
                for column in section["columns"]
                if isinstance(column, dict)
            }
        return set()

    def _table_to_rows(self, table: dict[str, Any]) -> list[dict[str, Any]]:
        columns = [
            str(column.get("name") or f"col_{index}")
            for index, column in enumerate(table.get("columns", []))
            if isinstance(column, dict)
        ]
        rows: list[dict[str, Any]] = []
        for raw_row in table.get("rows", []):
            if isinstance(raw_row, dict):
                rows.append(raw_row)
                continue
            if not isinstance(raw_row, list):
                continue
            rows.append(
                {
                    columns[index]: raw_row[index] if index < len(raw_row) else None
                    for index in range(len(columns))
                }
            )
        return rows

    def _looks_like_direct_row(self, section: dict[str, Any]) -> bool:
        fields = self._normalize_fields(section)
        return self._classify_row(section) is not None or bool(
            self._get(fields, "loggedbyservice", "connectionid", "requestid", "activity")
        )

    @staticmethod
    def _canonicalize_key(value: Any) -> str:
        return "".join(ch for ch in str(value).lower() if ch.isalnum())

    def _normalize_fields(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            self._canonicalize_key(key): value
            for key, value in row.items()
            if key is not None
        }

    @staticmethod
    def _get(fields: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            canonical_key = "".join(ch for ch in key.lower() if ch.isalnum())
            if canonical_key in fields:
                return fields[canonical_key]
        return None

    def _extract_initiated_by(self, row: dict[str, Any], fields: dict[str, Any]) -> str:
        raw_value = row.get("initiatedBy") or row.get("InitiatedBy") or self._get(fields, "initiatedby")
        value = self._maybe_json_value(raw_value)

        if isinstance(value, dict):
            user = value.get("user") or {}
            app = value.get("app") or {}
            for candidate in (
                user.get("userPrincipalName"),
                user.get("displayName"),
                app.get("displayName"),
                app.get("servicePrincipalName"),
            ):
                string_value = self._string(candidate)
                if string_value:
                    return string_value

        return self._string(value)

    def _extract_targets(self, row: dict[str, Any], fields: dict[str, Any]) -> list[str]:
        raw_value = row.get("targetResources") or row.get("TargetResources") or self._get(
            fields,
            "targetresources",
            "targets",
            "target",
        )
        value = self._maybe_json_value(raw_value)
        if isinstance(value, list):
            targets: list[str] = []
            for item in value:
                if isinstance(item, dict):
                    for candidate in (
                        item.get("displayName"),
                        item.get("userPrincipalName"),
                        item.get("type"),
                        item.get("id"),
                    ):
                        string_value = self._string(candidate)
                        if string_value and string_value not in targets:
                            targets.append(string_value)
                            break
                else:
                    string_value = self._string(item)
                    if string_value and string_value not in targets:
                        targets.append(string_value)
            return targets

        string_value = self._string(value)
        return [string_value] if string_value else []

    def _derive_destination(self, fields: dict[str, Any]) -> str:
        raw_value = self._string(
            self._get(
                fields,
                "destinationfqdn",
                "destinationhost",
                "destinationhostname",
                "fqdn",
                "destinationip",
                "requesturl",
                "url",
            )
        )
        if not raw_value:
            return "*"

        if raw_value.startswith("http://") or raw_value.startswith("https://"):
            parsed = urlparse(raw_value)
            return parsed.hostname or raw_value

        return raw_value

    def _derive_destination_port(self, fields: dict[str, Any]) -> str:
        port = self._string(
            self._get(fields, "destinationport", "serverport", "port")
        )
        if port:
            return port

        raw_url = self._string(self._get(fields, "requesturl", "url"))
        if raw_url.startswith("https://"):
            return "443"
        if raw_url.startswith("http://"):
            return "80"
        return "*"

    @staticmethod
    def _coerce_action(value: Any) -> RuleAction:
        normalized = str(value or "").strip().lower()
        if any(token in normalized for token in ("allow", "allowed", "success", "succeeded")):
            return RuleAction.ALLOW
        if any(token in normalized for token in ("deny", "denied", "block", "blocked", "fail", "failed")):
            return RuleAction.DENY
        return RuleAction.LOG

    @staticmethod
    def _build_log_id(prefix: str, identifier: Any, timestamp: str) -> str:
        token = str(identifier or "unknown").strip() or "unknown"
        suffix = f"-{timestamp}" if timestamp else ""
        return f"{prefix}-{token}{suffix}"

    @staticmethod
    def _string(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True)
        return str(value).strip()

    @staticmethod
    def _maybe_json_value(value: Any) -> Any:
        if not isinstance(value, str):
            return value

        raw_value = value.strip()
        if not raw_value or raw_value[0] not in "[{":
            return value

        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            return value