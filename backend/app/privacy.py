from __future__ import annotations

import hashlib
import json
import re
from typing import Any

REDACTED_SUBSCRIPTION = "[redacted-subscription]"
REDACTED_RESOURCE_GROUP = "[redacted-resource-group]"
REDACTED_TENANT = "[redacted-tenant]"

_SUBSCRIPTION_SEGMENT_RE = re.compile(r"(?i)(/subscriptions/)([^/?]+)")
_RESOURCE_GROUP_SEGMENT_RE = re.compile(r"(?i)(/resourcegroups/)([^/?]+)")

_SUBSCRIPTION_KEYS = {"subscriptionid", "subscription_id"}
_RESOURCE_GROUP_KEYS = {"resourcegroup", "resource_group", "resourcegroupname", "resource_group_name"}
_TENANT_KEYS = {"tenantid", "tenant_id"}


def sanitize_azure_text(value: str, key: str | None = None) -> str:
    key_name = key.lower() if key else ""
    if key_name in _SUBSCRIPTION_KEYS:
        return REDACTED_SUBSCRIPTION
    if key_name in _RESOURCE_GROUP_KEYS:
        return REDACTED_RESOURCE_GROUP
    if key_name in _TENANT_KEYS:
        return REDACTED_TENANT

    sanitized = _SUBSCRIPTION_SEGMENT_RE.sub(rf"\1{REDACTED_SUBSCRIPTION}", value)
    sanitized = _RESOURCE_GROUP_SEGMENT_RE.sub(rf"\1{REDACTED_RESOURCE_GROUP}", sanitized)
    return sanitized


def sanitize_azure_data(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {item_key: sanitize_azure_data(item_value, item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [sanitize_azure_data(item, key) for item in value]
    if isinstance(value, str):
        return sanitize_azure_text(value, key)
    return value


def sanitize_azure_json(value: Any) -> str:
    return json.dumps(sanitize_azure_data(value))