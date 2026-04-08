from __future__ import annotations

import hashlib
import json
import re
from typing import Any

REDACTED_SUBSCRIPTION = "[redacted-subscription]"
REDACTED_SUBSCRIPTION_NAME = "[redacted-subscription-name]"
REDACTED_RESOURCE_GROUP = "[redacted-resource-group]"
REDACTED_TENANT = "[redacted-tenant]"
REDACTED_USER = "[redacted-user]"

_SUBSCRIPTION_SEGMENT_RE = re.compile(r"(?i)(/subscriptions/)([^/?]+)")
_RESOURCE_GROUP_SEGMENT_RE = re.compile(r"(?i)(/resourcegroups/)([^/?]+)")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_LABELED_SUBSCRIPTION_ID_RE = re.compile(r"(?i)\b(subscription(?:\s*id)?)(\s*[:=]\s*)([0-9a-f-]{36})\b")
_LABELED_SUBSCRIPTION_NAME_RE = re.compile(r"(?i)\b(subscription(?:\s*name)?)(\s*[:=]\s*)([^\n,;]+)")
_LABELED_USER_RE = re.compile(
    r"(?i)\b(user(?:\s*principal\s*name|\s*name)?|owner(?:\s*name)?|principal(?:\s*name)?|sign[- ]?in\s*name)(\s*[:=]\s*)([^\n,;]+)"
)

_SUBSCRIPTION_KEYS = {"subscriptionid", "subscription_id"}
_SUBSCRIPTION_NAME_KEYS = {"subscriptionname", "subscription_name"}
_RESOURCE_GROUP_KEYS = {"resourcegroup", "resource_group", "resourcegroupname", "resource_group_name"}
_TENANT_KEYS = {"tenantid", "tenant_id"}
_USER_KEYS = {
    "user",
    "username",
    "user_name",
    "displayname",
    "display_name",
    "owner",
    "ownername",
    "owner_name",
    "principalname",
    "principal_name",
    "userprincipalname",
    "user_principal_name",
    "signinname",
    "sign_in_name",
}


def _replace_labeled_value(match: re.Match[str], redaction: str) -> str:
    return f"{match.group(1)}{match.group(2)}{redaction}"


def sanitize_azure_text(value: str, key: str | None = None) -> str:
    key_name = key.lower() if key else ""
    if key_name in _SUBSCRIPTION_KEYS:
        return REDACTED_SUBSCRIPTION
    if key_name in _SUBSCRIPTION_NAME_KEYS:
        return REDACTED_SUBSCRIPTION_NAME
    if key_name in _RESOURCE_GROUP_KEYS:
        return REDACTED_RESOURCE_GROUP
    if key_name in _TENANT_KEYS:
        return REDACTED_TENANT
    if key_name in _USER_KEYS:
        return REDACTED_USER

    sanitized = _EMAIL_RE.sub(REDACTED_USER, value)
    sanitized = _SUBSCRIPTION_SEGMENT_RE.sub(rf"\1{REDACTED_SUBSCRIPTION}", sanitized)
    sanitized = _RESOURCE_GROUP_SEGMENT_RE.sub(rf"\1{REDACTED_RESOURCE_GROUP}", sanitized)
    sanitized = _LABELED_SUBSCRIPTION_ID_RE.sub(
        lambda match: _replace_labeled_value(match, REDACTED_SUBSCRIPTION),
        sanitized,
    )
    sanitized = _LABELED_SUBSCRIPTION_NAME_RE.sub(
        lambda match: _replace_labeled_value(match, REDACTED_SUBSCRIPTION_NAME),
        sanitized,
    )
    sanitized = _LABELED_USER_RE.sub(
        lambda match: _replace_labeled_value(match, REDACTED_USER),
        sanitized,
    )
    return sanitized


def sanitize_optional_azure_text(value: str | None, key: str | None = None) -> str | None:
    if value is None:
        return None
    return sanitize_azure_text(value, key)


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