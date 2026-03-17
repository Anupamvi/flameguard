"""Prompt templates for natural-language to firewall-rule generation."""

SYSTEM_GENERATE = """\
You are FlameGuard, a network security assistant. Convert natural language \
intent into vendor-specific firewall configuration JSON.

Return valid JSON matching the vendor's schema. Include sensible defaults for \
any fields the user does not specify. Follow security best practices -- prefer \
deny-by-default, minimal port ranges, and specific source/destination addresses.
"""

USER_GENERATE_TEMPLATE = """\
Vendor: {vendor}

Intent: {intent}

Additional context:
{context}

Expected JSON schema for this vendor:
{vendor_schema_hint}

Generate the firewall rule configuration as JSON. Return JSON only.
"""

VENDOR_SCHEMA_HINTS: dict[str, str] = {
    "azure_firewall": """\
{{
  "name": "rule-name",
  "action": "Allow" | "Deny",
  "priority": 100-65000,
  "direction": "Inbound" | "Outbound",
  "sourceAddresses": ["10.0.0.0/24"],
  "destinationAddresses": ["*"],
  "destinationPorts": ["443"],
  "protocols": ["TCP"]
}}""",
    "azure_nsg": """\
{{
  "name": "rule-name",
  "properties": {{
    "protocol": "Tcp" | "Udp" | "*",
    "sourcePortRange": "*",
    "destinationPortRange": "443",
    "sourceAddressPrefix": "10.0.0.0/24",
    "destinationAddressPrefix": "*",
    "access": "Allow" | "Deny",
    "priority": 100-4096,
    "direction": "Inbound" | "Outbound"
  }}
}}""",
    "azure_waf": """\
{{
  "name": "rule-name",
  "priority": 1-100,
  "ruleType": "MatchRule",
  "action": "Allow" | "Block" | "Log",
  "matchConditions": [
    {{
      "matchVariables": [{{"variableName": "RemoteAddr"}}],
      "operator": "IPMatch",
      "matchValues": ["10.0.0.0/24"]
    }}
  ]
}}""",
}
