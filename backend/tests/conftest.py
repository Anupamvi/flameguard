import json
import os
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def nsg_data():
    with open(FIXTURES_DIR / "azure_nsg_sample.json") as f:
        return json.load(f)


@pytest.fixture
def firewall_data():
    with open(FIXTURES_DIR / "azure_firewall_sample.json") as f:
        return json.load(f)


@pytest.fixture
def waf_data():
    with open(FIXTURES_DIR / "azure_waf_sample.json") as f:
        return json.load(f)


@pytest.fixture
def firewall_log_export_normalized():
    return {
        "exportedAt": "2026-04-05T11:29:25.9470682-07:00",
        "subscription": "Example Firewall Subscription",
        "workspace": "sample-firewall-logs-workspace",
        "workspaceCustomerId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "firewallResourceId": "/subscriptions/11111111-2222-3333-4444-555555555555/resourcegroups/sample-rg-firewall/providers/microsoft.network/azurefirewalls/sample-firewall",
        "summary": [
            {"LogTable": "AZFWDnsQuery", "Count": 1},
            {"LogTable": "AZFWApplicationRule", "Count": 1},
            {"LogTable": "AzureDiagnostics", "Count": 1},
        ],
        "dnsSamples": [
            {
                "TenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "TimeGenerated": "2026-03-24T06:46:56.516467Z",
                "SourceIp": "10.0.1.7",
                "SourcePort": 8348,
                "QueryId": 53842,
                "QueryType": "A",
                "QueryClass": "IN",
                "QueryName": "config-updates.example.net.",
                "Protocol": "udp",
                "ResponseCode": "NOERROR",
                "Type": "AZFWDnsQuery",
                "_ResourceId": "/subscriptions/11111111-2222-3333-4444-555555555555/resourcegroups/sample-rg-firewall/providers/microsoft.network/azurefirewalls/sample-firewall",
            }
        ],
        "applicationSamples": [
            {
                "TenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "TimeGenerated": "2026-03-24T06:45:40.121992Z",
                "Protocol": "HTTPS",
                "SourceIp": "10.0.2.4",
                "SourcePort": 41348,
                "DestinationPort": 443,
                "Fqdn": "storage.example.net",
                "TargetUrl": "",
                "Action": "Allow",
                "Policy": "sample-firewall-policy",
                "RuleCollectionGroup": "DefaultApplicationRuleCollectionGroup",
                "RuleCollection": "allow-web",
                "Rule": "allow-http-https",
                "Type": "AZFWApplicationRule",
                "_ResourceId": "/subscriptions/11111111-2222-3333-4444-555555555555/resourcegroups/sample-rg-firewall/providers/microsoft.network/azurefirewalls/sample-firewall",
            }
        ],
        "diagnosticsSamples": [
            {
                "TenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "TimeGenerated": "2026-03-16T19:31:40.246683Z",
                "Category": "AZFWFlowTrace",
                "SourceIP": "10.0.2.4",
                "SourcePort_d": 45146,
                "DestinationIp_s": "203.0.113.10",
                "DestinationPort_d": 443,
                "Protocol_s": "TCP",
                "Action_s": "Log",
                "ActionReason_s": "Additional TCP Log",
                "Type": "AzureDiagnostics",
                "_ResourceId": "/subscriptions/11111111-2222-3333-4444-555555555555/resourcegroups/sample-rg-firewall/providers/microsoft.network/azurefirewalls/sample-firewall",
            }
        ],
    }


@pytest.fixture
def firewall_log_export_raw():
    return {
        "exportedAt": "2026-04-05T11:28:40.2829663-07:00",
        "subscription": "Example Firewall Subscription",
        "workspace": "sample-firewall-logs-workspace",
        "workspaceCustomerId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "summary": {
            "tables": [
                {
                    "name": "PrimaryResult",
                    "columns": [
                        {"name": "LogTable", "type": "string"},
                        {"name": "Count", "type": "long"},
                    ],
                    "rows": [["AZFWDnsQuery", 1], ["AZFWApplicationRule", 1], ["AzureDiagnostics", 1]],
                }
            ]
        },
        "dnsSamples": {
            "tables": [
                {
                    "name": "PrimaryResult",
                    "columns": [
                        {"name": "TenantId", "type": "string"},
                        {"name": "TimeGenerated", "type": "datetime"},
                        {"name": "SourceIp", "type": "string"},
                        {"name": "SourcePort", "type": "int"},
                        {"name": "QueryId", "type": "int"},
                        {"name": "QueryType", "type": "string"},
                        {"name": "QueryName", "type": "string"},
                        {"name": "Protocol", "type": "string"},
                        {"name": "ResponseCode", "type": "string"},
                        {"name": "Type", "type": "string"},
                    ],
                    "rows": [
                        [
                            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                            "2026-03-24T06:46:56.516467Z",
                            "10.0.1.7",
                            8348,
                            53842,
                            "A",
                            "config-updates.example.net.",
                            "udp",
                            "NOERROR",
                            "AZFWDnsQuery",
                        ]
                    ],
                }
            ]
        },
        "applicationSamples": {
            "tables": [
                {
                    "name": "PrimaryResult",
                    "columns": [
                        {"name": "TimeGenerated", "type": "datetime"},
                        {"name": "Protocol", "type": "string"},
                        {"name": "SourceIp", "type": "string"},
                        {"name": "SourcePort", "type": "int"},
                        {"name": "DestinationPort", "type": "int"},
                        {"name": "Fqdn", "type": "string"},
                        {"name": "Action", "type": "string"},
                        {"name": "Policy", "type": "string"},
                        {"name": "RuleCollectionGroup", "type": "string"},
                        {"name": "RuleCollection", "type": "string"},
                        {"name": "Rule", "type": "string"},
                        {"name": "Type", "type": "string"},
                    ],
                    "rows": [
                        [
                            "2026-03-24T06:45:40.121992Z",
                            "HTTPS",
                            "10.0.2.4",
                            41348,
                            443,
                            "storage.example.net",
                            "Allow",
                            "sample-firewall-policy",
                            "DefaultApplicationRuleCollectionGroup",
                            "allow-web",
                            "allow-http-https",
                            "AZFWApplicationRule",
                        ]
                    ],
                }
            ]
        },
        "diagnosticsSamples": {
            "tables": [
                {
                    "name": "PrimaryResult",
                    "columns": [
                        {"name": "TimeGenerated", "type": "datetime"},
                        {"name": "Category", "type": "string"},
                        {"name": "SourceIP", "type": "string"},
                        {"name": "SourcePort_d", "type": "int"},
                        {"name": "DestinationIp_s", "type": "string"},
                        {"name": "DestinationPort_d", "type": "int"},
                        {"name": "Protocol_s", "type": "string"},
                        {"name": "Action_s", "type": "string"},
                        {"name": "ActionReason_s", "type": "string"},
                        {"name": "Type", "type": "string"},
                    ],
                    "rows": [
                        [
                            "2026-03-16T19:31:40.246683Z",
                            "AZFWFlowTrace",
                            "10.0.2.4",
                            45146,
                            "203.0.113.10",
                            443,
                            "TCP",
                            "Log",
                            "Additional TCP Log",
                            "AzureDiagnostics",
                        ]
                    ],
                }
            ]
        },
    }
