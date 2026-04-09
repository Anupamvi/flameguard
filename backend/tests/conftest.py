import json
import os
from pathlib import Path

import pytest

from app.security import reset_security_state

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def reset_hardening_state():
    reset_security_state()
    yield
    reset_security_state()


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
        "workspaceCustomerId": "00000000-0000-0000-0000-000000000000",
        "firewallResourceId": "/subscriptions/11111111-2222-3333-4444-555555555555/resourcegroups/sample-rg-firewall/providers/microsoft.network/azurefirewalls/sample-firewall",
        "summary": [
            {"LogTable": "AZFWDnsQuery", "Count": 1},
            {"LogTable": "AZFWApplicationRule", "Count": 1},
            {"LogTable": "AzureDiagnostics", "Count": 1},
        ],
        "dnsSamples": [
            {
                "TenantId": "00000000-0000-0000-0000-000000000000",
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
                "TenantId": "00000000-0000-0000-0000-000000000000",
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
                "TenantId": "00000000-0000-0000-0000-000000000000",
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
        "workspaceCustomerId": "00000000-0000-0000-0000-000000000000",
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
                            "00000000-0000-0000-0000-000000000000",
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



@pytest.fixture
def waf_log_export_raw():
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Category", "type": "string"},
                    {"name": "clientIP_s", "type": "string"},
                    {"name": "clientPort_d", "type": "real"},
                    {"name": "HostName_s", "type": "string"},
                    {"name": "requestUri_s", "type": "string"},
                    {"name": "ruleId_s", "type": "string"},
                    {"name": "ruleName_s", "type": "string"},
                    {"name": "action_s", "type": "string"},
                    {"name": "sslEnabled_s", "type": "string"},
                    {"name": "Message", "type": "string"},
                    {"name": "transactionId_g", "type": "string"},
                    {"name": "listenerName_s", "type": "string"},
                    {"name": "priority_d", "type": "real"},
                ],
                "rows": [
                    [
                        "2026-04-06T10:14:33.100000Z",
                        "ApplicationGatewayFirewallLog",
                        "198.51.100.24",
                        58231,
                        "shop.contoso.com",
                        "https://shop.contoso.com/login?debug=1",
                        "942100",
                        "SQLiBlock",
                        "Blocked",
                        "true",
                        "Detected SQL injection pattern",
                        "11111111-2222-3333-4444-555555555555",
                        "public-https-listener",
                        100,
                    ]
                ],
            }
        ]
    }


@pytest.fixture
def waf_log_export_bundle(waf_log_export_raw):
    return {
        "exportedAt": "2026-04-06T12:34:24.7235460-07:00",
        "workspace": {
            "name": "sample-log-analytics",
            "customerId": "00000000-0000-0000-0000-000000000000",
        },
        "wafResources": [
            {
                "name": "sample-app-gateway",
                "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-rg-appgw/providers/Microsoft.Network/applicationGateways/sample-app-gateway",
            }
        ],
        "diagnosticSettings": [
            {
                "name": "sample-diagnostic-setting",
                "categories": [
                    "ApplicationGatewayAccessLog",
                    "ApplicationGatewayPerformanceLog",
                    "ApplicationGatewayFirewallLog",
                ],
            }
        ],
        "summary": {"TotalRows": 1},
        "sampleLogs": waf_log_export_raw,
    }


@pytest.fixture
def waf_log_export_empty_raw():
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TenantId", "type": "string"},
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Category", "type": "string"},
                    {"name": "Message", "type": "string"},
                    {"name": "clientIP_s", "type": "string"},
                    {"name": "HostName_s", "type": "string"},
                    {"name": "listenerName_s", "type": "string"},
                    {"name": "originalRequestUriWithArgs_s", "type": "string"},
                    {"name": "transactionId_g", "type": "string"},
                ],
                "rows": [],
            }
        ]
    }


@pytest.fixture
def waf_log_export_appgw_csv() -> bytes:
    return b"""TenantId,TimeGenerated [UTC],ResourceId,Category,requestUri_s,ruleId_s,ruleName_s,action_s,details_message_s,hostname_s,policyId_s,policyScope_s,policyScopeName_s,engine_s,timeStamp_t [UTC],transactionId_g,clientIp_s,clientPort_s,listenerName_s,Type,_ResourceId\n00000000-0000-0000-0000-000000000000,2023-07-30T23:55:35.522Z,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-rg-appgw/providers/Microsoft.Network/applicationGateways/sample-appgw,ApplicationGatewayFirewallLog,https://shop.contoso.com/login?debug=1,942100,SQLiBlock,Blocked,Detected SQL injection pattern,shop.contoso.com,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-rg-appgw/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/sample-policy,Global,Global,Azwaf,2023-07-30T23:54:23.000Z,11111111-2222-3333-4444-555555555555,198.51.100.24,58231,public-https-listener,AzureDiagnostics,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-rg-appgw/providers/Microsoft.Network/applicationGateways/sample-appgw\n"""


@pytest.fixture
def waf_log_export_afd_csv() -> bytes:
    return b"""TenantId,TimeGenerated [UTC],ResourceId,Category,requestUri_s,ruleName_s,action_s,details_matches_s,hostName_s,trackingReference_s,policyMode_s,clientIp_s,clientPort_s,Type,_ResourceId\n00000000-0000-0000-0000-000000000000,2023-06-27T05:13:01.577Z,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-rg-frontdoor/providers/Microsoft.Cdn/profiles/sample-frontdoor,FrontDoorWebApplicationFirewallLog,https://sample-frontdoor.example.invalid:443/,RedirectFirefoxUserAgent,Redirect,"[{""matchVariableName"":""HeaderValue:user-agent"",""matchVariableValue"":""rv:109.0""}]",sample-frontdoor.example.invalid,03W+aZAAAAAA,prevention,203.0.113.8,61084,AzureDiagnostics,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-rg-frontdoor/providers/Microsoft.Cdn/profiles/sample-frontdoor\n"""


@pytest.fixture
def gsa_audit_log_export_raw():
    return {
        "value": [
            {
                "id": "8f2c2921-8f1b-4db3-9c5f-5f1a6d117901",
                "activityDateTime": "2026-04-08T10:15:00Z",
                "loggedByService": "Global Secure Access",
                "category": "Forwarding Profiles",
                "activityDisplayName": "Updated forwarding profile",
                "operationType": "Update",
                "result": "success",
                "resultReason": "Forwarding profile updated successfully",
                "initiatedBy": {
                    "user": {
                        "userPrincipalName": "admin@contoso.com",
                        "displayName": "Contoso Admin",
                    }
                },
                "targetResources": [
                    {"displayName": "Corporate forwarding profile", "type": "ForwardingProfile"}
                ],
            }
        ]
    }


@pytest.fixture
def gsa_audit_log_export_csv() -> bytes:
    return b"""Activity Date Time,Logged By Service,Category,Activity Display Name,Operation Type,Result,Result Reason,Initiated By,Target Resources,Id\n2026-04-08T10:15:00Z,Global Secure Access,Forwarding Profiles,Updated forwarding profile,Update,success,Forwarding profile updated successfully,admin@contoso.com,Corporate forwarding profile,8f2c2921-8f1b-4db3-9c5f-5f1a6d117901\n"""


@pytest.fixture
def gsa_traffic_log_export_raw():
    return {
        "tables": [
            {
                "name": "NetworkAccessTraffic",
                "columns": [
                    {"name": "ActivityDateTime", "type": "datetime"},
                    {"name": "ConnectionId", "type": "string"},
                    {"name": "TransactionId", "type": "string"},
                    {"name": "TrafficType", "type": "string"},
                    {"name": "Action", "type": "string"},
                    {"name": "Protocol", "type": "string"},
                    {"name": "SourceIp", "type": "string"},
                    {"name": "SourcePort", "type": "int"},
                    {"name": "DestinationFqdn", "type": "string"},
                    {"name": "DestinationPort", "type": "int"},
                    {"name": "UserPrincipalName", "type": "string"},
                    {"name": "DeviceCategory", "type": "string"},
                    {"name": "Category", "type": "string"},
                ],
                "rows": [
                    [
                        "2026-04-08T10:20:00Z",
                        "conn-12345",
                        "txn-67890",
                        "Microsoft 365",
                        "Denied",
                        "HTTPS",
                        "198.51.100.24",
                        58231,
                        "sharepoint.contoso.com",
                        443,
                        "alex@contoso.com",
                        "client",
                        "NetworkAccessTrafficLogs",
                    ]
                ],
            }
        ]
    }


@pytest.fixture
def gsa_deployment_log_export_raw():
    return {
        "records": [
            {
                "Date": "2026-04-08T10:25:00Z",
                "Activity": "Redistribute Forwarding Profile",
                "Status": "Deployment Successful",
                "Initiated By": "admin@contoso.com",
                "Type": "forwardingProfile",
                "Request ID": "req-123456",
                "Error Messages": "",
            }
        ]
    }
