"""Seed the database with a realistic demo Azure NSG audit.

Creates ~50 rules with deliberate misconfigurations, findings across all
severities, and compliance checks so the dashboard is never empty.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Base
from app.models.audit import AuditFinding, AuditReport
from app.models.compliance import ComplianceCheck
from app.models.rule import Rule, RuleSet

# Deterministic namespace so re-seeding is idempotent
_NS = uuid.UUID("00000000-0000-0000-0000-000000000000")

def _id(name: str) -> str:
    return str(uuid.uuid5(_NS, name))


DEMO_RULESET_ID = _id("demo-ruleset")
DEMO_AUDIT_ID = _id("demo-audit")


# ---------------------------------------------------------------------------
# NSG Rules  (~50 rules mimicking a real enterprise config)
# ---------------------------------------------------------------------------

_RULES: list[dict] = [
    # ── Good rules ────────────────────────────────────────────────────
    {"name": "Allow-HTTPS-Inbound", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["*"], "dst": ["10.1.0.0/24"], "dst_ports": ["443"],
     "priority": 100, "desc": "Allow HTTPS from internet to web tier", "risk": 0.1},
    {"name": "Allow-HTTP-Inbound", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["*"], "dst": ["10.1.0.0/24"], "dst_ports": ["80"],
     "priority": 110, "desc": "Allow HTTP for redirect to HTTPS", "risk": 0.3},
    {"name": "Allow-SSH-VPN", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.5.0.0/16"], "dst": ["10.1.0.0/24"], "dst_ports": ["22"],
     "priority": 200, "desc": "SSH from VPN subnet only", "risk": 0.1},
    {"name": "Allow-RDP-VPN", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.5.0.0/16"], "dst": ["10.2.0.0/24"], "dst_ports": ["3389"],
     "priority": 210, "desc": "RDP from VPN to management subnet", "risk": 0.15},
    {"name": "Allow-SQL-AppTier", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["10.3.0.0/24"], "dst_ports": ["1433"],
     "priority": 300, "desc": "SQL Server from app tier only", "risk": 0.1},
    {"name": "Allow-DNS-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "UDP", "src": ["10.0.0.0/8"], "dst": ["168.63.129.16"], "dst_ports": ["53"],
     "priority": 100, "desc": "DNS queries to Azure resolver", "risk": 0.05},
    {"name": "Allow-NTP-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "UDP", "src": ["10.0.0.0/8"], "dst": ["*"], "dst_ports": ["123"],
     "priority": 110, "desc": "NTP time sync", "risk": 0.05},
    {"name": "Allow-AzureMonitor", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.0.0.0/8"], "dst": ["AzureMonitor"], "dst_ports": ["443"],
     "priority": 120, "desc": "Azure Monitor telemetry", "risk": 0.05},
    {"name": "Allow-KeyVault", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["AzureKeyVault"], "dst_ports": ["443"],
     "priority": 130, "desc": "Key Vault access from app tier", "risk": 0.05},
    {"name": "Allow-Storage-Blob", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["Storage"], "dst_ports": ["443"],
     "priority": 140, "desc": "Blob storage access", "risk": 0.1},
    {"name": "Allow-LB-HealthProbe", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["168.63.129.16"], "dst": ["10.1.0.0/24"], "dst_ports": ["65503-65534"],
     "priority": 105, "desc": "Azure Load Balancer health probes", "risk": 0.0},
    {"name": "Allow-AppGateway-Backend", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.0.1.0/24"], "dst": ["10.1.0.0/24"], "dst_ports": ["8080"],
     "priority": 115, "desc": "App Gateway to backend pool", "risk": 0.1},
    {"name": "Allow-Redis-Cache", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["10.4.0.0/24"], "dst_ports": ["6379", "6380"],
     "priority": 310, "desc": "Redis from app tier", "risk": 0.15},
    {"name": "Allow-CosmosDB", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["AzureCosmosDB"], "dst_ports": ["443"],
     "priority": 150, "desc": "Cosmos DB access from app tier", "risk": 0.1},
    {"name": "Allow-ServiceBus", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["ServiceBus"], "dst_ports": ["5671", "5672"],
     "priority": 160, "desc": "Service Bus messaging", "risk": 0.1},

    # ── CRITICAL misconfigurations ────────────────────────────────────
    {"name": "Allow-All-Inbound", "action": "allow", "direction": "inbound",
     "protocol": "*", "src": ["0.0.0.0/0"], "dst": ["*"], "dst_ports": ["*"],
     "priority": 500, "desc": "TEMP: Open all for migration (REMOVE)", "risk": 0.98},
    {"name": "Allow-RDP-Internet", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["0.0.0.0/0"], "dst": ["10.2.0.0/24"], "dst_ports": ["3389"],
     "priority": 400, "desc": "RDP from internet for contractor access", "risk": 0.95},
    {"name": "Allow-SSH-Internet", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["0.0.0.0/0"], "dst": ["10.1.0.0/24"], "dst_ports": ["22"],
     "priority": 410, "desc": "", "risk": 0.92},
    {"name": "Allow-DB-Internet", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["0.0.0.0/0"], "dst": ["10.3.0.0/24"], "dst_ports": ["1433", "3306", "5432"],
     "priority": 420, "desc": "", "risk": 0.97},

    # ── HIGH severity issues ──────────────────────────────────────────
    {"name": "Allow-All-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "*", "src": ["10.0.0.0/8"], "dst": ["0.0.0.0/0"], "dst_ports": ["*"],
     "priority": 500, "desc": "Unrestricted outbound", "risk": 0.75},
    {"name": "Allow-FTP-Inbound", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["*"], "dst": ["10.1.0.0/24"], "dst_ports": ["20", "21"],
     "priority": 320, "desc": "FTP for legacy file transfer", "risk": 0.7},
    {"name": "Allow-Telnet-Inbound", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.100.0.0/16"], "dst": ["10.2.0.0/24"], "dst_ports": ["23"],
     "priority": 330, "desc": "Telnet from partner network", "risk": 0.72},
    {"name": "Allow-SMTP-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.0.0.0/8"], "dst": ["*"], "dst_ports": ["25"],
     "priority": 200, "desc": "SMTP outbound", "risk": 0.65},
    {"name": "Allow-Wide-PortRange", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.100.0.0/16"], "dst": ["10.1.0.0/24"], "dst_ports": ["1024-65535"],
     "priority": 340, "desc": "Partner integration ports", "risk": 0.68},

    # ── MEDIUM severity issues ────────────────────────────────────────
    {"name": "Deny-SSH-Inbound", "action": "deny", "direction": "inbound",
     "protocol": "TCP", "src": ["*"], "dst": ["*"], "dst_ports": ["22"],
     "priority": 600, "desc": "Deny SSH - shadowed by Allow-SSH-Internet (pri 410)", "risk": 0.5},
    {"name": "Deny-RDP-Inbound", "action": "deny", "direction": "inbound",
     "protocol": "TCP", "src": ["*"], "dst": ["*"], "dst_ports": ["3389"],
     "priority": 610, "desc": "Deny RDP - shadowed by Allow-RDP-Internet (pri 400)", "risk": 0.5},
    {"name": "Allow-HTTPS-Dup", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["*"], "dst": ["10.1.0.0/24"], "dst_ports": ["443"],
     "priority": 350, "desc": "Duplicate of rule at priority 100", "risk": 0.3},
    {"name": "Allow-HTTP-Dup", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["*"], "dst": ["10.1.0.0/24"], "dst_ports": ["80"],
     "priority": 360, "desc": "Redundant copy of Allow-HTTP-Inbound", "risk": 0.25},
    {"name": "Allow-ICMP-Any", "action": "allow", "direction": "inbound",
     "protocol": "ICMP", "src": ["*"], "dst": ["*"], "dst_ports": ["*"],
     "priority": 450, "desc": "ICMP from any source", "risk": 0.4},
    {"name": "Allow-MySQL-Wide", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.0.0.0/8"], "dst": ["10.3.0.0/24"], "dst_ports": ["3306"],
     "priority": 305, "desc": "MySQL from entire private range - too broad", "risk": 0.45},
    {"name": "Deny-All-Inbound-Shadowed", "action": "deny", "direction": "inbound",
     "protocol": "*", "src": ["*"], "dst": ["*"], "dst_ports": ["*"],
     "priority": 4096, "desc": "Default deny - completely shadowed by Allow-All-Inbound", "risk": 0.6},

    # ── LOW severity / informational ──────────────────────────────────
    {"name": "Allow-VNET-Inbound", "action": "allow", "direction": "inbound",
     "protocol": "*", "src": ["VirtualNetwork"], "dst": ["VirtualNetwork"], "dst_ports": ["*"],
     "priority": 65000, "desc": "", "risk": 0.1},
    {"name": "Allow-LB-Inbound", "action": "allow", "direction": "inbound",
     "protocol": "*", "src": ["AzureLoadBalancer"], "dst": ["*"], "dst_ports": ["*"],
     "priority": 65001, "desc": "", "risk": 0.05},
    {"name": "Deny-All-Inbound-Default", "action": "deny", "direction": "inbound",
     "protocol": "*", "src": ["*"], "dst": ["*"], "dst_ports": ["*"],
     "priority": 65500, "desc": "Azure default deny-all inbound", "risk": 0.0},
    {"name": "Allow-VNET-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "*", "src": ["VirtualNetwork"], "dst": ["VirtualNetwork"], "dst_ports": ["*"],
     "priority": 65000, "desc": "", "risk": 0.1},
    {"name": "Allow-Internet-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "*", "src": ["*"], "dst": ["Internet"], "dst_ports": ["*"],
     "priority": 65001, "desc": "Azure default allow-internet outbound", "risk": 0.2},
    {"name": "Deny-All-Outbound-Default", "action": "deny", "direction": "outbound",
     "protocol": "*", "src": ["*"], "dst": ["*"], "dst_ports": ["*"],
     "priority": 65500, "desc": "Azure default deny-all outbound", "risk": 0.0},
    {"name": "Allow-Mgmt-HTTPS", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.5.0.0/16"], "dst": ["10.2.0.0/24"], "dst_ports": ["443"],
     "priority": 220, "desc": "HTTPS mgmt from VPN", "risk": 0.1},
    {"name": "Allow-Grafana", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.5.0.0/16"], "dst": ["10.6.0.10"], "dst_ports": ["3000"],
     "priority": 230, "desc": "Grafana from VPN", "risk": 0.1},
    {"name": "Allow-Prometheus", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.6.0.10"], "dst": ["10.0.0.0/8"], "dst_ports": ["9090", "9100"],
     "priority": 240, "desc": "Prometheus scraping", "risk": 0.15},
    {"name": "Allow-ElasticSearch", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["10.7.0.0/24"], "dst_ports": ["9200", "9300"],
     "priority": 315, "desc": "Elasticsearch from app tier", "risk": 0.2},
    {"name": "Allow-Kafka", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["10.8.0.0/24"], "dst_ports": ["9092"],
     "priority": 325, "desc": "Kafka from app tier", "risk": 0.15},
    {"name": "Allow-LDAP-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.0.0.0/8"], "dst": ["10.9.0.5"], "dst_ports": ["389", "636"],
     "priority": 170, "desc": "LDAP/LDAPS to domain controller", "risk": 0.1},
    {"name": "Allow-Syslog-Outbound", "action": "allow", "direction": "outbound",
     "protocol": "UDP", "src": ["10.0.0.0/8"], "dst": ["10.6.0.20"], "dst_ports": ["514"],
     "priority": 180, "desc": "Syslog to SIEM", "risk": 0.05},
    {"name": "Allow-WinRM-Disabled", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.5.0.0/16"], "dst": ["10.2.0.0/24"], "dst_ports": ["5985", "5986"],
     "priority": 250, "desc": "WinRM from VPN (disabled)", "risk": 0.2, "enabled": False},
    {"name": "Allow-Legacy-App", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.100.0.0/16"], "dst": ["10.1.0.50"], "dst_ports": ["8443"],
     "priority": 370, "desc": "Legacy partner app endpoint", "risk": 0.3},
    {"name": "Allow-gRPC", "action": "allow", "direction": "inbound",
     "protocol": "TCP", "src": ["10.1.0.0/24"], "dst": ["10.1.0.0/24"], "dst_ports": ["50051"],
     "priority": 380, "desc": "Internal gRPC communication", "risk": 0.1},
    {"name": "Allow-Docker-Registry", "action": "allow", "direction": "outbound",
     "protocol": "TCP", "src": ["10.0.0.0/8"], "dst": ["AzureContainerRegistry"], "dst_ports": ["443"],
     "priority": 190, "desc": "ACR pull access", "risk": 0.05},
]


def _build_rule_objects(ruleset_id: str) -> list[Rule]:
    rules = []
    for i, r in enumerate(_RULES):
        rules.append(Rule(
            id=_id(f"rule-{i}"),
            ruleset_id=ruleset_id,
            original_id=f"nsg-sample-{i+1:03d}",
            name=r["name"],
            action=r["action"],
            direction=r["direction"],
            protocol=r.get("protocol"),
            source_addresses=json.dumps(r.get("src", ["*"])),
            source_ports=json.dumps(["*"]),
            dest_addresses=json.dumps(r.get("dst", ["*"])),
            dest_ports=json.dumps(r.get("dst_ports", ["*"])),
            priority=r.get("priority"),
            description=r.get("desc", ""),
            enabled=r.get("enabled", True),
            risk_score=r.get("risk", 0.0),
            tags=json.dumps({}),
        ))
    return rules


# ---------------------------------------------------------------------------
# Findings — realistic audit output
# ---------------------------------------------------------------------------

def _build_findings(audit_id: str) -> list[AuditFinding]:
    findings = []

    def _f(sev: str, cat: str, title: str, desc: str, rec: str,
           conf: float, rule_names: list[str], source: str = "verified"):
        # Resolve rule name → rule id
        rule_idx_by_name = {r["name"]: i for i, r in enumerate(_RULES)}
        affected = [_id(f"rule-{rule_idx_by_name[n]}") for n in rule_names if n in rule_idx_by_name]
        primary = affected[0] if affected else None
        findings.append(AuditFinding(
            id=_id(f"finding-{len(findings)}"),
            audit_id=audit_id,
            rule_id=primary,
            related_rule_ids=json.dumps(affected),
            severity=sev,
            category=cat,
            title=title,
            description=desc,
            recommendation=rec,
            confidence=conf,
            source=source,
        ))

    # Critical
    _f("critical", "overly_permissive",
       "Unrestricted inbound access from internet",
       "Rule 'Allow-All-Inbound' (priority 500) permits ALL protocols from 0.0.0.0/0 to ANY destination on ALL ports. "
       "This completely bypasses all other security rules and exposes the entire network to the internet. "
       "The description says 'TEMP: Open all for migration' suggesting this was meant to be temporary.",
       "Remove 'Allow-All-Inbound' immediately. If migration requires open access, create specific rules for the required ports and source IPs only.",
       0.99, ["Allow-All-Inbound"])

    _f("critical", "overly_permissive",
       "RDP (3389) exposed to internet",
       "Rule 'Allow-RDP-Internet' (priority 400) allows RDP from 0.0.0.0/0 to the management subnet 10.2.0.0/24. "
       "RDP is a primary attack vector for ransomware and brute-force attacks. This is never acceptable in production.",
       "Remove 'Allow-RDP-Internet'. Use Azure Bastion or VPN-restricted access (already available via 'Allow-RDP-VPN' at priority 210).",
       0.98, ["Allow-RDP-Internet"])

    _f("critical", "overly_permissive",
       "Database ports exposed to internet",
       "Rule 'Allow-DB-Internet' (priority 420) exposes SQL Server (1433), MySQL (3306), and PostgreSQL (5432) to 0.0.0.0/0. "
       "Database services should never be directly accessible from the internet. This is a critical data exfiltration risk.",
       "Remove 'Allow-DB-Internet' immediately. Database access should be restricted to application tier subnets only.",
       0.99, ["Allow-DB-Internet"])

    _f("critical", "overly_permissive",
       "SSH (22) exposed to internet without restriction",
       "Rule 'Allow-SSH-Internet' (priority 410) allows SSH from 0.0.0.0/0. Combined with the missing description, "
       "this appears to be an unauthorized or accidental rule. SSH from the internet enables brute-force attacks.",
       "Remove 'Allow-SSH-Internet'. SSH access is already properly scoped via 'Allow-SSH-VPN' (priority 200) from 10.5.0.0/16.",
       0.97, ["Allow-SSH-Internet"])

    # High
    _f("high", "overly_permissive",
       "Unrestricted outbound to internet",
       "Rule 'Allow-All-Outbound' (priority 500) permits all traffic from the private range to 0.0.0.0/0. "
       "This enables data exfiltration, C2 callbacks, and crypto-mining. Outbound should be restricted to known services.",
       "Replace with specific allow rules for required outbound destinations (DNS, NTP, Azure services). Deny all other outbound traffic.",
       0.92, ["Allow-All-Outbound"])

    _f("high", "best_practice",
       "Insecure protocol: FTP (ports 20-21) allowed",
       "Rule 'Allow-FTP-Inbound' permits FTP from any source. FTP transmits credentials in plaintext "
       "and is a known vector for malware delivery.",
       "Replace FTP with SFTP (port 22 from trusted sources) or Azure File Sync. Remove 'Allow-FTP-Inbound'.",
       0.95, ["Allow-FTP-Inbound"])

    _f("high", "best_practice",
       "Insecure protocol: Telnet (port 23) allowed",
       "Rule 'Allow-Telnet-Inbound' permits Telnet from partner network. Telnet transmits all data including "
       "credentials in plaintext, making it vulnerable to network sniffing attacks.",
       "Replace with SSH (port 22) from the partner network 10.100.0.0/16. Remove 'Allow-Telnet-Inbound'.",
       0.94, ["Allow-Telnet-Inbound"])

    _f("high", "overly_permissive",
       "Open SMTP relay risk",
       "Rule 'Allow-SMTP-Outbound' allows port 25 to any destination from the entire private range. "
       "This can be exploited for spam relay or email-based data exfiltration.",
       "Restrict SMTP outbound to your organization's mail servers only, or use Azure Communication Services for outbound email.",
       0.88, ["Allow-SMTP-Outbound"])

    _f("high", "overly_permissive",
       "Excessively wide port range allowed",
       "Rule 'Allow-Wide-PortRange' opens ports 1024-65535 from the partner network. This is effectively an allow-all "
       "for ephemeral ports and exposes numerous services unnecessarily.",
       "Identify the specific ports required for partner integration and create targeted rules. Remove the wide range.",
       0.90, ["Allow-Wide-PortRange"])

    # Medium
    _f("medium", "shadowed",
       "Deny-SSH rule is shadowed",
       "Rule 'Deny-SSH-Inbound' (priority 600) will never trigger because 'Allow-SSH-Internet' (priority 410) "
       "and 'Allow-All-Inbound' (priority 500) both match SSH traffic at higher priority.",
       "Remove 'Deny-SSH-Inbound' as it provides false sense of security. Fix the allow rules instead.",
       0.96, ["Deny-SSH-Inbound", "Allow-SSH-Internet"])

    _f("medium", "shadowed",
       "Deny-RDP rule is shadowed",
       "Rule 'Deny-RDP-Inbound' (priority 610) is bypassed by 'Allow-RDP-Internet' (priority 400) "
       "and 'Allow-All-Inbound' (priority 500).",
       "Remove the shadowed deny rule after fixing the allow rules that override it.",
       0.96, ["Deny-RDP-Inbound", "Allow-RDP-Internet"])

    _f("medium", "shadowed",
       "Default deny-all completely shadowed",
       "The explicit deny-all at priority 4096 is fully shadowed by 'Allow-All-Inbound' at priority 500. "
       "The intent to deny unmatched traffic is defeated.",
       "Remove the 'Allow-All-Inbound' rule to restore the deny-all's effectiveness.",
       0.98, ["Deny-All-Inbound-Shadowed", "Allow-All-Inbound"])

    _f("medium", "unused",
       "Duplicate HTTPS inbound rule",
       "'Allow-HTTPS-Dup' (priority 350) duplicates 'Allow-HTTPS-Inbound' (priority 100) exactly. "
       "The duplicate is never evaluated because the original matches first.",
       "Remove 'Allow-HTTPS-Dup' to reduce rule clutter.",
       0.93, ["Allow-HTTPS-Dup", "Allow-HTTPS-Inbound"])

    _f("medium", "unused",
       "Duplicate HTTP inbound rule",
       "'Allow-HTTP-Dup' (priority 360) is a redundant copy of 'Allow-HTTP-Inbound' (priority 110).",
       "Remove 'Allow-HTTP-Dup'.",
       0.93, ["Allow-HTTP-Dup", "Allow-HTTP-Inbound"])

    _f("medium", "overly_permissive",
       "ICMP allowed from any source",
       "'Allow-ICMP-Any' permits ICMP from all sources. While ICMP is useful for diagnostics, "
       "unrestricted ICMP enables network reconnaissance and certain DoS attacks.",
       "Restrict ICMP to internal subnets and the VPN range. Block ICMP from 0.0.0.0/0.",
       0.82, ["Allow-ICMP-Any"])

    _f("medium", "overly_permissive",
       "MySQL access too broad",
       "'Allow-MySQL-Wide' grants MySQL access from the entire 10.0.0.0/8 range instead of just the app tier. "
       "Any compromised host in the private network could access the database.",
       "Narrow the source to 10.1.0.0/24 (app tier) only, matching the pattern used for SQL Server.",
       0.87, ["Allow-MySQL-Wide"])

    # Low
    _f("low", "best_practice",
       "Multiple rules missing descriptions",
       "Rules 'Allow-SSH-Internet', 'Allow-DB-Internet', 'Allow-VNET-Inbound', 'Allow-LB-Inbound' and "
       "3 other rules have empty descriptions. This hinders auditing and incident response.",
       "Add meaningful descriptions to all rules explaining their business purpose and expected review date.",
       0.90, ["Allow-SSH-Internet", "Allow-DB-Internet", "Allow-VNET-Inbound", "Allow-LB-Inbound"])

    _f("low", "best_practice",
       "Disabled rule should be cleaned up",
       "'Allow-WinRM-Disabled' is disabled but still present. Disabled rules add clutter and may be "
       "accidentally re-enabled.",
       "Remove disabled rules or document why they are kept. Set a review date.",
       0.85, ["Allow-WinRM-Disabled"])

    _f("low", "best_practice",
       "Inconsistent rule naming conventions",
       "Some rules use 'Allow-' or 'Deny-' prefix while default Azure rules don't. Some use camelCase "
       "for service names while others use hyphens. A consistent naming convention improves manageability.",
       "Adopt a consistent naming convention like: {Action}-{Direction}-{Source}-{Dest}-{Service}.",
       0.78, ["Allow-Legacy-App", "Allow-gRPC"])

    return findings


# ---------------------------------------------------------------------------
# Compliance checks
# ---------------------------------------------------------------------------

def _build_compliance(audit_id: str) -> list[ComplianceCheck]:
    checks = []

    def _c(fw: str, ctrl_id: str, title: str, status: str, evidence: str, rule_names: list[str]):
        rule_idx_by_name = {r["name"]: i for i, r in enumerate(_RULES)}
        affected = [_id(f"rule-{rule_idx_by_name[n]}") for n in rule_names if n in rule_idx_by_name]
        checks.append(ComplianceCheck(
            id=_id(f"compliance-{fw}-{ctrl_id}"),
            audit_id=audit_id,
            framework=fw,
            control_id=ctrl_id,
            control_title=title,
            status=status,
            evidence=evidence,
            affected_rule_ids=json.dumps(affected),
        ))

    # CIS Azure v2.0
    _c("cis_azure_v2", "CIS-6.1", "Ensure that RDP access is restricted from the internet",
       "fail", "Rule 'Allow-RDP-Internet' permits RDP from 0.0.0.0/0.", ["Allow-RDP-Internet"])
    _c("cis_azure_v2", "CIS-6.2", "Ensure that SSH access is restricted from the internet",
       "fail", "Rule 'Allow-SSH-Internet' permits SSH from 0.0.0.0/0.", ["Allow-SSH-Internet"])
    _c("cis_azure_v2", "CIS-6.3", "Ensure no NSG allows inbound from 0.0.0.0/0 to any port",
       "fail", "'Allow-All-Inbound' permits all traffic from 0.0.0.0/0.", ["Allow-All-Inbound"])
    _c("cis_azure_v2", "CIS-6.4", "Ensure that UDP services are restricted from the internet",
       "pass", "No UDP rules allow unrestricted internet access.", [])
    _c("cis_azure_v2", "CIS-6.5", "Ensure that Network Security Groups are strict",
       "fail", "Multiple overly permissive rules and shadowed deny rules detected.", ["Allow-All-Inbound", "Allow-All-Outbound"])
    _c("cis_azure_v2", "CIS-6.6", "Ensure that HTTP (80) access is restricted",
       "pass", "HTTP is allowed only to web tier 10.1.0.0/24 for HTTPS redirect.", ["Allow-HTTP-Inbound"])
    _c("cis_azure_v2", "CIS-6.7", "Ensure that Network Watcher is enabled",
       "not_applicable", "Network Watcher configuration is outside NSG rule scope.", [])

    # PCI DSS v4.0
    _c("pci_dss_v4", "PCI-1.3.1", "Restrict inbound traffic to system components in the CDE",
       "fail", "Allow-All-Inbound violates CDE segmentation.", ["Allow-All-Inbound"])
    _c("pci_dss_v4", "PCI-1.3.2", "Restrict outbound traffic from the CDE",
       "fail", "Allow-All-Outbound allows unrestricted egress.", ["Allow-All-Outbound"])
    _c("pci_dss_v4", "PCI-1.3.4", "Block unauthorized traffic between zones",
       "fail", "Multiple rules allow cross-zone traffic too broadly.", ["Allow-MySQL-Wide", "Allow-Wide-PortRange"])
    _c("pci_dss_v4", "PCI-1.4.1", "Implement NSGs on all subnets",
       "pass", "NSG is attached with default deny.", [])
    _c("pci_dss_v4", "PCI-2.2.7", "Disable unnecessary services and protocols",
       "fail", "FTP and Telnet (insecure protocols) are permitted.", ["Allow-FTP-Inbound", "Allow-Telnet-Inbound"])
    _c("pci_dss_v4", "PCI-8.3.1", "Ensure strong authentication for admin access",
       "not_applicable", "Authentication is outside NSG scope; however RDP/SSH exposure increases risk.", [])

    return checks


# ---------------------------------------------------------------------------
# Main seed function
# ---------------------------------------------------------------------------

async def seed_demo(db: AsyncSession) -> dict:
    """Insert demo audit data. Idempotent — skips if demo already exists."""

    # Check if demo already exists
    existing = await db.execute(
        select(AuditReport).where(AuditReport.id == DEMO_AUDIT_ID)
    )
    if existing.scalar_one_or_none():
        return {"status": "already_seeded", "audit_id": DEMO_AUDIT_ID}

    # Build raw JSON that resembles an uploaded NSG export
    raw_nsg = {
        "name": "nsg-sample",
        "location": "eastus",
        "properties": {
            "securityRules": [
                {
                    "name": r["name"],
                    "properties": {
                        "access": r["action"].capitalize(),
                        "direction": r["direction"].capitalize(),
                        "protocol": r.get("protocol", "*"),
                        "sourceAddressPrefixes": r.get("src", ["*"]),
                        "destinationAddressPrefixes": r.get("dst", ["*"]),
                        "destinationPortRanges": r.get("dst_ports", ["*"]),
                        "priority": r.get("priority", 100),
                        "description": r.get("desc", ""),
                    },
                }
                for r in _RULES
            ]
        },
    }

    now = datetime.now(timezone.utc)

    # Create RuleSet
    ruleset = RuleSet(
        id=DEMO_RULESET_ID,
        filename="nsg-sample-export.json",
        vendor="azure_nsg",
        raw_json=json.dumps(raw_nsg),
        rule_count=len(_RULES),
        uploaded_at=now - timedelta(minutes=5),
    )
    db.add(ruleset)

    # Create Rules
    for rule in _build_rule_objects(DEMO_RULESET_ID):
        db.add(rule)

    # Create Findings
    all_findings = _build_findings(DEMO_AUDIT_ID)

    # Tally severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    # Create AuditReport
    audit = AuditReport(
        id=DEMO_AUDIT_ID,
        ruleset_id=DEMO_RULESET_ID,
        status="completed",
        summary=(
         f"Audit of nsg-sample identified {len(all_findings)} security findings across "
            f"{len(_RULES)} rules. "
            f"{sev_counts['critical']} critical and {sev_counts['high']} high-severity issues "
            "require immediate attention. The most urgent finding is an unrestricted "
            "allow-all inbound rule that exposes the entire network to the internet, "
            "along with RDP, SSH, and database ports open to 0.0.0.0/0. "
            "Several deny rules are shadowed and provide no effective protection."
        ),
        total_findings=len(all_findings),
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        medium_count=sev_counts["medium"],
        low_count=sev_counts["low"],
        created_at=now - timedelta(minutes=5),
        completed_at=now - timedelta(minutes=2),
    )
    db.add(audit)

    for f in all_findings:
        db.add(f)

    # Create Compliance Checks
    for cc in _build_compliance(DEMO_AUDIT_ID):
        db.add(cc)

    await db.commit()

    return {
        "status": "seeded",
        "audit_id": DEMO_AUDIT_ID,
        "rule_count": len(_RULES),
        "finding_count": len(all_findings),
    }
