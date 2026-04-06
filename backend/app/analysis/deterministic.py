"""Deterministic rule analysis engine.

Runs fast, pattern-based checks against parsed rules to flag known-bad
patterns WITHOUT using an LLM.  Results are stored alongside LLM findings
so users can see which issues were independently verified.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

from app.parsers.base import NormalizedRule, RuleAction, RuleDirection

logger = logging.getLogger(__name__)

# Ports that should never be internet-exposed
SENSITIVE_PORTS: dict[str, str] = {
    "22": "SSH",
    "3389": "RDP",
    "23": "Telnet",
    "21": "FTP",
    "20": "FTP-Data",
    "1433": "MSSQL",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "5900": "VNC",
    "445": "SMB",
    "135": "RPC",
    "139": "NetBIOS",
    "161": "SNMP",
    "2049": "NFS",
    "11211": "Memcached",
}

# CIDRs that represent "the entire internet"
INTERNET_SOURCES = {"0.0.0.0/0", "*", "any", "internet", "0.0.0.0"}

# Wildcard port tokens
WILDCARD_PORTS = {"*", "0-65535", "any", "0-65535/tcp", "0-65535/udp"}


@dataclass
class DeterministicFinding:
    """A finding produced by pattern-matching, no LLM involved."""

    check_id: str  # unique identifier for the check (e.g. "DET-001")
    severity: str  # critical, high, medium, low
    category: str  # maps to existing audit categories
    title: str
    description: str
    recommendation: str
    confidence: float  # always 1.0 for deterministic checks
    affected_rules: list[str]  # rule names
    source: str = "deterministic"


def _is_internet_source(addresses: list[str]) -> bool:
    """Check if source addresses include the entire internet."""
    for addr in addresses:
        if addr.lower().strip() in INTERNET_SOURCES:
            return True
    return False


def _is_wildcard_ports(ports: list[str]) -> bool:
    """Check if ports represent all ports."""
    for p in ports:
        if p.strip().lower() in WILDCARD_PORTS:
            return True
    return False


def _port_matches(rule_ports: list[str], target_port: str) -> bool:
    """Check if a rule's port list covers a specific target port."""
    tp = int(target_port)
    for p in rule_ports:
        p = p.strip()
        if p.lower() in WILDCARD_PORTS:
            return True
        if "-" in p:
            parts = p.split("-")
            try:
                if int(parts[0]) <= tp <= int(parts[1]):
                    return True
            except (ValueError, IndexError):
                continue
        else:
            try:
                if int(p) == tp:
                    return True
            except ValueError:
                continue
    return False


def _is_wide_cidr(addresses: list[str], threshold: int = 16) -> list[str]:
    """Return addresses with CIDR prefix <= threshold (overly broad)."""
    wide = []
    for addr in addresses:
        addr = addr.strip()
        if addr.lower() in INTERNET_SOURCES:
            continue  # handled by internet-source check
        try:
            net = ipaddress.ip_network(addr, strict=False)
            if net.prefixlen <= threshold:
                wide.append(addr)
        except ValueError:
            continue
    return wide


def _effective_priority(rule: NormalizedRule) -> int:
    """Return the effective priority for ordering.
    For Azure Firewall, collection_priority matters first, then rule priority.
    For NSG, just priority.
    """
    if rule.collection_priority is not None and rule.priority is not None:
        return rule.collection_priority * 100000 + rule.priority
    return rule.priority or 0


def check_internet_exposed_allow(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """DET-001: Inbound Allow from 0.0.0.0/0 (any-any or all-ports)."""
    findings: list[DeterministicFinding] = []
    for rule in rules:
        if rule.action != RuleAction.ALLOW:
            continue
        if rule.direction == RuleDirection.OUTBOUND:
            continue
        if not rule.enabled:
            continue
        if not _is_internet_source(rule.source_addresses):
            continue
        if _is_wildcard_ports(rule.destination_ports):
            findings.append(DeterministicFinding(
                check_id="DET-001",
                severity="critical",
                category="overly_permissive",
                title=f"Internet-exposed allow-all rule: {rule.name}",
                description=(
                    f"Rule '{rule.name}' allows ALL inbound traffic from the internet "
                    f"(source: 0.0.0.0/0) on all ports. This is the most dangerous "
                    f"configuration possible — any service on the network is reachable."
                ),
                recommendation=(
                    "Remove this rule immediately. Replace with specific rules that "
                    "allow only required ports from known source CIDRs."
                ),
                confidence=1.0,
                affected_rules=[rule.name],
            ))
    return findings


def check_sensitive_ports_exposed(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """DET-002: Sensitive ports (SSH, RDP, DB, etc.) exposed to internet."""
    findings: list[DeterministicFinding] = []
    for rule in rules:
        if rule.action != RuleAction.ALLOW:
            continue
        if rule.direction == RuleDirection.OUTBOUND:
            continue
        if not rule.enabled:
            continue
        if not _is_internet_source(rule.source_addresses):
            continue

        exposed: list[str] = []
        for port, service in SENSITIVE_PORTS.items():
            if _port_matches(rule.destination_ports, port):
                exposed.append(f"{service} ({port})")

        if exposed:
            services_str = ", ".join(exposed)
            severity = "critical" if any(
                s.startswith(("SSH", "RDP", "Telnet", "VNC", "SMB"))
                for s in exposed
            ) else "high"
            findings.append(DeterministicFinding(
                check_id="DET-002",
                severity=severity,
                category="overly_permissive",
                title=f"Sensitive port(s) internet-exposed: {rule.name}",
                description=(
                    f"Rule '{rule.name}' exposes {services_str} to the entire "
                    f"internet (source: 0.0.0.0/0). These services are common "
                    f"attack targets for brute-force and exploitation."
                ),
                recommendation=(
                    f"Restrict source to specific IP ranges or VPN CIDRs. "
                    f"For remote access (SSH/RDP), use Azure Bastion or a "
                    f"jump box instead of direct internet exposure."
                ),
                confidence=1.0,
                affected_rules=[rule.name],
            ))
    return findings


def check_any_any_allow(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """DET-003: Allow rule with any source, any destination, any port, any protocol."""
    findings: list[DeterministicFinding] = []
    for rule in rules:
        if rule.action != RuleAction.ALLOW:
            continue
        if not rule.enabled:
            continue

        any_src = _is_internet_source(rule.source_addresses) or not rule.source_addresses
        any_dst = (
            not rule.destination_addresses
            or any(a.lower().strip() in INTERNET_SOURCES for a in rule.destination_addresses)
        )
        any_port = _is_wildcard_ports(rule.destination_ports) or not rule.destination_ports
        any_proto = rule.protocol.lower() in ("any", "*", "")

        if any_src and any_dst and any_port and any_proto:
            findings.append(DeterministicFinding(
                check_id="DET-003",
                severity="critical",
                category="overly_permissive",
                title=f"Unrestricted any-any-any allow rule: {rule.name}",
                description=(
                    f"Rule '{rule.name}' allows all traffic from any source to any "
                    f"destination on any port using any protocol. This effectively "
                    f"disables the firewall for traffic matching this rule."
                ),
                recommendation=(
                    "Replace with specific rules that follow least-privilege: "
                    "define exact source CIDRs, destination CIDRs, ports, and protocols."
                ),
                confidence=1.0,
                affected_rules=[rule.name],
            ))
    return findings


def check_wide_cidr_source(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """DET-004: Allow rules with excessively wide source CIDRs (/16 or broader)."""
    findings: list[DeterministicFinding] = []
    for rule in rules:
        if rule.action != RuleAction.ALLOW:
            continue
        if not rule.enabled:
            continue

        wide = _is_wide_cidr(rule.source_addresses, threshold=16)
        if wide:
            findings.append(DeterministicFinding(
                check_id="DET-004",
                severity="high",
                category="overly_permissive",
                title=f"Overly broad source CIDR: {rule.name}",
                description=(
                    f"Rule '{rule.name}' allows traffic from overly broad source "
                    f"ranges: {', '.join(wide)}. A /16 covers 65,536 IPs; a /8 "
                    f"covers 16 million."
                ),
                recommendation=(
                    "Narrow source CIDRs to the smallest ranges needed. "
                    "Use /24 or smaller where possible."
                ),
                confidence=1.0,
                affected_rules=[rule.name],
            ))
    return findings


def check_shadowed_rules(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """DET-005: Rules that are completely shadowed by a higher-priority rule."""
    findings: list[DeterministicFinding] = []

    # Only check rules that have priorities
    prioritized = [r for r in rules if r.priority is not None and r.enabled]
    if len(prioritized) < 2:
        return findings

    # Group by direction
    for direction in (RuleDirection.INBOUND, RuleDirection.OUTBOUND, RuleDirection.BOTH):
        dir_rules = [r for r in prioritized if r.direction == direction or r.direction == RuleDirection.BOTH]
        # Sort by effective priority (lower number = higher priority for Azure)
        dir_rules.sort(key=_effective_priority)

        for i, later_rule in enumerate(dir_rules):
            for earlier_rule in dir_rules[:i]:
                # A deny-all earlier shadows a later allow
                if (
                    earlier_rule.action == RuleAction.DENY
                    and later_rule.action == RuleAction.ALLOW
                    and _is_wildcard_ports(earlier_rule.destination_ports)
                    and (
                        _is_internet_source(earlier_rule.source_addresses)
                        or not earlier_rule.source_addresses
                    )
                    and earlier_rule.protocol.lower() in ("any", "*", "")
                ):
                    findings.append(DeterministicFinding(
                        check_id="DET-005",
                        severity="medium",
                        category="shadowed",
                        title=f"Rule shadowed by higher-priority deny-all: {later_rule.name}",
                        description=(
                            f"Rule '{later_rule.name}' (priority {_effective_priority(later_rule)}) "
                            f"is shadowed by deny-all rule '{earlier_rule.name}' "
                            f"(priority {_effective_priority(earlier_rule)}). "
                            f"The allow rule will never match any traffic."
                        ),
                        recommendation=(
                            f"Either remove '{later_rule.name}' (it has no effect) "
                            f"or adjust priorities so it evaluates before the deny-all."
                        ),
                        confidence=1.0,
                        affected_rules=[later_rule.name, earlier_rule.name],
                    ))
                    break  # Only report the first shadowing rule

    return findings


def check_insecure_protocols(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """DET-006: Rules allowing inherently insecure protocols (FTP, Telnet, HTTP)."""
    findings: list[DeterministicFinding] = []
    INSECURE_PORTS = {"21": "FTP", "23": "Telnet", "20": "FTP-Data", "69": "TFTP", "161": "SNMP"}

    for rule in rules:
        if rule.action != RuleAction.ALLOW:
            continue
        if not rule.enabled:
            continue

        insecure_found: list[str] = []
        for port, proto in INSECURE_PORTS.items():
            if _port_matches(rule.destination_ports, port):
                insecure_found.append(f"{proto} ({port})")

        if insecure_found:
            findings.append(DeterministicFinding(
                check_id="DET-006",
                severity="medium",
                category="best_practice",
                title=f"Insecure protocol allowed: {rule.name}",
                description=(
                    f"Rule '{rule.name}' allows traffic on insecure protocols: "
                    f"{', '.join(insecure_found)}. These protocols transmit data "
                    f"in plaintext and are vulnerable to interception."
                ),
                recommendation=(
                    "Replace with encrypted alternatives: SSH instead of Telnet, "
                    "SFTP instead of FTP, HTTPS instead of HTTP, SNMPv3 instead of SNMP."
                ),
                confidence=1.0,
                affected_rules=[rule.name],
            ))
    return findings


def check_wide_port_ranges(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """DET-007: Rules with excessively wide port ranges (>1000 ports)."""
    findings: list[DeterministicFinding] = []
    for rule in rules:
        if rule.action != RuleAction.ALLOW:
            continue
        if not rule.enabled:
            continue

        for p in rule.destination_ports:
            p = p.strip()
            if p.lower() in WILDCARD_PORTS:
                continue  # Handled by DET-001/DET-003
            if "-" in p:
                parts = p.split("-")
                try:
                    span = int(parts[1]) - int(parts[0])
                    if span > 1000:
                        findings.append(DeterministicFinding(
                            check_id="DET-007",
                            severity="medium",
                            category="overly_permissive",
                            title=f"Wide port range ({p}) in rule: {rule.name}",
                            description=(
                                f"Rule '{rule.name}' opens a range of {span} ports ({p}). "
                                f"This exposes far more services than typically needed."
                            ),
                            recommendation=(
                                "Narrow port range to only the specific ports required. "
                                "Use multiple rules with exact ports if needed."
                            ),
                            confidence=1.0,
                            affected_rules=[rule.name],
                        ))
                        break  # One finding per rule for wide ranges
                except (ValueError, IndexError):
                    continue
    return findings


# ── Orchestrator ──────────────────────────────────────────────────────────────

ALL_CHECKS = [
    check_internet_exposed_allow,    # DET-001
    check_sensitive_ports_exposed,   # DET-002
    check_any_any_allow,             # DET-003
    check_wide_cidr_source,          # DET-004
    check_shadowed_rules,            # DET-005
    check_insecure_protocols,        # DET-006
    check_wide_port_ranges,          # DET-007
]


def run_deterministic_checks(rules: list[NormalizedRule]) -> list[DeterministicFinding]:
    """Run all deterministic checks and return combined findings.
    
    These are pattern-based checks that don't require an LLM.
    Every finding has confidence=1.0 because the patterns are exact.
    """
    findings: list[DeterministicFinding] = []
    for check_fn in ALL_CHECKS:
        try:
            results = check_fn(rules)
            findings.extend(results)
        except Exception:
            logger.exception("Deterministic check %s failed", check_fn.__name__)
    logger.info("Deterministic checks: %d findings from %d rules", len(findings), len(rules))
    return findings
