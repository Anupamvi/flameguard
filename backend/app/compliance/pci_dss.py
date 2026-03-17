"""PCI-DSS 4.0 Requirement 1 — Network Segmentation & Firewall checks."""

from __future__ import annotations

import ipaddress

from app.compliance.engine import ComplianceFramework, ComplianceResult
from app.parsers.base import NormalizedRule, RuleAction, RuleDirection

FRAMEWORK_ID = "pci_dss_v4"

_INTERNET_SOURCES = {"*", "internet", "0.0.0.0/0", "any"}


def _is_internet_source(addr: str) -> bool:
    return addr.strip().lower() in _INTERNET_SOURCES


def _has_internet_source(rule: NormalizedRule) -> bool:
    return any(_is_internet_source(a) for a in rule.source_addresses)


def _all_ports(rule_ports: list[str]) -> bool:
    for p in rule_ports:
        if p == "*":
            return True
        if "-" in p:
            try:
                lo, hi = p.split("-", 1)
                if int(lo) == 0 and int(hi) >= 65535:
                    return True
            except (ValueError, TypeError):
                continue
    return False


# RFC1918 broad ranges: flag if destination is a /16 or broader within these
_BROAD_INTERNAL = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_broad_internal(addr: str) -> bool:
    """Return True if addr is a broad internal CIDR (/16 or wider)."""
    try:
        net = ipaddress.ip_network(addr.strip(), strict=False)
    except (ValueError, TypeError):
        return False
    if net.prefixlen > 16:
        return False
    return any(net.subnet_of(rfc) for rfc in _BROAD_INTERNAL)


class PCIDSSChecks(ComplianceFramework):
    framework_id = FRAMEWORK_ID

    def evaluate(self, rules: list[NormalizedRule]) -> list[ComplianceResult]:
        return [
            self._check_1_2_1(rules),
            self._check_1_3_1(rules),
            self._check_1_3_2(rules),
            self._check_1_3_4(rules),
            self._check_1_3_5(rules),
            self._check_1_4_1(rules),
        ]

    # ── PCI-1.2.1  Restrict inbound with source * and protocol Any ──────────

    def _check_1_2_1(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
                and r.protocol.lower() == "any"
            ):
                bad.append(r.original_id)
                evidence_parts.append(
                    f"Rule '{r.name}' allows inbound from '*' with protocol 'Any'"
                )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="PCI-1.2.1",
                control_title="Restrict inbound traffic to only that which is necessary",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="PCI-1.2.1",
            control_title="Restrict inbound traffic to only that which is necessary",
            status="pass",
            evidence="No allow-inbound rules with source '*' and protocol 'Any' found.",
            affected_rule_ids=[],
        )

    # ── PCI-1.3.1  DMZ enforcement — too many Internet inbound rules ───────

    def _check_1_3_1(self, rules: list[NormalizedRule]) -> ComplianceResult:
        internet_inbound: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
            ):
                internet_inbound.append(r.original_id)

        if len(internet_inbound) > 3:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="PCI-1.3.1",
                control_title="Implement a DMZ to limit inbound traffic to system components in the CDE",
                status="fail",
                evidence=(
                    f"{len(internet_inbound)} rules allow inbound from Internet "
                    f"(threshold: 3). Rule IDs: {', '.join(internet_inbound)}"
                ),
                affected_rule_ids=internet_inbound,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="PCI-1.3.1",
            control_title="Implement a DMZ to limit inbound traffic to system components in the CDE",
            status="pass",
            evidence=f"Only {len(internet_inbound)} rule(s) allow inbound from Internet (within threshold).",
            affected_rule_ids=[],
        )

    # ── PCI-1.3.2  Limit inbound to DMZ — no broad internal destinations ───

    def _check_1_3_2(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
            ):
                broad = [a for a in r.destination_addresses if _is_broad_internal(a)]
                if broad:
                    bad.append(r.original_id)
                    evidence_parts.append(
                        f"Rule '{r.name}' allows inbound from Internet to broad internal range(s): {', '.join(broad)}"
                    )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="PCI-1.3.2",
                control_title="Limit inbound Internet traffic to IP addresses within the DMZ",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="PCI-1.3.2",
            control_title="Limit inbound Internet traffic to IP addresses within the DMZ",
            status="pass",
            evidence="No inbound Internet rules target broad internal address ranges.",
            affected_rule_ids=[],
        )

    # ── PCI-1.3.4  No unauthorized outbound from CDE ───────────────────────

    def _check_1_3_4(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.OUTBOUND
                and _all_ports(r.destination_ports)
                and any(a.strip() == "*" for a in r.destination_addresses)
                and r.tags.get("default_rule") != "true"
            ):
                bad.append(r.original_id)
                evidence_parts.append(
                    f"Rule '{r.name}' allows outbound to '*' on all ports"
                )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="PCI-1.3.4",
                control_title="Do not allow unauthorized outbound traffic from the CDE to the Internet",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="PCI-1.3.4",
            control_title="Do not allow unauthorized outbound traffic from the CDE to the Internet",
            status="pass",
            evidence="No user-defined allow-all outbound rules found.",
            affected_rule_ids=[],
        )

    # ── PCI-1.3.5  Stateful connections ─────────────────────────────────────

    def _check_1_3_5(self, rules: list[NormalizedRule]) -> ComplianceResult:
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="PCI-1.3.5",
            control_title="Permit only established connections into the network",
            status="pass",
            evidence="Azure NSGs and firewalls are stateful by default; return traffic is automatically allowed.",
            affected_rule_ids=[],
        )

    # ── PCI-1.4.1  Anti-spoofing ───────────────────────────────────────────

    def _check_1_4_1(self, rules: list[NormalizedRule]) -> ComplianceResult:
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="PCI-1.4.1",
            control_title="Implement anti-spoofing measures to detect and block forged source IP addresses",
            status="not_applicable",
            evidence="Anti-spoofing is handled at the Azure platform level and cannot be assessed from NSG rules alone.",
            affected_rule_ids=[],
        )
