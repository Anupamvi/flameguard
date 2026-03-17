"""CIS Azure Foundations Benchmark v2.0 — Network Security checks (Section 6)."""

from __future__ import annotations

from app.compliance.engine import ComplianceFramework, ComplianceResult
from app.parsers.base import NormalizedRule, RuleAction, RuleDirection

FRAMEWORK_ID = "cis_azure_v2"

# Sources that represent "Internet" / unrestricted origin
_INTERNET_SOURCES = {"*", "internet", "0.0.0.0/0", "any"}


def _is_internet_source(addr: str) -> bool:
    return addr.strip().lower() in _INTERNET_SOURCES


def _has_internet_source(rule: NormalizedRule) -> bool:
    return any(_is_internet_source(a) for a in rule.source_addresses)


def _port_matches(rule_ports: list[str], target: str) -> bool:
    """Return True if the rule's port list covers *target* (single port string)."""
    for p in rule_ports:
        if p == "*":
            return True
        if p == target:
            return True
        # Range check  e.g. "0-65535" covers everything
        if "-" in p:
            try:
                lo, hi = p.split("-", 1)
                if int(lo) <= int(target) <= int(hi):
                    return True
            except (ValueError, TypeError):
                continue
    return False


def _all_ports(rule_ports: list[str]) -> bool:
    """True if the port list means 'all ports'."""
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


def _is_broad_port_range(rule_ports: list[str], threshold: int = 1000) -> bool:
    """True if any single port entry spans more than *threshold* ports."""
    for p in rule_ports:
        if p == "*":
            return True
        if "-" in p:
            try:
                lo, hi = p.split("-", 1)
                if int(hi) - int(lo) >= threshold:
                    return True
            except (ValueError, TypeError):
                continue
    return False


class CISAzureChecks(ComplianceFramework):
    framework_id = FRAMEWORK_ID

    def evaluate(self, rules: list[NormalizedRule]) -> list[ComplianceResult]:
        return [
            self._check_6_1(rules),
            self._check_6_2(rules),
            self._check_6_3(rules),
            self._check_6_4(rules),
            self._check_6_5(rules),
            self._check_6_6(rules),
            self._check_6_7(rules),
            self._check_6_8(rules),
        ]

    # ── CIS-6.1  RDP from Internet ──────────────────────────────────────────

    def _check_6_1(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
                and _port_matches(r.destination_ports, "3389")
            ):
                bad.append(r.original_id)
                src = ", ".join(r.source_addresses)
                evidence_parts.append(
                    f"Rule '{r.name}' allows RDP (port 3389) from source '{src}'"
                )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="CIS-6.1",
                control_title="Ensure that RDP access from the Internet is evaluated and restricted",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.1",
            control_title="Ensure that RDP access from the Internet is evaluated and restricted",
            status="pass",
            evidence="No rules allow RDP (port 3389) from the Internet.",
            affected_rule_ids=[],
        )

    # ── CIS-6.2  SSH from Internet ──────────────────────────────────────────

    def _check_6_2(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
                and _port_matches(r.destination_ports, "22")
            ):
                bad.append(r.original_id)
                src = ", ".join(r.source_addresses)
                evidence_parts.append(
                    f"Rule '{r.name}' allows SSH (port 22) from source '{src}'"
                )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="CIS-6.2",
                control_title="Ensure that SSH access from the Internet is evaluated and restricted",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.2",
            control_title="Ensure that SSH access from the Internet is evaluated and restricted",
            status="pass",
            evidence="No rules allow SSH (port 22) from the Internet.",
            affected_rule_ids=[],
        )

    # ── CIS-6.3  Unrestricted inbound ───────────────────────────────────────

    def _check_6_3(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
                and _all_ports(r.destination_ports)
            ):
                bad.append(r.original_id)
                src = ", ".join(r.source_addresses)
                evidence_parts.append(
                    f"Rule '{r.name}' allows unrestricted inbound on all ports from source '{src}'"
                )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="CIS-6.3",
                control_title="Ensure no Network Security Group allows unrestricted inbound access",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.3",
            control_title="Ensure no Network Security Group allows unrestricted inbound access",
            status="pass",
            evidence="No rules allow unrestricted inbound from the Internet on all ports.",
            affected_rule_ids=[],
        )

    # ── CIS-6.4  UDP from Internet ──────────────────────────────────────────

    def _check_6_4(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
                and r.protocol.lower() in ("udp", "any")
                and _is_broad_port_range(r.destination_ports)
            ):
                bad.append(r.original_id)
                evidence_parts.append(
                    f"Rule '{r.name}' allows UDP from Internet with broad port range"
                )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="CIS-6.4",
                control_title="Ensure that UDP access from the Internet is evaluated and restricted",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.4",
            control_title="Ensure that UDP access from the Internet is evaluated and restricted",
            status="pass",
            evidence="No rules allow UDP from the Internet with broad port ranges.",
            affected_rule_ids=[],
        )

    # ── CIS-6.5  HTTP management from Internet ─────────────────────────────

    def _check_6_5(self, rules: list[NormalizedRule]) -> ComplianceResult:
        mgmt_ports = ("80", "443", "8080", "8443")
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.INBOUND
                and _has_internet_source(r)
            ):
                matched_ports = [p for p in mgmt_ports if _port_matches(r.destination_ports, p)]
                if matched_ports:
                    bad.append(r.original_id)
                    evidence_parts.append(
                        f"Rule '{r.name}' allows inbound from Internet to port(s) {', '.join(matched_ports)}"
                    )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="CIS-6.5",
                control_title="Ensure that HTTP(S) access from the Internet is evaluated and restricted",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.5",
            control_title="Ensure that HTTP(S) access from the Internet is evaluated and restricted",
            status="pass",
            evidence="No rules allow HTTP/HTTPS management ports from the Internet.",
            affected_rule_ids=[],
        )

    # ── CIS-6.6  Network Watcher ────────────────────────────────────────────

    def _check_6_6(self, rules: list[NormalizedRule]) -> ComplianceResult:
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.6",
            control_title="Ensure that Network Watcher is enabled",
            status="not_applicable",
            evidence="Network Watcher status cannot be determined from firewall rules alone.",
            affected_rule_ids=[],
        )

    # ── CIS-6.7  Restrict outbound ─────────────────────────────────────────

    def _check_6_7(self, rules: list[NormalizedRule]) -> ComplianceResult:
        bad: list[str] = []
        evidence_parts: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.ALLOW
                and r.direction == RuleDirection.OUTBOUND
                and _all_ports(r.destination_ports)
                and any(a.strip() == "*" for a in r.destination_addresses)
                # Exclude Azure default rules (tagged)
                and r.tags.get("default_rule") != "true"
            ):
                bad.append(r.original_id)
                evidence_parts.append(
                    f"Rule '{r.name}' allows outbound to '*' on all ports"
                )

        if bad:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="CIS-6.7",
                control_title="Ensure that outbound traffic to the Internet is evaluated and restricted",
                status="fail",
                evidence="; ".join(evidence_parts),
                affected_rule_ids=bad,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.7",
            control_title="Ensure that outbound traffic to the Internet is evaluated and restricted",
            status="pass",
            evidence="No user-defined rules allow unrestricted outbound to all destinations on all ports.",
            affected_rule_ids=[],
        )

    # ── CIS-6.8  Deny-all as last rule ─────────────────────────────────────

    def _check_6_8(self, rules: list[NormalizedRule]) -> ComplianceResult:
        deny_all_ids: list[str] = []
        for r in rules:
            if (
                r.action == RuleAction.DENY
                and r.direction == RuleDirection.INBOUND
                and _all_ports(r.destination_ports)
                and any(a.strip() == "*" for a in r.source_addresses)
                and any(a.strip() == "*" for a in r.destination_addresses)
                # Exclude Azure default rules — we want explicit user-defined deny
                and r.tags.get("default_rule") != "true"
            ):
                deny_all_ids.append(r.original_id)

        if deny_all_ids:
            return ComplianceResult(
                framework=FRAMEWORK_ID,
                control_id="CIS-6.8",
                control_title="Ensure that an explicit deny-all rule exists as the lowest priority inbound rule",
                status="pass",
                evidence=f"Deny-all inbound rule(s) found: {', '.join(deny_all_ids)}.",
                affected_rule_ids=deny_all_ids,
            )
        return ComplianceResult(
            framework=FRAMEWORK_ID,
            control_id="CIS-6.8",
            control_title="Ensure that an explicit deny-all rule exists as the lowest priority inbound rule",
            status="fail",
            evidence="No explicit user-defined deny-all inbound rule found.",
            affected_rule_ids=[],
        )
