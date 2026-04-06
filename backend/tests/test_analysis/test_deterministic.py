"""Tests for the deterministic rule analysis engine."""

from app.analysis.deterministic import (
    DeterministicFinding,
    check_any_any_allow,
    check_insecure_protocols,
    check_internet_exposed_allow,
    check_sensitive_ports_exposed,
    check_shadowed_rules,
    check_wide_cidr_source,
    check_wide_port_ranges,
    run_deterministic_checks,
)
from app.parsers.base import NormalizedRule, RuleAction, RuleDirection, VendorType


def _rule(**overrides) -> NormalizedRule:
    defaults = dict(
        original_id="test-1",
        name="test-rule",
        vendor=VendorType.AZURE_NSG,
        action=RuleAction.ALLOW,
        direction=RuleDirection.INBOUND,
        protocol="TCP",
        source_addresses=["10.0.0.0/24"],
        source_ports=["*"],
        destination_addresses=["10.1.0.0/24"],
        destination_ports=["443"],
        priority=100,
        description="test",
        enabled=True,
    )
    defaults.update(overrides)
    return NormalizedRule(**defaults)


# ── DET-001: Internet-exposed allow-all ──


def test_det001_internet_exposed_all_ports():
    r = _rule(name="bad", source_addresses=["0.0.0.0/0"], destination_ports=["*"])
    findings = check_internet_exposed_allow([r])
    assert len(findings) == 1
    assert findings[0].check_id == "DET-001"
    assert findings[0].severity == "critical"


def test_det001_skips_deny():
    r = _rule(name="ok", source_addresses=["0.0.0.0/0"], destination_ports=["*"],
              action=RuleAction.DENY)
    assert check_internet_exposed_allow([r]) == []


def test_det001_skips_specific_port():
    r = _rule(name="ok", source_addresses=["0.0.0.0/0"], destination_ports=["443"])
    assert check_internet_exposed_allow([r]) == []


# ── DET-002: Sensitive ports exposed ──


def test_det002_ssh_exposed():
    r = _rule(name="bad-ssh", source_addresses=["0.0.0.0/0"], destination_ports=["22"])
    findings = check_sensitive_ports_exposed([r])
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "SSH" in findings[0].description


def test_det002_db_exposed():
    r = _rule(name="bad-pg", source_addresses=["0.0.0.0/0"], destination_ports=["5432"])
    findings = check_sensitive_ports_exposed([r])
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_det002_port_range_covers_rdp():
    r = _rule(name="range", source_addresses=["0.0.0.0/0"], destination_ports=["3380-3400"])
    findings = check_sensitive_ports_exposed([r])
    assert len(findings) == 1
    assert "RDP" in findings[0].description


def test_det002_skips_internal():
    r = _rule(name="ok", source_addresses=["10.0.0.0/24"], destination_ports=["22"])
    assert check_sensitive_ports_exposed([r]) == []


# ── DET-003: Any-any-any allow ──


def test_det003_any_any():
    r = _rule(
        name="any-any",
        source_addresses=["*"],
        destination_addresses=["*"],
        destination_ports=["*"],
        protocol="Any",
    )
    findings = check_any_any_allow([r])
    assert len(findings) == 1
    assert findings[0].check_id == "DET-003"


# ── DET-004: Wide CIDR ──


def test_det004_wide_cidr():
    r = _rule(name="wide", source_addresses=["10.0.0.0/8"])
    findings = check_wide_cidr_source([r])
    assert len(findings) == 1
    assert "/8" in findings[0].description


def test_det004_normal_cidr():
    r = _rule(name="ok", source_addresses=["10.0.0.0/24"])
    assert check_wide_cidr_source([r]) == []


# ── DET-005: Shadowed rules ──


def test_det005_shadowed_by_deny_all():
    deny = _rule(
        name="deny-all", action=RuleAction.DENY, priority=100,
        source_addresses=["*"], destination_ports=["*"], protocol="Any",
    )
    allow = _rule(name="allow-ssh", action=RuleAction.ALLOW, priority=200, destination_ports=["22"])
    findings = check_shadowed_rules([deny, allow])
    assert len(findings) == 1
    assert "allow-ssh" in findings[0].title


# ── DET-006: Insecure protocols ──


def test_det006_ftp():
    r = _rule(name="ftp", destination_ports=["21"])
    findings = check_insecure_protocols([r])
    assert len(findings) == 1
    assert "FTP" in findings[0].description


# ── DET-007: Wide port ranges ──


def test_det007_wide_range():
    r = _rule(name="wide-ports", destination_ports=["1024-9999"])
    findings = check_wide_port_ranges([r])
    assert len(findings) == 1


def test_det007_narrow_range():
    r = _rule(name="ok", destination_ports=["443-445"])
    assert check_wide_port_ranges([r]) == []


# ── Full orchestrator ──


def test_run_all_catches_multiple():
    rules = [
        _rule(name="any-any-internet", source_addresses=["0.0.0.0/0"],
              destination_addresses=["*"], destination_ports=["*"], protocol="Any"),
        _rule(name="ssh-exposed", source_addresses=["0.0.0.0/0"], destination_ports=["22"]),
        _rule(name="wide-source", source_addresses=["10.0.0.0/8"], destination_ports=["443"]),
    ]
    findings = run_deterministic_checks(rules)
    assert len(findings) >= 4
    check_ids = {f.check_id for f in findings}
    assert "DET-001" in check_ids
    assert "DET-002" in check_ids
    assert "DET-003" in check_ids
    assert "DET-004" in check_ids


def test_all_findings_have_confidence_1():
    rules = [
        _rule(name="bad", source_addresses=["0.0.0.0/0"], destination_ports=["*"]),
    ]
    for f in run_deterministic_checks(rules):
        assert f.confidence == 1.0
        assert f.source == "deterministic"
