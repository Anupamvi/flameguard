from app.config import settings
from app.llm.pipeline import _prepare_rules_for_analysis
from app.parsers.base import NormalizedRule, RuleAction, RuleDirection, VendorType


def _waf_log_rule(name: str, client_ip: str, hostname: str = "shop.contoso.com", rule_id: str = "942100") -> NormalizedRule:
    return NormalizedRule(
        original_id=f"waf:{name}:{client_ip}",
        name=name,
        vendor=VendorType.AZURE_WAF,
        action=RuleAction.DENY,
        direction=RuleDirection.INBOUND,
        protocol="HTTPS",
        source_addresses=[client_ip],
        source_ports=["58231"],
        destination_addresses=[hostname],
        destination_ports=["443"],
        priority=None,
        description="Observed ApplicationGatewayFirewallLog; uri=https://shop.contoso.com/login",
        enabled=True,
        tags={
            "rule_type": "ObservedWAFLog",
            "rule_id": rule_id,
            "hostname": hostname,
            "log_category": "ApplicationGatewayFirewallLog",
        },
    )


def _nsg_rule() -> NormalizedRule:
    return NormalizedRule(
        original_id="nsg:allow-https",
        name="AllowHttps",
        vendor=VendorType.AZURE_NSG,
        action=RuleAction.ALLOW,
        direction=RuleDirection.INBOUND,
        protocol="TCP",
        source_addresses=["0.0.0.0/0"],
        source_ports=["*"],
        destination_addresses=["10.0.0.4"],
        destination_ports=["443"],
        priority=100,
        description="Allow HTTPS inbound",
        enabled=True,
    )


def test_prepare_rules_for_analysis_leaves_non_log_rules_unchanged():
    rules = [_nsg_rule()]

    prepared, note = _prepare_rules_for_analysis(rules)

    assert prepared == rules
    assert note is None


def test_prepare_rules_for_analysis_condenses_duplicate_waf_log_rows():
    rules = [
        _waf_log_rule("SQLiBlock", "198.51.100.24"),
        _waf_log_rule("SQLiBlock", "198.51.100.25"),
    ]

    prepared, note = _prepare_rules_for_analysis(rules)

    assert len(prepared) == 1
    assert note == "Condensed 2 WAF log rows into 1 representative event patterns."
    assert prepared[0].tags["event_count"] == "2"
    assert set(prepared[0].source_addresses) == {"198.51.100.24", "198.51.100.25"}
    assert prepared[0].description.startswith("Observed in 2 matching WAF log events.")


def test_prepare_rules_for_analysis_caps_unique_waf_patterns():
    rules = [
        _waf_log_rule(f"Rule-{index}", f"198.51.100.{index % 250}", hostname=f"host-{index}.contoso.com", rule_id=str(index))
        for index in range(settings.max_log_rules_for_analysis + 5)
    ]

    prepared, note = _prepare_rules_for_analysis(rules)

    assert len(prepared) == settings.max_log_rules_for_analysis
    assert note == (
        f"Condensed {settings.max_log_rules_for_analysis + 5} WAF log rows into "
        f"{settings.max_log_rules_for_analysis + 5} representative event patterns and analyzed the top "
        f"{settings.max_log_rules_for_analysis} patterns."
    )