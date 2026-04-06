from app.parsers.azure_firewall import AzureFirewallParser
from app.parsers.base import RuleAction, RuleDirection, VendorType


class TestAzureFirewallParser:
    def setup_method(self):
        self.parser = AzureFirewallParser()

    def test_can_parse_policy_rcg(self, firewall_data):
        assert self.parser.can_parse(firewall_data) is True

    def test_cannot_parse_unrelated(self):
        assert self.parser.can_parse({"type": "Microsoft.Network/networkSecurityGroups"}) is False

    def test_parse_returns_rules(self, firewall_data):
        rules = self.parser.parse(firewall_data)
        assert len(rules) > 0
        assert all(r.vendor == VendorType.AZURE_FIREWALL for r in rules)

    def test_parse_network_rules(self, firewall_data):
        rules = self.parser.parse(firewall_data)
        network_rules = [r for r in rules if r.tags.get("rule_type") == "NetworkRule"]
        assert len(network_rules) > 0

    def test_parse_collection_hierarchy(self, firewall_data):
        rules = self.parser.parse(firewall_data)
        dns_rule = next((r for r in rules if r.name == "Allow-DNS"), None)
        assert dns_rule is not None
        assert dns_rule.collection_name is not None
        assert dns_rule.collection_priority is not None

    def test_parse_misconfigured_allow_all(self, firewall_data):
        rules = self.parser.parse(firewall_data)
        allow_all = next((r for r in rules if "Allow-All" in r.name), None)
        assert allow_all is not None
        assert allow_all.action == RuleAction.ALLOW
        assert "*" in allow_all.source_addresses
        assert "*" in allow_all.destination_addresses

    def test_parse_deny_rules(self, firewall_data):
        rules = self.parser.parse(firewall_data)
        deny_rules = [r for r in rules if r.action == RuleAction.DENY]
        assert len(deny_rules) > 0

    def test_generate_returns_network_rule(self, firewall_data):
        rules = self.parser.parse(firewall_data)
        generated = self.parser.generate(rules[0])
        assert generated["ruleType"] == "NetworkRule"
        assert "name" in generated
        assert "ipProtocols" in generated

    def test_can_parse_normalized_log_export(self, firewall_log_export_normalized):
        assert self.parser.can_parse(firewall_log_export_normalized) is True

    def test_can_parse_raw_log_export(self, firewall_log_export_raw):
        assert self.parser.can_parse(firewall_log_export_raw) is True

    def test_parse_normalized_log_export_returns_observed_rules(self, firewall_log_export_normalized):
        rules = self.parser.parse(firewall_log_export_normalized)
        assert len(rules) == 3
        assert {rule.tags.get("rule_type") for rule in rules} == {
            "DnsQueryLog",
            "ApplicationRuleLog",
            "ObservedTrafficLog",
        }
        assert any(rule.action == RuleAction.LOG for rule in rules)

    def test_parse_raw_log_export_returns_observed_rules(self, firewall_log_export_raw):
        rules = self.parser.parse(firewall_log_export_raw)
        assert len(rules) == 3
        assert all(rule.vendor == VendorType.AZURE_FIREWALL for rule in rules)
