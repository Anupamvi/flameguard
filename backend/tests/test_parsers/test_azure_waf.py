from app.parsers.azure_waf import AzureWAFParser
from app.parsers.base import RuleAction, RuleDirection, VendorType


class TestAzureWAFParser:
    def setup_method(self):
        self.parser = AzureWAFParser()

    def test_can_parse_appgw_waf(self, waf_data):
        assert self.parser.can_parse(waf_data) is True

    def test_cannot_parse_unrelated(self):
        assert self.parser.can_parse({"type": "Microsoft.Network/azureFirewalls"}) is False

    def test_parse_returns_rules(self, waf_data):
        rules = self.parser.parse(waf_data)
        assert len(rules) > 0
        assert all(r.vendor == VendorType.AZURE_WAF for r in rules)

    def test_all_rules_are_inbound(self, waf_data):
        rules = self.parser.parse(waf_data)
        assert all(r.direction == RuleDirection.INBOUND for r in rules)

    def test_parse_block_rule(self, waf_data):
        rules = self.parser.parse(waf_data)
        block_ips = next((r for r in rules if r.name == "BlockKnownBadIPs"), None)
        assert block_ips is not None
        assert block_ips.action == RuleAction.DENY
        assert len(block_ips.source_addresses) > 0
        assert block_ips.source_addresses != ["*"]

    def test_parse_rate_limit_rule(self, waf_data):
        rules = self.parser.parse(waf_data)
        rate_limit = next((r for r in rules if "RateLimit" in r.name), None)
        assert rate_limit is not None
        assert rate_limit.tags.get("rule_type") == "RateLimitRule"

    def test_parse_priorities(self, waf_data):
        rules = self.parser.parse(waf_data)
        priorities = [r.priority for r in rules if r.priority is not None]
        assert len(priorities) > 0
        # All priorities should be positive integers
        assert all(p > 0 for p in priorities)

    def test_generate_returns_valid_structure(self, waf_data):
        rules = self.parser.parse(waf_data)
        generated = self.parser.generate(rules[0])
        assert "name" in generated
        assert "priority" in generated
        assert "matchConditions" in generated
        assert generated["action"] in ("Allow", "Block", "Log")
