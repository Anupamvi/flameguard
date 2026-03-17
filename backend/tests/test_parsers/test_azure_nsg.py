from app.parsers.azure_nsg import AzureNSGParser
from app.parsers.base import RuleAction, RuleDirection, VendorType


class TestAzureNSGParser:
    def setup_method(self):
        self.parser = AzureNSGParser()

    def test_can_parse_direct_nsg(self, nsg_data):
        assert self.parser.can_parse(nsg_data) is True

    def test_can_parse_arm_template(self, nsg_data):
        arm = {"resources": [nsg_data]}
        assert self.parser.can_parse(arm) is True

    def test_cannot_parse_unrelated(self):
        assert self.parser.can_parse({"type": "Microsoft.Network/azureFirewalls"}) is False
        assert self.parser.can_parse({"foo": "bar"}) is False

    def test_parse_returns_rules(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        assert len(rules) > 0
        assert all(r.vendor == VendorType.AZURE_NSG for r in rules)

    def test_parse_custom_and_default_rules(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        custom = [r for r in rules if r.tags.get("default_rule") != "true"]
        defaults = [r for r in rules if r.tags.get("default_rule") == "true"]
        assert len(custom) > 0
        assert len(defaults) > 0

    def test_parse_rule_fields(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        https_rule = next((r for r in rules if r.name == "Allow-HTTPS-Inbound"), None)
        assert https_rule is not None
        assert https_rule.action == RuleAction.ALLOW
        assert https_rule.direction == RuleDirection.INBOUND
        assert https_rule.protocol == "Tcp"
        assert "443" in https_rule.destination_ports
        assert https_rule.priority == 100

    def test_parse_misconfigured_ssh(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        ssh = next((r for r in rules if "SSH" in r.name and "MISCONFIGURED" in r.name), None)
        assert ssh is not None
        assert ssh.action == RuleAction.ALLOW
        assert "*" in ssh.source_addresses
        assert "22" in ssh.destination_ports

    def test_generate_roundtrip(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        for rule in rules[:3]:
            generated = self.parser.generate(rule)
            assert "name" in generated
            assert "properties" in generated
            assert generated["properties"]["access"] in ("Allow", "Deny")
            assert generated["properties"]["direction"] in ("Inbound", "Outbound")
