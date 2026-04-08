from app.parsers.azure_gsa import AzureGSAParser
from app.parsers.base import RuleAction, RuleDirection, VendorType


class TestAzureGSAParser:
    def setup_method(self):
        self.parser = AzureGSAParser()

    def test_can_parse_audit_logs(self, gsa_audit_log_export_raw):
        assert self.parser.can_parse(gsa_audit_log_export_raw) is True

    def test_can_parse_traffic_logs(self, gsa_traffic_log_export_raw):
        assert self.parser.can_parse(gsa_traffic_log_export_raw) is True

    def test_can_parse_deployment_logs(self, gsa_deployment_log_export_raw):
        assert self.parser.can_parse(gsa_deployment_log_export_raw) is True

    def test_parse_audit_logs(self, gsa_audit_log_export_raw):
        rules = self.parser.parse(gsa_audit_log_export_raw)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.vendor == VendorType.AZURE_GSA
        assert rule.action == RuleAction.LOG
        assert rule.direction == RuleDirection.BOTH
        assert rule.collection_name == "Forwarding Profiles"
        assert rule.tags.get("log_type") == "audit"
        assert "admin@contoso.com" in rule.description

    def test_parse_traffic_logs(self, gsa_traffic_log_export_raw):
        rules = self.parser.parse(gsa_traffic_log_export_raw)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.vendor == VendorType.AZURE_GSA
        assert rule.action == RuleAction.DENY
        assert rule.direction == RuleDirection.OUTBOUND
        assert rule.source_addresses == ["198.51.100.24"]
        assert rule.destination_addresses == ["sharepoint.contoso.com"]
        assert rule.destination_ports == ["443"]
        assert rule.tags.get("log_type") == "traffic"

    def test_parse_deployment_logs(self, gsa_deployment_log_export_raw):
        rules = self.parser.parse(gsa_deployment_log_export_raw)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.vendor == VendorType.AZURE_GSA
        assert rule.action == RuleAction.LOG
        assert rule.direction == RuleDirection.BOTH
        assert rule.tags.get("log_type") == "deployment"
        assert rule.tags.get("status") == "Deployment Successful"