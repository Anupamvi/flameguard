from app.compliance.pci_dss import PCIDSSChecks
from app.parsers.azure_nsg import AzureNSGParser


class TestPCIDSSChecks:
    def setup_method(self):
        self.checks = PCIDSSChecks()
        self.parser = AzureNSGParser()

    def test_evaluates_all_controls(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        results = self.checks.evaluate(rules)
        assert len(results) == 6
        control_ids = [r.control_id for r in results]
        assert "PCI-1.2.1" in control_ids
        assert "PCI-1.3.5" in control_ids

    def test_detects_unrestricted_inbound(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        results = self.checks.evaluate(rules)
        restrict = next(r for r in results if r.control_id == "PCI-1.2.1")
        assert restrict.status == "fail"

    def test_stateful_connections_pass(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        results = self.checks.evaluate(rules)
        stateful = next(r for r in results if r.control_id == "PCI-1.3.5")
        assert stateful.status == "pass"

    def test_all_results_have_framework(self, nsg_data):
        rules = self.parser.parse(nsg_data)
        results = self.checks.evaluate(rules)
        assert all(r.framework == "pci_dss_v4" for r in results)
