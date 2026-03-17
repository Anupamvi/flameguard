import json

from app.compliance.cis_azure import CISAzureChecks
from app.parsers.azure_nsg import AzureNSGParser


class TestCISAzureChecks:
    def setup_method(self):
        self.checks = CISAzureChecks()
        self.parser = AzureNSGParser()

    def _load_rules(self, nsg_data):
        return self.parser.parse(nsg_data)

    def test_evaluates_all_controls(self, nsg_data):
        rules = self._load_rules(nsg_data)
        results = self.checks.evaluate(rules)
        assert len(results) == 8
        control_ids = [r.control_id for r in results]
        assert "CIS-6.1" in control_ids
        assert "CIS-6.2" in control_ids
        assert "CIS-6.8" in control_ids

    def test_detects_rdp_from_internet(self, nsg_data):
        rules = self._load_rules(nsg_data)
        results = self.checks.evaluate(rules)
        rdp = next(r for r in results if r.control_id == "CIS-6.1")
        assert rdp.status == "fail"
        assert "3389" in rdp.evidence.lower() or "rdp" in rdp.evidence.lower()

    def test_detects_ssh_from_internet(self, nsg_data):
        rules = self._load_rules(nsg_data)
        results = self.checks.evaluate(rules)
        ssh = next(r for r in results if r.control_id == "CIS-6.2")
        assert ssh.status == "fail"

    def test_detects_unrestricted_inbound(self, nsg_data):
        rules = self._load_rules(nsg_data)
        results = self.checks.evaluate(rules)
        unrestricted = next(r for r in results if r.control_id == "CIS-6.3")
        assert unrestricted.status == "fail"

    def test_all_results_have_framework(self, nsg_data):
        rules = self._load_rules(nsg_data)
        results = self.checks.evaluate(rules)
        assert all(r.framework == "cis_azure_v2" for r in results)
