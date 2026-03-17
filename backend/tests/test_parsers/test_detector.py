import pytest

from app.parsers.base import VendorType
from app.parsers.detector import auto_detect_vendor


class TestAutoDetectVendor:
    def test_detects_nsg(self, nsg_data):
        parser, vendor = auto_detect_vendor(nsg_data)
        assert vendor == VendorType.AZURE_NSG

    def test_detects_firewall(self, firewall_data):
        parser, vendor = auto_detect_vendor(firewall_data)
        assert vendor == VendorType.AZURE_FIREWALL

    def test_detects_waf(self, waf_data):
        parser, vendor = auto_detect_vendor(waf_data)
        assert vendor == VendorType.AZURE_WAF

    def test_raises_on_unknown(self):
        with pytest.raises(ValueError, match="Unrecognized"):
            auto_detect_vendor({"foo": "bar"})
