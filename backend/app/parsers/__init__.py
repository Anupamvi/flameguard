# Import all parsers to trigger @ParserRegistry.register
from app.parsers.azure_gsa import AzureGSAParser  # noqa: F401
from app.parsers.azure_nsg import AzureNSGParser  # noqa: F401
from app.parsers.azure_firewall import AzureFirewallParser  # noqa: F401
from app.parsers.azure_waf import AzureWAFParser  # noqa: F401
from app.parsers.detector import auto_detect_vendor  # noqa: F401
