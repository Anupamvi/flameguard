from __future__ import annotations

from typing import Any

from app.parsers.base import BaseParser, ParserRegistry, VendorType


def auto_detect_vendor(data: dict[str, Any]) -> tuple[BaseParser, VendorType]:
    """Inspect uploaded JSON and return the appropriate parser.

    Raises ValueError if no parser can handle the data.
    """
    parser = ParserRegistry.detect(data)
    if parser is None:
        supported = ", ".join(v.value for v in ParserRegistry.all_vendors())
        raise ValueError(
            f"Unrecognized firewall config format. "
            f"Supported vendors: {supported}. "
            f"Please upload a supported Azure Firewall, Azure NSG, Azure WAF, or Global Secure Access export."
        )
    return parser, parser.vendor
