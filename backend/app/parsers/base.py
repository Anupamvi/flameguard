from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VendorType(str, Enum):
    AZURE_FIREWALL = "azure_firewall"
    AZURE_GSA = "azure_gsa"
    AZURE_NSG = "azure_nsg"
    AZURE_WAF = "azure_waf"


class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"


class RuleDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


@dataclass
class NormalizedRule:
    """Vendor-agnostic canonical rule representation.

    Every vendor parser converts its native format into this structure.
    All downstream analysis (LLM audit, compliance, risk scoring, UI)
    operates exclusively on NormalizedRules.
    """

    original_id: str
    name: str
    vendor: VendorType
    action: RuleAction
    direction: RuleDirection
    protocol: str  # TCP, UDP, Any, ICMP, etc.
    source_addresses: list[str] = field(default_factory=list)
    source_ports: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    destination_ports: list[str] = field(default_factory=list)
    priority: int | None = None
    collection_name: str | None = None
    collection_priority: int | None = None
    description: str = ""
    enabled: bool = True
    raw_json: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)

    def to_llm_summary(self) -> dict[str, Any]:
        """Compact representation sent to the LLM (excludes raw_json)."""
        return {
            "name": self.name,
            "action": self.action.value,
            "direction": self.direction.value,
            "protocol": self.protocol,
            "source": self.source_addresses or ["*"],
            "source_ports": self.source_ports or ["*"],
            "destination": self.destination_addresses or ["*"],
            "dest_ports": self.destination_ports or ["*"],
            "priority": self.priority,
            "collection": self.collection_name,
            "enabled": self.enabled,
            "description": self.description,
        }


class BaseParser(ABC):
    """Abstract base class for all vendor parsers."""

    vendor: VendorType

    @abstractmethod
    def parse(self, data: dict[str, Any]) -> list[NormalizedRule]:
        """Parse vendor-specific JSON into normalized rules."""
        ...

    @abstractmethod
    def can_parse(self, data: dict[str, Any]) -> bool:
        """Return True if this parser can handle the given JSON structure."""
        ...

    @abstractmethod
    def generate(self, normalized: NormalizedRule) -> dict[str, Any]:
        """Convert a NormalizedRule back to vendor-specific JSON."""
        ...


class ParserRegistry:
    """Auto-discovery registry for vendor parsers."""

    _parsers: dict[VendorType, BaseParser] = {}

    @classmethod
    def register(cls, parser_class: type[BaseParser]) -> type[BaseParser]:
        instance = parser_class()
        cls._parsers[instance.vendor] = instance
        return parser_class

    @classmethod
    def get(cls, vendor: VendorType) -> BaseParser:
        if vendor not in cls._parsers:
            raise ValueError(f"No parser registered for vendor: {vendor}")
        return cls._parsers[vendor]

    @classmethod
    def detect(cls, data: dict[str, Any]) -> BaseParser | None:
        for parser in cls._parsers.values():
            if parser.can_parse(data):
                return parser
        return None

    @classmethod
    def all_vendors(cls) -> list[VendorType]:
        return list(cls._parsers.keys())
