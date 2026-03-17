"""Core compliance engine: pluggable framework registration and evaluation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.parsers.base import NormalizedRule


@dataclass
class ComplianceResult:
    framework: str
    control_id: str
    control_title: str
    status: str  # "pass", "fail", "not_applicable"
    evidence: str
    affected_rule_ids: list[str] = field(default_factory=list)


class ComplianceFramework(ABC):
    framework_id: str

    @abstractmethod
    def evaluate(self, rules: list[NormalizedRule]) -> list[ComplianceResult]:
        ...


class ComplianceEngine:
    def __init__(self) -> None:
        self._frameworks: list[ComplianceFramework] = []

    def register(self, framework: ComplianceFramework) -> None:
        self._frameworks.append(framework)

    def run(self, rules: list[NormalizedRule]) -> list[ComplianceResult]:
        results: list[ComplianceResult] = []
        for fw in self._frameworks:
            results.extend(fw.evaluate(rules))
        return results


def get_compliance_engine() -> ComplianceEngine:
    """Factory that returns engine with all registered frameworks."""
    from app.compliance.cis_azure import CISAzureChecks
    from app.compliance.pci_dss import PCIDSSChecks

    engine = ComplianceEngine()
    engine.register(CISAzureChecks())
    engine.register(PCIDSSChecks())
    return engine
