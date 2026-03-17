import uuid

from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class ComplianceCheck(Base):
    __tablename__ = "compliance_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    audit_id: Mapped[str] = mapped_column(String(36), ForeignKey("audit_reports.id"), nullable=False)
    framework: Mapped[str] = mapped_column(String(50), nullable=False)  # cis_azure_v2, pci_dss_v4
    control_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g. CIS-6.1, PCI-1.3.1
    control_title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # pass, fail, not_applicable
    evidence: Mapped[str | None] = mapped_column(Text)
    affected_rule_ids: Mapped[str | None] = mapped_column(Text)  # JSON array

    audit_report: Mapped["AuditReport"] = relationship(back_populates="compliance_checks")

    from app.models.audit import AuditReport  # noqa: F811
