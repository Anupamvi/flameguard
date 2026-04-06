import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditReport(Base):
    __tablename__ = "audit_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ruleset_id: Mapped[str] = mapped_column(String(36), ForeignKey("rulesets.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, parsing, auditing, scoring, completed, failed
    summary: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    ruleset: Mapped["RuleSet"] = relationship(back_populates="audit_reports")
    findings: Mapped[list["AuditFinding"]] = relationship(back_populates="audit_report", cascade="all, delete-orphan")
    compliance_checks: Mapped[list["ComplianceCheck"]] = relationship(back_populates="audit_report", cascade="all, delete-orphan")
    chat_messages: Mapped[list["ChatMessage"]] = relationship(back_populates="audit_report", cascade="all, delete-orphan")

    # Forward refs
    from app.models.rule import RuleSet  # noqa: F811


class AuditFinding(Base):
    __tablename__ = "audit_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    audit_id: Mapped[str] = mapped_column(String(36), ForeignKey("audit_reports.id"), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("rules.id"))
    related_rule_ids: Mapped[str | None] = mapped_column(Text)  # JSON array
    severity: Mapped[str] = mapped_column(String(10), nullable=False)  # critical, high, medium, low, info
    category: Mapped[str] = mapped_column(String(30), nullable=False)  # shadowed, overly_permissive, contradictory, unused, best_practice
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(20), default="llm")  # "llm", "deterministic", "verified" (both agree)

    audit_report: Mapped["AuditReport"] = relationship(back_populates="findings")

    from app.models.compliance import ComplianceCheck  # noqa: F811
    from app.models.chat import ChatMessage  # noqa: F811
