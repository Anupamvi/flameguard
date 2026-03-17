import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RuleSet(Base):
    __tablename__ = "rulesets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_json: Mapped[str] = mapped_column(Text, nullable=False)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    rules: Mapped[list["Rule"]] = relationship("Rule", back_populates="ruleset", cascade="all, delete-orphan")
    audit_reports: Mapped[list["AuditReport"]] = relationship(back_populates="ruleset")


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ruleset_id: Mapped[str] = mapped_column(String(36), ForeignKey("rulesets.id"), nullable=False)
    original_id: Mapped[str | None] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(10), nullable=False)  # allow, deny, log
    direction: Mapped[str] = mapped_column(String(10), nullable=False)  # inbound, outbound, both
    protocol: Mapped[str | None] = mapped_column(String(20))
    source_addresses: Mapped[str | None] = mapped_column(Text)  # JSON array
    source_ports: Mapped[str | None] = mapped_column(Text)  # JSON array
    dest_addresses: Mapped[str | None] = mapped_column(Text)  # JSON array
    dest_ports: Mapped[str | None] = mapped_column(Text)  # JSON array
    priority: Mapped[int | None] = mapped_column(Integer)
    collection_name: Mapped[str | None] = mapped_column(String(255))
    collection_priority: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_score: Mapped[float | None] = mapped_column(Float)
    tags: Mapped[str | None] = mapped_column(Text)  # JSON object
    raw_json: Mapped[str | None] = mapped_column(Text)

    ruleset: Mapped["RuleSet"] = relationship("RuleSet", back_populates="rules")

    # Import needed for type reference
    from app.models.audit import AuditReport  # noqa: F811 - just for type hint context
