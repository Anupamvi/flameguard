from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.rule import RuleSet, Rule  # noqa: E402, F401
from app.models.audit import AuditReport, AuditFinding  # noqa: E402, F401
from app.models.compliance import ComplianceCheck  # noqa: E402, F401
from app.models.chat import ChatMessage  # noqa: E402, F401
