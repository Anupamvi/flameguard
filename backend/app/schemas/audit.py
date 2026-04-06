from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


SEVERITY_LEVELS = Literal["critical", "high", "medium", "low", "info"]
AUDIT_CATEGORIES = Literal[
    "shadowed",
    "overly_permissive",
    "contradictory",
    "unused",
    "best_practice",
]
AUDIT_STATUS = Literal["pending", "parsing", "auditing", "scoring", "completed", "failed"]

DEFAULT_CHECKS: list[str] = [
    "shadowed",
    "overly_permissive",
    "contradictory",
    "unused",
    "best_practice",
]


class AuditRequest(BaseModel):
    ruleset_id: str
    checks: list[str] = Field(default_factory=lambda: list(DEFAULT_CHECKS))


FINDING_SOURCE = Literal["llm", "deterministic", "verified"]


class FindingOut(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    severity: SEVERITY_LEVELS
    category: AUDIT_CATEGORIES
    title: str
    description: str
    recommendation: Optional[str] = None
    confidence: Optional[float] = None
    source: FINDING_SOURCE = "llm"
    affected_rule_ids: list[str]


class AuditResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    ruleset_id: str
    filename: str
    vendor: str
    rule_count: int
    status: AUDIT_STATUS
    summary: Optional[str] = None
    error_message: Optional[str] = None
    findings: list[FindingOut] = []
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    created_at: datetime
    completed_at: Optional[datetime] = None


class UploadResponse(BaseModel):
    ruleset_id: str
    audit_id: str
    status: str
    rule_count: int
    vendor: str
    parse_warnings: list[str] = []


class DeleteAuditsRequest(BaseModel):
    audit_ids: list[str] = Field(min_length=1, max_length=100)


class DeleteAuditsResponse(BaseModel):
    deleted_audit_ids: list[str]
    deleted_ruleset_ids: list[str]
