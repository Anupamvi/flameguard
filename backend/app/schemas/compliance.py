from typing import Literal, Optional

from pydantic import BaseModel


COMPLIANCE_STATUS = Literal["pass", "fail", "not_applicable"]


class ComplianceCheckOut(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    framework: str
    control_id: str
    control_title: str
    status: COMPLIANCE_STATUS
    evidence: Optional[str] = None
    affected_rule_ids: list[str]


class ComplianceSummary(BaseModel):
    framework: str
    total_controls: int
    passed: int
    failed: int
    not_applicable: int
    checks: list[ComplianceCheckOut]
