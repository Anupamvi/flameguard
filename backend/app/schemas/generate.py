from typing import Any, Literal, Optional

from pydantic import BaseModel


class RuleGenRequest(BaseModel):
    intent: str
    vendor: str
    context: Optional[str] = None


class RuleGenResponse(BaseModel):
    config: dict[str, Any]
    explanation: str
    warnings: list[str]
    is_valid: bool


class FrontendRuleGenRequest(BaseModel):
    description: str
    vendor: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    category: str = "general"


class FrontendRuleGenResponse(BaseModel):
    rule: dict[str, Any]
    explanation: str
    confidence: float
