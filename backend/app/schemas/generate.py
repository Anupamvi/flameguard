from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class RuleGenRequest(BaseModel):
    intent: str = Field(min_length=5, max_length=4000)
    vendor: str = Field(min_length=1, max_length=64)
    context: Optional[str] = Field(default=None, max_length=8000)


class RuleGenResponse(BaseModel):
    config: dict[str, Any]
    explanation: str
    warnings: list[str]
    is_valid: bool


class FrontendRuleGenRequest(BaseModel):
    description: str = Field(min_length=5, max_length=4000)
    vendor: str = Field(min_length=1, max_length=64)
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    category: str = Field(default="general", min_length=1, max_length=64)


class FrontendRuleGenResponse(BaseModel):
    rule: dict[str, Any]
    explanation: str
    confidence: float
    warnings: list[str]
