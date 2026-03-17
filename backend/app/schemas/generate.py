from typing import Any, Optional

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
