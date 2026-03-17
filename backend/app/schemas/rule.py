from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RuleOut(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    original_id: str
    name: str
    vendor: str
    action: str
    direction: str
    protocol: Optional[str] = None
    source_addresses: list[str]
    source_ports: list[str]
    destination_addresses: list[str]
    destination_ports: list[str]
    priority: Optional[int] = None
    collection_name: Optional[str] = None
    collection_priority: Optional[int] = None
    description: str
    enabled: bool
    risk_score: Optional[float] = None
    tags: dict[str, str]


class RuleSetOut(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    filename: str
    vendor: str
    rule_count: int
    uploaded_at: datetime


class RuleExplainResponse(BaseModel):
    rule_id: str
    explanation: str
    concerns: list[str]
