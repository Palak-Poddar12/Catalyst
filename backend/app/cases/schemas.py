from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    severity: str = "LOW"

class CaseResponse(BaseModel):
    id: int
    title: str
    name: str
    description: str
    severity: str
    case_id: int | None = None
    subject: str | None = None
    sender: str | None = None
    recipient: str | None = None
    classification: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    status: str = "OPEN"
    email_count: int = 0
    latest_analysis_id: int | None = None
    latest_email_id: int | None = None
    created_at: Any | None = None
    updated_at: Any | None = None
    analysis: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)
