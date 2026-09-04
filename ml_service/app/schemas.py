from typing import Any
from pydantic import BaseModel, Field

class PredictRequest(BaseModel):
    features: dict[str, Any]

class PredictResponse(BaseModel):
    classification: str
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
