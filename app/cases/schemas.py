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

    model_config = ConfigDict(from_attributes=True)
