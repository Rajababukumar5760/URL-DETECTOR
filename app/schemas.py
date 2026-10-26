from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096, description="URL to analyze; it will not be visited.")

    @field_validator("url")
    @classmethod
    def trim_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Please enter a URL.")
        return value


class RuleFinding(BaseModel):
    rule_id: str
    title: str
    explanation: str
    severity: Literal["info", "low", "medium", "high"]
    evidence: str
    points: int


class AnalyzeResponse(BaseModel):
    valid: bool
    normalized_url: str | None = None
    hostname: str | None = None
    features: dict[str, Any] = Field(default_factory=dict)
    findings: list[RuleFinding] = Field(default_factory=list)
    rule_score: int = 0
    risk_category: Literal["LOW OBSERVED RISK", "CAUTION", "HIGH RISK", "INSUFFICIENT EVIDENCE"]
    explanation: str
    precautions: list[str] = Field(default_factory=list)
    ml: dict[str, Any] = Field(default_factory=dict)
    threat_intelligence: dict[str, Any] = Field(default_factory=lambda: {"checked": False, "status": "not_configured"})