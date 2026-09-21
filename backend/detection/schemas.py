"""Version-stable data contracts shared by detection clients and consumers."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class InputType(StrEnum):
    """Input modalities supported by the detection pipeline."""

    TEXT = "text"
    URL = "url"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"


class Severity(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(StrEnum):
    BENIGN = "benign"
    PHISHING = "phishing"
    SCAM = "scam"
    MALICIOUS_URL = "malicious_url"
    SOCIAL_ENGINEERING = "social_engineering"
    MALWARE = "malware"
    HARASSMENT = "harassment"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class Indicator(BaseModel):
    """A generic extracted indicator with optional source context."""

    value: str = Field(min_length=1, max_length=2_048)
    kind: str = Field(min_length=1, max_length=64)
    context: str | None = Field(default=None, max_length=1_024)


class ExtractedEntities(BaseModel):
    """Indicators extracted from an input without assigning threat meaning."""

    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)


class Signal(BaseModel):
    """An auditable observation produced by a future detector."""

    code: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=1_024)
    source: str = Field(min_length=1, max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    """Normalized input handed to exactly one modality detector."""

    scan_id: UUID = Field(default_factory=uuid4)
    input_type: InputType
    content: str = Field(min_length=1, description="Raw text, URL, or a future asset reference.")
    mime_type: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("content must not be blank")
        return value


class ScanResult(BaseModel):
    """Stable result contract for Module 2 and future user interfaces."""

    scan_id: UUID = Field(default_factory=uuid4)
    input_type: InputType
    risk_score: float | None = Field(default=None, ge=0, le=100)
    severity: Severity
    threat_type: ThreatType
    confidence: float | None = Field(default=None, ge=0, le=1)
    signals: list[Signal] = Field(default_factory=list)
    explanation: str = Field(min_length=1, max_length=4_000)
    recommendation: str = Field(min_length=1, max_length=4_000)
    entities: ExtractedEntities = Field(default_factory=ExtractedEntities)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
