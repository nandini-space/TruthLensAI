"""Provider-neutral contracts for Module 2 threat-intelligence enrichment."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import Field, JsonValue, model_validator

from backend.models.schemas import ContractModel, ScanResult


class IndicatorType(str, Enum):
    """Observable types Module 2 may investigate after extraction."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    PHONE = "phone"
    OTHER = "other"


class Reputation(str, Enum):
    """Normalized intelligence reputation, not a provider-specific verdict."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class ProviderStatus(str, Enum):
    """Outcome of a provider query or enrichment operation."""

    SUCCESS = "success"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class Indicator(ContractModel):
    """A normalized security-relevant observable selected for investigation."""

    indicator_id: UUID
    type: IndicatorType
    value: Annotated[str, Field(min_length=1)]
    source: Annotated[str, Field(min_length=1)]
    confidence: Annotated[float | None, Field(ge=0, le=1)] = None
    context: dict[str, JsonValue] = Field(default_factory=dict)


class ThreatIntelFinding(ContractModel):
    """A provider-neutral individual observation about an indicator."""

    source: Annotated[str, Field(min_length=1)]
    category: Annotated[str, Field(min_length=1)]
    description: Annotated[str, Field(min_length=1)]
    confidence: Annotated[float | None, Field(ge=0, le=1)] = None
    timestamp: datetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class ThreatIntelResult(ContractModel):
    """A normalized result from one intelligence source for one indicator."""

    indicator: Indicator
    reputation: Reputation
    confidence: Annotated[float | None, Field(ge=0, le=1)] = None
    source: Annotated[str, Field(min_length=1)]
    queried_at: datetime
    status: ProviderStatus
    findings: list[ThreatIntelFinding] = Field(default_factory=list)
    provider_reference: str | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def provider_failure_is_not_benign(self) -> ThreatIntelResult:
        if self.status in {ProviderStatus.UNAVAILABLE, ProviderStatus.ERROR}:
            if self.reputation not in {Reputation.UNKNOWN, Reputation.UNAVAILABLE}:
                raise ValueError(
                    "unavailable or failed providers must use unknown or unavailable reputation"
                )
        return self


class EnrichedThreatResult(ContractModel):
    """Module 2 enrichment output composed with the original ScanResult."""

    scan_id: UUID
    scan_result: ScanResult
    indicators: list[Indicator] = Field(default_factory=list)
    threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)
    status: ProviderStatus
    enriched_at: datetime
    provider_sources: list[Annotated[str, Field(min_length=1)]] = Field(
        default_factory=list
    )
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def scan_identity_matches_composed_result(self) -> EnrichedThreatResult:
        if self.scan_id != self.scan_result.scan_id:
            raise ValueError("scan_id must match scan_result.scan_id")
        return self
