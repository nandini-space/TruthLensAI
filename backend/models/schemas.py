"""Shared, versioned data contracts exchanged between TruthLensAI modules."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class ContractModel(BaseModel):
    """Base behavior for public inter-module contracts."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Modality(str, Enum):
    """Supported input types for a detection scan."""

    TEXT = "text"
    URL = "url"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"


class Severity(str, Enum):
    """Detection severity; this is not an incident lifecycle state."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionSignal(ContractModel):
    """A machine-readable signal contributing to a detection result."""

    name: Annotated[str, Field(min_length=1)]
    value: Annotated[str, Field(min_length=1)]
    source: Annotated[str, Field(min_length=1)]
    confidence: Annotated[float | None, Field(ge=0, le=1)] = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class ExtractedEntity(ContractModel):
    """An entity found by Module 1, before any Module 2 enrichment."""

    entity_type: Annotated[str, Field(min_length=1)]
    value: Annotated[str, Field(min_length=1)]
    normalized_value: str | None = None
    confidence: Annotated[float | None, Field(ge=0, le=1)] = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class Provenance(ContractModel):
    """Source and detector details needed to trace a scan result."""

    source: Annotated[str, Field(min_length=1)]
    detector_id: Annotated[str, Field(min_length=1)]
    detector_version: str | None = None
    processed_at: datetime
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class InputReference(ContractModel):
    """Safe representation of the input analyzed by Module 1.

    ``original_content`` is only for reasonably sized textual content. Binary or
    large inputs must be represented by ``reference_uri`` (and optionally a hash),
    never embedded as image, audio, or video blobs in this contract.
    """

    original_content: Annotated[str | None, Field(max_length=100_000)] = None
    reference_uri: str | None = None
    content_hash: str | None = None
    media_type: str | None = None

    @model_validator(mode="after")
    def has_content_or_reference(self) -> InputReference:
        if not self.original_content and not self.reference_uri:
            raise ValueError("either original_content or reference_uri is required")
        return self


class ScanResult(ContractModel):
    """Canonical normalized output from Module 1 consumed by Module 2.

    ``risk_score`` uses the inclusive 0--100 scale. ``confidence`` uses the
    inclusive 0--1 scale. This model intentionally excludes enrichment, incident,
    evidence, reporting, and other Module 2 fields.
    """

    scan_id: UUID
    modality: Modality
    timestamp: datetime
    risk_score: Annotated[float, Field(ge=0, le=100)]
    severity: Severity
    confidence: Annotated[float, Field(ge=0, le=1)]
    threat_type: Annotated[str, Field(min_length=1)]
    signals: list[DetectionSignal]
    explanation: Annotated[str, Field(min_length=1)]
    extracted_entities: list[ExtractedEntity]
    recommendation: Annotated[str, Field(min_length=1)]
    provenance: Provenance
    input_reference: InputReference
