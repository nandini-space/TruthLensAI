"""Evidence and incident contracts for future Module 2 investigation work."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import Field, model_validator

from backend.intelligence.models import EnrichedThreatResult
from backend.models.schemas import ContractModel, ScanResult, Severity


class IncidentStatus(str, Enum):
    """Lifecycle position of an incident, independent from detection severity."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class EvidencePack(ContractModel):
    """A compositional evidence snapshot ready for future persistence."""

    evidence_id: UUID
    scan_id: UUID
    scan_result: ScanResult
    enriched_threat_result: EnrichedThreatResult
    collected_at: datetime

    @model_validator(mode="after")
    def composed_objects_share_the_same_scan(self) -> EvidencePack:
        if self.scan_id != self.scan_result.scan_id:
            raise ValueError("scan_id must match scan_result.scan_id")
        if self.scan_id != self.enriched_threat_result.scan_id:
            raise ValueError("scan_id must match enriched_threat_result.scan_id")
        return self


class Incident(ContractModel):
    """A future incident-management record; no lifecycle operations are included."""

    incident_id: UUID
    scan_id: UUID
    threat_type: Annotated[str, Field(min_length=1)]
    severity: Severity
    risk_score: Annotated[float, Field(ge=0, le=100)]
    confidence: Annotated[float, Field(ge=0, le=1)]
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    evidence_pack: EvidencePack | None = None
    evidence_reference: str | None = None
    resolution_information: str | None = None

    @model_validator(mode="after")
    def evidence_matches_incident_scan(self) -> Incident:
        if self.evidence_pack and self.scan_id != self.evidence_pack.scan_id:
            raise ValueError("scan_id must match evidence_pack.scan_id")
        return self
