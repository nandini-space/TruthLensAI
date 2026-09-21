"""Forensic-report data contract for future Module 2 report generation."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field, model_validator

from backend.incidents.models import EvidencePack, Incident
from backend.intelligence.models import Indicator, ThreatIntelResult
from backend.models.schemas import ContractModel, DetectionSignal, InputReference, Severity


class ForensicReport(ContractModel):
    """Structured report payload; report generation and storage are future work."""

    report_id: UUID
    incident_id: UUID
    scan_id: UUID
    threat_type: str = Field(min_length=1)
    risk_score: float = Field(ge=0, le=100)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    original_input: InputReference
    indicators: list[Indicator] = Field(default_factory=list)
    detected_signals: list[DetectionSignal] = Field(default_factory=list)
    analysis: str = Field(min_length=1)
    threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)
    recommended_action: str = Field(min_length=1)
    generated_at: datetime
    evidence_pack: EvidencePack
    incident: Incident

    @model_validator(mode="after")
    def related_contracts_share_identifiers(self) -> ForensicReport:
        if self.incident_id != self.incident.incident_id:
            raise ValueError("incident_id must match incident.incident_id")
        if self.scan_id != self.evidence_pack.scan_id:
            raise ValueError("scan_id must match evidence_pack.scan_id")
        if self.scan_id != self.incident.scan_id:
            raise ValueError("scan_id must match incident.scan_id")
        return self
