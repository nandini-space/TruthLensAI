"""Side-effect-free generation of validated forensic-report snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from backend.incidents.models import EvidencePack, Incident
from backend.reports.models import ForensicReport


def build_forensic_report(
    incident: Incident,
    evidence_pack: EvidencePack,
    *,
    generated_at: datetime | None = None,
) -> ForensicReport:
    """Build an independent report snapshot from one incident and its evidence."""

    incident_snapshot = _validated_incident_snapshot(incident)
    evidence_snapshot = _validated_evidence_snapshot(evidence_pack)
    _validate_relationship(incident_snapshot, evidence_snapshot)

    scan = evidence_snapshot.scan_result
    enrichment = evidence_snapshot.enriched_threat_result
    return ForensicReport(
        report_id=uuid5(
            NAMESPACE_URL,
            f"truthlensai:forensic-report:{incident_snapshot.incident_id}:"
            f"{evidence_snapshot.evidence_id}",
        ),
        incident_id=incident_snapshot.incident_id,
        scan_id=evidence_snapshot.scan_id,
        threat_type=scan.threat_type,
        risk_score=scan.risk_score,
        severity=scan.severity,
        confidence=scan.confidence,
        original_input=scan.input_reference.model_copy(deep=True),
        indicators=[indicator.model_copy(deep=True) for indicator in enrichment.indicators],
        detected_signals=[signal.model_copy(deep=True) for signal in scan.signals],
        analysis=scan.explanation,
        threat_intelligence=[
            result.model_copy(deep=True) for result in enrichment.threat_intelligence
        ],
        recommended_action=scan.recommendation,
        generated_at=_utc_timestamp(generated_at),
        evidence_pack=evidence_snapshot,
        incident=incident_snapshot,
    )


def _validated_incident_snapshot(incident: Incident) -> Incident:
    if not isinstance(incident, Incident):
        raise TypeError("incident must be an Incident")
    return Incident.model_validate(incident.model_dump()).model_copy(deep=True)


def _validated_evidence_snapshot(evidence_pack: EvidencePack) -> EvidencePack:
    if not isinstance(evidence_pack, EvidencePack):
        raise TypeError("evidence_pack must be an EvidencePack")
    return EvidencePack.model_validate(evidence_pack.model_dump()).model_copy(deep=True)


def _validate_relationship(incident: Incident, evidence_pack: EvidencePack) -> None:
    if incident.scan_id != evidence_pack.scan_id:
        raise ValueError("incident.scan_id must match evidence_pack.scan_id")
    if (
        incident.evidence_pack is not None
        and incident.evidence_pack.evidence_id != evidence_pack.evidence_id
    ):
        raise ValueError("incident.evidence_pack must match the supplied evidence_pack")
    if (
        incident.evidence_reference is not None
        and incident.evidence_reference != str(evidence_pack.evidence_id)
    ):
        raise ValueError("incident.evidence_reference must match evidence_pack.evidence_id")


def _utc_timestamp(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    return value.astimezone(timezone.utc)
