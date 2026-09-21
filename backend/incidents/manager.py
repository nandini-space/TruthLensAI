"""Side-effect-free incident creation and lifecycle domain operations."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from backend.incidents.models import EvidencePack, Incident, IncidentStatus


_VALID_TRANSITIONS = {
    IncidentStatus.OPEN: IncidentStatus.INVESTIGATING,
    IncidentStatus.INVESTIGATING: IncidentStatus.RESOLVED,
}


def create_incident(
    evidence_pack: EvidencePack, *, created_at: datetime | None = None
) -> Incident:
    """Create an OPEN incident from a validated, deep-copied evidence snapshot."""

    evidence_snapshot = _validated_evidence_snapshot(evidence_pack)
    timestamp = _utc_timestamp(created_at, field_name="created_at")
    scan = evidence_snapshot.scan_result
    return Incident(
        incident_id=uuid5(
            NAMESPACE_URL, f"truthlensai:incident:{evidence_snapshot.evidence_id}"
        ),
        scan_id=evidence_snapshot.scan_id,
        threat_type=scan.threat_type,
        severity=scan.severity,
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        status=IncidentStatus.OPEN,
        created_at=timestamp,
        updated_at=timestamp,
        evidence_pack=evidence_snapshot,
        evidence_reference=str(evidence_snapshot.evidence_id),
    )


def update_incident_status(
    incident: Incident,
    status: IncidentStatus,
    *,
    updated_at: datetime | None = None,
) -> Incident:
    """Return a new incident snapshot after one valid lifecycle transition."""

    if not isinstance(incident, Incident):
        raise TypeError("incident must be an Incident")
    if not isinstance(status, IncidentStatus):
        raise TypeError("status must be an IncidentStatus")
    if status == incident.status:
        raise ValueError("incident status is already set to the requested state")
    if _VALID_TRANSITIONS.get(incident.status) is not status:
        raise ValueError(
            f"invalid incident transition: {incident.status.value} -> {status.value}"
        )

    timestamp = _utc_timestamp(updated_at, field_name="updated_at")
    if timestamp < incident.updated_at:
        raise ValueError("updated_at cannot be earlier than the current updated_at")
    updated = incident.model_copy(deep=True, update={"status": status, "updated_at": timestamp})
    return Incident.model_validate(updated.model_dump())


def _validated_evidence_snapshot(evidence_pack: EvidencePack) -> EvidencePack:
    if not isinstance(evidence_pack, EvidencePack):
        raise TypeError("evidence_pack must be an EvidencePack")
    return EvidencePack.model_validate(evidence_pack.model_dump()).model_copy(deep=True)


def _utc_timestamp(value: datetime | None, *, field_name: str) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)
