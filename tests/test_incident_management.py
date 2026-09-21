"""Tests for side-effect-free incident creation and lifecycle validation."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from pydantic import ValidationError

from backend.incidents.evidence import build_evidence_pack
from backend.incidents.manager import create_incident, update_incident_status
from backend.incidents.models import EvidencePack, IncidentStatus
from backend.intelligence.models import Indicator, IndicatorType
from backend.models.schemas import (
    DetectionSignal,
    ExtractedEntity,
    InputReference,
    Modality,
    Provenance,
    ScanResult,
    Severity,
)


class IncidentManagementTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    @staticmethod
    def timestamp(hour: int = 12) -> datetime:
        return datetime(2026, 9, 21, hour, 0, tzinfo=timezone.utc)

    def evidence_pack(self):
        scan = ScanResult(
            scan_id=self.scan_id,
            modality=Modality.URL,
            timestamp=self.timestamp(),
            risk_score=88,
            severity=Severity.HIGH,
            confidence=0.93,
            threat_type="credential_phishing",
            signals=[
                DetectionSignal(
                    name="lookalike-domain",
                    value="secure-acme.example.test",
                    source="url-detector",
                )
            ],
            explanation="The URL imitates a known login domain.",
            extracted_entities=[
                ExtractedEntity(entity_type="domain", value="secure-acme.example.test")
            ],
            recommendation="Do not visit the URL.",
            provenance=Provenance(
                source="web-upload",
                detector_id="multimodal-detector",
                processed_at=self.timestamp(),
            ),
            input_reference=InputReference(reference_uri="storage://scans/input-1"),
        )
        indicator = Indicator(
            indicator_id=UUID("a5816e23-1735-4d55-a7dc-d6749105e660"),
            type=IndicatorType.DOMAIN,
            value="secure-acme.example.test",
            source="scan_result",
        )
        return build_evidence_pack(scan, [indicator], [], collected_at=self.timestamp(13))

    def test_create_incident_preserves_evidence_and_detection_fields(self) -> None:
        evidence = self.evidence_pack()
        incident = create_incident(evidence, created_at=self.timestamp(14))
        self.assertEqual(incident.status, IncidentStatus.OPEN)
        self.assertEqual(incident.scan_id, evidence.scan_id)
        self.assertEqual(incident.evidence_pack.evidence_id, evidence.evidence_id)
        self.assertEqual(incident.evidence_reference, str(evidence.evidence_id))
        self.assertEqual(incident.threat_type, "credential_phishing")
        self.assertEqual(incident.severity, Severity.HIGH)
        self.assertEqual(incident.risk_score, 88)
        self.assertEqual(incident.confidence, 0.93)
        self.assertEqual(incident.created_at, self.timestamp(14))
        self.assertEqual(incident.updated_at, self.timestamp(14))

    def test_valid_lifecycle_transitions_are_returned_as_new_snapshots(self) -> None:
        incident = create_incident(self.evidence_pack(), created_at=self.timestamp(14))
        investigating = update_incident_status(
            incident, IncidentStatus.INVESTIGATING, updated_at=self.timestamp(15)
        )
        resolved = update_incident_status(
            investigating, IncidentStatus.RESOLVED, updated_at=self.timestamp(16)
        )
        self.assertEqual(incident.status, IncidentStatus.OPEN)
        self.assertEqual(investigating.status, IncidentStatus.INVESTIGATING)
        self.assertEqual(resolved.status, IncidentStatus.RESOLVED)
        self.assertEqual(resolved.updated_at, self.timestamp(16))

    def test_invalid_and_same_state_transitions_are_rejected(self) -> None:
        incident = create_incident(self.evidence_pack(), created_at=self.timestamp(14))
        with self.assertRaises(ValueError):
            update_incident_status(incident, IncidentStatus.OPEN)
        with self.assertRaises(ValueError):
            update_incident_status(incident, IncidentStatus.RESOLVED)
        resolved = update_incident_status(
            update_incident_status(
                incident, IncidentStatus.INVESTIGATING, updated_at=self.timestamp(15)
            ),
            IncidentStatus.RESOLVED,
            updated_at=self.timestamp(16),
        )
        for status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED):
            with self.subTest(status=status), self.assertRaises(ValueError):
                update_incident_status(resolved, status, updated_at=self.timestamp(17))

    def test_timestamps_mutation_safety_and_evidence_validation(self) -> None:
        evidence = self.evidence_pack()
        incident = create_incident(evidence)
        self.assertEqual(incident.created_at.tzinfo, timezone.utc)
        incident.evidence_pack.scan_result.input_reference.reference_uri = "storage://changed"
        self.assertEqual(evidence.scan_result.input_reference.reference_uri, "storage://scans/input-1")
        with self.assertRaises(ValueError):
            create_incident(evidence, created_at=datetime(2026, 9, 21, 14, 0))

        invalid_evidence = evidence.model_copy(
            update={"scan_id": UUID("4e658c53-9c1c-4b79-9ad3-8a2c4e4192cf")}
        )
        with self.assertRaises(ValidationError):
            create_incident(invalid_evidence)


if __name__ == "__main__":
    unittest.main()
