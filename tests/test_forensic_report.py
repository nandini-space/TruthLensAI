"""Tests for side-effect-free forensic report generation."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from backend.incidents.evidence import build_evidence_pack
from backend.incidents.manager import create_incident, update_incident_status
from backend.incidents.models import IncidentStatus
from backend.intelligence.models import (
    Indicator,
    IndicatorType,
    ProviderStatus,
    Reputation,
    ThreatIntelResult,
)
from backend.models.schemas import (
    DetectionSignal,
    ExtractedEntity,
    InputReference,
    Modality,
    Provenance,
    ScanResult,
    Severity,
)
from backend.reports.forensic import build_forensic_report
from backend.reports.models import ForensicReport


class ForensicReportTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    @staticmethod
    def timestamp(hour: int = 12) -> datetime:
        return datetime(2026, 9, 22, hour, 0, tzinfo=timezone.utc)

    def evidence_pack(self, *, scan_id: UUID | None = None):
        scan = ScanResult(
            scan_id=scan_id or self.scan_id,
            modality=Modality.URL,
            timestamp=self.timestamp(),
            risk_score=88,
            severity=Severity.HIGH,
            confidence=0.93,
            threat_type="credential_phishing",
            signals=[DetectionSignal(name="lookalike-domain", value="acme-login.test", source="url-detector")],
            explanation="The URL imitates a known login domain.",
            extracted_entities=[ExtractedEntity(entity_type="domain", value="acme-login.test")],
            recommendation="Do not visit the URL.",
            provenance=Provenance(source="web-upload", detector_id="detector", processed_at=self.timestamp()),
            input_reference=InputReference(reference_uri="storage://scans/input-1"),
        )
        indicator = Indicator(
            indicator_id=UUID("a5816e23-1735-4d55-a7dc-d6749105e660"),
            type=IndicatorType.DOMAIN,
            value="acme-login.test",
            source="scan_result",
            context={"entity_type": "domain"},
        )
        unavailable = ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.UNAVAILABLE,
            source="community_intelligence",
            queried_at=self.timestamp(13),
            status=ProviderStatus.UNAVAILABLE,
        )
        return build_evidence_pack(scan, [indicator], [unavailable], collected_at=self.timestamp(13))

    def test_build_preserves_evidence_and_serializes(self) -> None:
        evidence = self.evidence_pack()
        incident = create_incident(evidence, created_at=self.timestamp(14))
        report = build_forensic_report(incident, evidence, generated_at=self.timestamp(15))

        self.assertIsInstance(report, ForensicReport)
        self.assertEqual(report.incident_id, incident.incident_id)
        self.assertEqual(report.scan_id, evidence.scan_id)
        self.assertEqual(report.threat_type, "credential_phishing")
        self.assertEqual(report.severity, Severity.HIGH)
        self.assertEqual(report.original_input.reference_uri, "storage://scans/input-1")
        self.assertEqual(report.indicators, evidence.enriched_threat_result.indicators)
        self.assertEqual(report.detected_signals, evidence.scan_result.signals)
        self.assertEqual(report.analysis, evidence.scan_result.explanation)
        self.assertEqual(report.recommended_action, evidence.scan_result.recommendation)
        self.assertEqual(report.incident.status, IncidentStatus.OPEN)
        self.assertEqual(report.threat_intelligence[0].reputation, Reputation.UNAVAILABLE)
        self.assertEqual(report.threat_intelligence[0].status, ProviderStatus.UNAVAILABLE)
        self.assertEqual(report.generated_at, self.timestamp(15))
        self.assertEqual(ForensicReport.model_validate_json(report.model_dump_json()), report)

    def test_identity_mismatch_is_rejected(self) -> None:
        evidence = self.evidence_pack()
        incident = create_incident(evidence, created_at=self.timestamp(14))
        other_evidence = self.evidence_pack(
            scan_id=UUID("4e658c53-9c1c-4b79-9ad3-8a2c4e4192cf")
        )
        with self.assertRaises(ValueError):
            build_forensic_report(incident, other_evidence)

        mismatched_reference = incident.model_copy(update={"evidence_reference": "other-evidence"})
        with self.assertRaises(ValueError):
            build_forensic_report(mismatched_reference, evidence)

    def test_lifecycle_timestamp_and_snapshots_are_independent(self) -> None:
        evidence = self.evidence_pack()
        incident = update_incident_status(
            create_incident(evidence, created_at=self.timestamp(14)),
            IncidentStatus.INVESTIGATING,
            updated_at=self.timestamp(15),
        )
        report = build_forensic_report(incident, evidence)

        self.assertEqual(report.incident.status, IncidentStatus.INVESTIGATING)
        self.assertEqual(incident.status, IncidentStatus.INVESTIGATING)
        self.assertEqual(report.generated_at.tzinfo, timezone.utc)
        report.original_input.reference_uri = "storage://changed"
        report.indicators[0].context["entity_type"] = "changed"
        report.incident.status = IncidentStatus.RESOLVED
        self.assertEqual(evidence.scan_result.input_reference.reference_uri, "storage://scans/input-1")
        self.assertEqual(evidence.enriched_threat_result.indicators[0].context["entity_type"], "domain")
        self.assertEqual(incident.status, IncidentStatus.INVESTIGATING)
        with self.assertRaises(ValueError):
            build_forensic_report(incident, evidence, generated_at=datetime(2026, 9, 22, 16, 0))


if __name__ == "__main__":
    unittest.main()
