"""Focused tests for the provider-neutral Module 2 data contracts."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from pydantic import ValidationError

from backend.incidents.models import EvidencePack, Incident, IncidentStatus
from backend.intelligence.models import (
    EnrichedThreatResult,
    Indicator,
    IndicatorType,
    ProviderStatus,
    Reputation,
    ThreatIntelFinding,
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
from backend.reports.models import ForensicReport


class Module2ContractTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")
    indicator_id = UUID("a5816e23-1735-4d55-a7dc-d6749105e660")
    evidence_id = UUID("de7e9e5f-9707-4ce9-a5f7-5d7997bc11a9")
    incident_id = UUID("4e658c53-9c1c-4b79-9ad3-8a2c4e4192cf")
    report_id = UUID("9e4b8dca-b43a-4a46-b71d-e2d90dd3d779")

    @staticmethod
    def now() -> datetime:
        return datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    def scan_result(self) -> ScanResult:
        return ScanResult(
            scan_id=self.scan_id,
            modality=Modality.URL,
            timestamp=self.now(),
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
                ExtractedEntity(
                    entity_type="domain", value="secure-acme.example.test"
                )
            ],
            recommendation="Do not visit the URL.",
            provenance=Provenance(
                source="web-upload",
                detector_id="multimodal-detector",
                processed_at=self.now(),
            ),
            input_reference=InputReference(reference_uri="storage://scans/input-1"),
        )

    def indicator(self) -> Indicator:
        return Indicator(
            indicator_id=self.indicator_id,
            type=IndicatorType.DOMAIN,
            value="secure-acme.example.test",
            source="scan-result.entity",
            confidence=0.99,
            context={"entity_type": "domain"},
        )

    def intel_result(self, status: ProviderStatus = ProviderStatus.SUCCESS) -> ThreatIntelResult:
        reputation = Reputation.MALICIOUS
        if status in {ProviderStatus.UNAVAILABLE, ProviderStatus.ERROR}:
            reputation = Reputation.UNAVAILABLE
        return ThreatIntelResult(
            indicator=self.indicator(),
            reputation=reputation,
            confidence=0.87,
            source="provider-a",
            queried_at=self.now(),
            status=status,
            findings=[
                ThreatIntelFinding(
                    source="provider-a",
                    category="phishing",
                    description="Indicator is associated with credential theft.",
                    confidence=0.87,
                    timestamp=self.now(),
                )
            ],
            provider_reference="provider-a:indicator:123",
        )

    def enriched_result(self) -> EnrichedThreatResult:
        scan = self.scan_result()
        return EnrichedThreatResult(
            scan_id=scan.scan_id,
            scan_result=scan,
            indicators=[self.indicator()],
            threat_intelligence=[self.intel_result()],
            status=ProviderStatus.SUCCESS,
            enriched_at=self.now(),
            provider_sources=["provider-a"],
        )

    def evidence_pack(self) -> EvidencePack:
        scan = self.scan_result()
        return EvidencePack(
            evidence_id=self.evidence_id,
            scan_id=scan.scan_id,
            scan_result=scan,
            enriched_threat_result=self.enriched_result(),
            collected_at=self.now(),
        )

    def incident(self) -> Incident:
        return Incident(
            incident_id=self.incident_id,
            scan_id=self.scan_id,
            threat_type="credential_phishing",
            severity=Severity.HIGH,
            risk_score=88,
            confidence=0.93,
            status=IncidentStatus.INVESTIGATING,
            created_at=self.now(),
            updated_at=self.now(),
            evidence_pack=self.evidence_pack(),
        )

    def test_valid_indicator_and_empty_value_validation(self) -> None:
        self.assertEqual(self.indicator().type, IndicatorType.DOMAIN)
        with self.assertRaises(ValidationError):
            Indicator(
                indicator_id=self.indicator_id,
                type=IndicatorType.DOMAIN,
                value="",
                source="scan-result.entity",
            )

    def test_valid_threat_intel_and_unavailable_state(self) -> None:
        self.assertEqual(self.intel_result().reputation, Reputation.MALICIOUS)
        unavailable = self.intel_result(ProviderStatus.UNAVAILABLE)
        self.assertEqual(unavailable.reputation, Reputation.UNAVAILABLE)
        self.assertEqual(unavailable.status, ProviderStatus.UNAVAILABLE)

    def test_provider_failure_cannot_be_converted_to_benign(self) -> None:
        payload = self.intel_result(ProviderStatus.ERROR).model_dump()
        payload["reputation"] = Reputation.BENIGN
        with self.assertRaises(ValidationError):
            ThreatIntelResult.model_validate(payload)

    def test_enriched_result_supports_multiple_indicators_and_findings(self) -> None:
        result = self.enriched_result()
        second_indicator = self.indicator().model_copy(
            update={
                "indicator_id": UUID("4a0553a6-cc44-4718-a3ed-308714310fe4"),
                "type": IndicatorType.URL,
                "value": "https://secure-acme.example.test/login",
            }
        )
        second_finding = result.threat_intelligence[0].findings[0].model_copy(
            update={"category": "credential-theft", "description": "Login page detected."}
        )
        result = result.model_copy(
            update={
                "indicators": [result.indicators[0], second_indicator],
                "threat_intelligence": [
                    result.threat_intelligence[0].model_copy(
                        update={
                            "findings": [
                                result.threat_intelligence[0].findings[0],
                                second_finding,
                            ]
                        }
                    )
                ],
            }
        )
        self.assertEqual(len(result.indicators), 2)
        self.assertEqual(len(result.threat_intelligence[0].findings), 2)

    def test_valid_evidence_pack_and_incident_statuses(self) -> None:
        self.assertEqual(self.evidence_pack().scan_id, self.scan_id)
        for status in IncidentStatus:
            with self.subTest(status=status):
                incident = self.incident().model_copy(update={"status": status})
                self.assertEqual(incident.status, status)

    def test_incident_status_is_independent_from_severity(self) -> None:
        incident = self.incident()
        self.assertEqual(incident.severity, Severity.HIGH)
        self.assertEqual(incident.status, IncidentStatus.INVESTIGATING)
        payload = incident.model_dump()
        payload["status"] = "critical"
        with self.assertRaises(ValidationError):
            Incident.model_validate(payload)

    def test_valid_forensic_report_and_round_trip_serialization(self) -> None:
        evidence = self.evidence_pack()
        report = ForensicReport(
            report_id=self.report_id,
            incident_id=self.incident_id,
            scan_id=self.scan_id,
            threat_type="credential_phishing",
            risk_score=88,
            severity=Severity.HIGH,
            confidence=0.93,
            original_input=self.scan_result().input_reference,
            indicators=[self.indicator()],
            detected_signals=self.scan_result().signals,
            analysis="The indicator and detector signals support a phishing assessment.",
            threat_intelligence=[self.intel_result()],
            recommended_action="Block the domain and alert affected users.",
            generated_at=self.now(),
            evidence_pack=evidence,
            incident=self.incident(),
        )
        restored = ForensicReport.model_validate_json(report.model_dump_json())
        self.assertEqual(restored.report_id, report.report_id)
        self.assertEqual(restored.incident.status, IncidentStatus.INVESTIGATING)


if __name__ == "__main__":
    unittest.main()
