"""Offline tests for evidence packaging with the existing compositional contracts."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from pydantic import ValidationError

from backend.incidents.evidence import build_evidence_pack
from backend.incidents.models import EvidencePack
from backend.intelligence.models import (
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


class EvidencePackagingTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    @staticmethod
    def scan_time() -> datetime:
        return datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    def scan_result(self) -> ScanResult:
        return ScanResult(
            scan_id=self.scan_id,
            modality=Modality.URL,
            timestamp=self.scan_time(),
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
                processed_at=self.scan_time(),
            ),
            input_reference=InputReference(
                reference_uri="storage://scans/input-1", content_hash="abc123"
            ),
        )

    def indicator(self, suffix: int = 1) -> Indicator:
        return Indicator(
            indicator_id=UUID(f"a5816e23-1735-4d55-a7dc-d6749105e6{suffix:02d}"),
            type=IndicatorType.DOMAIN,
            value=f"secure-acme{suffix}.example.test",
            source="scan_result",
            context={"position": suffix},
        )

    def intelligence(
        self, indicator: Indicator, reputation: Reputation, status: ProviderStatus
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=reputation,
            source="threat_intelligence_aggregator",
            queried_at=self.scan_time(),
            status=status,
            findings=[
                ThreatIntelFinding(
                    source="provider-a",
                    category="provider_result_summary",
                    description="Provider evidence.",
                ),
                ThreatIntelFinding(
                    source="threat_intelligence_aggregator",
                    category="reputation_conflict",
                    description="Conflicting provider evidence retained.",
                ),
            ],
        )

    def test_build_preserves_detection_context_and_original_reference(self) -> None:
        scan = self.scan_result()
        indicator = self.indicator()
        intelligence = self.intelligence(indicator, Reputation.SUSPICIOUS, ProviderStatus.SUCCESS)
        collected_at = datetime(2026, 9, 22, 9, 30, tzinfo=timezone.utc)
        evidence = build_evidence_pack(scan, [indicator], [intelligence], collected_at=collected_at)

        self.assertEqual(evidence.scan_id, scan.scan_id)
        self.assertEqual(evidence.scan_result.input_reference, scan.input_reference)
        self.assertEqual(evidence.scan_result.risk_score, 88)
        self.assertEqual(evidence.scan_result.severity, Severity.HIGH)
        self.assertEqual(evidence.scan_result.confidence, 0.93)
        self.assertEqual(evidence.scan_result.threat_type, "credential_phishing")
        self.assertEqual(evidence.scan_result.signals, scan.signals)
        self.assertEqual(evidence.scan_result.explanation, scan.explanation)
        self.assertEqual(evidence.scan_result.provenance, scan.provenance)
        self.assertEqual(evidence.collected_at, collected_at)
        self.assertEqual(evidence.scan_result.timestamp, self.scan_time())

    def test_indicators_and_intelligence_are_preserved_without_reinterpretation(self) -> None:
        first = self.indicator(1)
        second = self.indicator(2)
        unknown = self.intelligence(first, Reputation.UNKNOWN, ProviderStatus.SUCCESS)
        unavailable = self.intelligence(
            second, Reputation.UNAVAILABLE, ProviderStatus.UNAVAILABLE
        )
        evidence = build_evidence_pack(self.scan_result(), [first, second], [unknown, unavailable])

        enriched = evidence.enriched_threat_result
        self.assertEqual(enriched.indicators, [first, second])
        self.assertEqual(enriched.threat_intelligence, [unknown, unavailable])
        self.assertEqual(enriched.threat_intelligence[0].reputation, Reputation.UNKNOWN)
        self.assertEqual(enriched.threat_intelligence[1].reputation, Reputation.UNAVAILABLE)
        self.assertTrue(
            any(
                finding.category == "reputation_conflict"
                for finding in enriched.threat_intelligence[0].findings
            )
        )
        self.assertEqual(enriched.status, ProviderStatus.SUCCESS)

    def test_empty_lists_work_and_snapshot_is_isolated_from_callers(self) -> None:
        scan = self.scan_result()
        indicators = [self.indicator()]
        intelligence = [self.intelligence(indicators[0], Reputation.BENIGN, ProviderStatus.SUCCESS)]
        evidence = build_evidence_pack(scan, indicators, intelligence)
        indicators.append(self.indicator(2))
        intelligence[0].findings[0].description = "mutated caller finding"
        scan.input_reference.reference_uri = "storage://scans/changed"

        self.assertEqual(len(evidence.enriched_threat_result.indicators), 1)
        self.assertEqual(
            evidence.enriched_threat_result.threat_intelligence[0].findings[0].description,
            "Provider evidence.",
        )
        self.assertEqual(evidence.scan_result.input_reference.reference_uri, "storage://scans/input-1")
        empty = build_evidence_pack(self.scan_result(), [], [])
        self.assertEqual(empty.enriched_threat_result.indicators, [])
        self.assertEqual(empty.enriched_threat_result.threat_intelligence, [])
        self.assertEqual(empty.enriched_threat_result.status, ProviderStatus.UNAVAILABLE)

    def test_identity_timestamp_and_serialization_validation(self) -> None:
        scan = self.scan_result()
        evidence = build_evidence_pack(scan, [], [])
        self.assertIsNotNone(evidence.collected_at.tzinfo)
        self.assertEqual(evidence.collected_at.utcoffset(), timezone.utc.utcoffset(evidence.collected_at))
        restored = EvidencePack.model_validate_json(evidence.model_dump_json())
        self.assertEqual(restored.scan_id, scan.scan_id)

        payload = evidence.model_dump()
        payload["scan_id"] = UUID("4e658c53-9c1c-4b79-9ad3-8a2c4e4192cf")
        with self.assertRaises(ValidationError):
            EvidencePack.model_validate(payload)
        with self.assertRaises(ValueError):
            build_evidence_pack(scan, [], [], collected_at=datetime(2026, 9, 22, 9, 30))


if __name__ == "__main__":
    unittest.main()
