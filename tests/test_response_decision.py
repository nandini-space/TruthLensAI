"""Tests for conservative response policy and dry-run-only blocking."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from backend.incidents.evidence import build_evidence_pack
from backend.incidents.manager import create_incident
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
from backend.response.blocker import DryRunIOCBlocker
from backend.response.decision import decide_response
from backend.response.models import ExecutionMode, ResponseAction


class ResponseDecisionTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    @staticmethod
    def timestamp(hour: int = 12) -> datetime:
        return datetime(2026, 9, 22, hour, 0, tzinfo=timezone.utc)

    def evidence_pack(
        self,
        reputation: Reputation,
        indicator_type: IndicatorType = IndicatorType.DOMAIN,
        *,
        duplicate: bool = False,
        aggregate: bool = False,
    ):
        scan = ScanResult(
            scan_id=self.scan_id,
            modality=Modality.URL,
            timestamp=self.timestamp(),
            risk_score=90,
            severity=Severity.HIGH,
            confidence=0.9,
            threat_type="credential_phishing",
            signals=[DetectionSignal(name="lookalike", value="bad.example", source="url-detector")],
            explanation="Existing evidence.",
            extracted_entities=[ExtractedEntity(entity_type="domain", value="bad.example")],
            recommendation="Do not visit.",
            provenance=Provenance(source="upload", detector_id="detector", processed_at=self.timestamp()),
            input_reference=InputReference(reference_uri="storage://input"),
        )
        indicator = Indicator(
            indicator_id=UUID("a5816e23-1735-4d55-a7dc-d6749105e660"),
            type=indicator_type,
            value="bad.example" if indicator_type is not IndicatorType.PHONE else "+15551234567",
            source="scan_result",
        )
        indicators = [indicator, indicator.model_copy(deep=True)] if duplicate else [indicator]
        result = ThreatIntelResult(
            indicator=indicator,
            reputation=reputation,
            source="threat_intelligence_aggregator" if aggregate else "provider-a",
            queried_at=self.timestamp(13),
            status=(ProviderStatus.UNAVAILABLE if reputation is Reputation.UNAVAILABLE else ProviderStatus.SUCCESS),
        )
        return build_evidence_pack(scan, indicators, [result], collected_at=self.timestamp(13))

    def test_malicious_supported_indicator_is_a_dry_run_block(self) -> None:
        evidence = self.evidence_pack(Reputation.MALICIOUS, aggregate=True)
        decision = decide_response(evidence)[0]
        result = DryRunIOCBlocker().block(decision)
        self.assertEqual(decision.action, ResponseAction.BLOCK)
        self.assertEqual(decision.mode, ExecutionMode.DRY_RUN)
        self.assertTrue(result.would_block)
        self.assertFalse(result.executed)
        self.assertEqual(result.mode, ExecutionMode.DRY_RUN)

    def test_uncertain_benign_and_unsupported_values_never_block(self) -> None:
        for reputation in (
            Reputation.SUSPICIOUS,
            Reputation.UNKNOWN,
            Reputation.UNAVAILABLE,
            Reputation.BENIGN,
        ):
            with self.subTest(reputation=reputation):
                decision = decide_response(self.evidence_pack(reputation, aggregate=True))[0]
                self.assertEqual(decision.action, ResponseAction.NO_ACTION)
                result = DryRunIOCBlocker().block(decision)
                self.assertFalse(result.would_block)
                self.assertFalse(result.executed)
        unsupported = decide_response(
            self.evidence_pack(Reputation.MALICIOUS, IndicatorType.PHONE, aggregate=True)
        )[0]
        self.assertEqual(unsupported.action, ResponseAction.NO_ACTION)
        self.assertIn("not supported", unsupported.reason)

    def test_duplicates_and_unaggregated_provider_disagreement_are_safe(self) -> None:
        duplicated = decide_response(self.evidence_pack(Reputation.MALICIOUS, duplicate=True))
        self.assertEqual(len(duplicated), 1)
        self.assertEqual(duplicated[0].action, ResponseAction.BLOCK)

        evidence = self.evidence_pack(Reputation.MALICIOUS)
        second = evidence.enriched_threat_result.threat_intelligence[0].model_copy(
            update={"source": "provider-b", "reputation": Reputation.BENIGN}
        )
        conflicting = evidence.model_copy(
            update={
                "enriched_threat_result": evidence.enriched_threat_result.model_copy(
                    update={"threat_intelligence": [evidence.enriched_threat_result.threat_intelligence[0], second]}
                )
            }
        )
        decision = decide_response(conflicting)[0]
        self.assertEqual(decision.action, ResponseAction.NO_ACTION)
        self.assertIn("require an aggregated", decision.reason)

    def test_incident_consistency_and_source_immutability(self) -> None:
        evidence = self.evidence_pack(Reputation.MALICIOUS, aggregate=True)
        incident = create_incident(evidence, created_at=self.timestamp(14))
        decision = decide_response(evidence, incident)[0]
        self.assertEqual(decision.incident_id, incident.incident_id)
        self.assertEqual(incident.status.value, "open")
        self.assertEqual(evidence.enriched_threat_result.indicators[0].value, "bad.example")

        mismatched = incident.model_copy(update={"evidence_reference": "other-evidence"})
        with self.assertRaises(ValueError):
            decide_response(evidence, mismatched)


if __name__ == "__main__":
    unittest.main()
