"""Offline integration tests for the Module 2 orchestration entry point."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from backend.incidents.evidence import build_evidence_pack
from backend.incidents.manager import create_incident, update_incident_status
from backend.incidents.models import IncidentStatus
from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.models.schemas import (
    DetectionSignal, ExtractedEntity, InputReference, Modality, Provenance, ScanResult, Severity,
)
from backend.module2.orchestrator import run_module2_investigation
from backend.response.models import ExecutionMode, ResponseAction


class _Provider:
    source = "fake_provider"

    def __init__(self, reputation: Reputation = Reputation.MALICIOUS, fail: bool = False) -> None:
        self.reputation, self.fail = reputation, fail

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        if self.fail and indicator.value == "bad.example":
            raise RuntimeError("offline test failure")
        return ThreatIntelResult(
            indicator=indicator,
            reputation=self.reputation,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, 0, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class Module2OrchestratorTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    @staticmethod
    def timestamp(hour: int = 12) -> datetime:
        return datetime(2026, 9, 22, hour, 0, tzinfo=timezone.utc)

    def scan(self, entities=None) -> ScanResult:
        return ScanResult(
            scan_id=self.scan_id, modality=Modality.URL, timestamp=self.timestamp(), risk_score=90,
            severity=Severity.HIGH, confidence=0.9, threat_type="credential_phishing",
            signals=[DetectionSignal(name="lookalike", value="bad.example", source="detector")],
            explanation="Existing evidence.", extracted_entities=entities if entities is not None else [
                ExtractedEntity(entity_type="domain", value="bad.example"),
                ExtractedEntity(entity_type="domain", value="other.example"),
            ], recommendation="Do not visit.",
            provenance=Provenance(source="upload", detector_id="detector", processed_at=self.timestamp()),
            input_reference=InputReference(reference_uri="storage://input"),
        )

    def test_happy_path_produces_all_stages_and_dry_run_records(self) -> None:
        scan = self.scan()
        result = run_module2_investigation(
            scan, threat_intelligence_providers=[_Provider()],
            recorded_at=self.timestamp(14), generated_at=self.timestamp(15),
        )
        self.assertEqual(len(result.indicators), 2)
        self.assertEqual(len(result.threat_intelligence), 2)
        self.assertEqual(result.evidence_pack.enriched_threat_result, result.enriched_threat_result)
        self.assertEqual(result.forensic_report.generated_at, self.timestamp(15))
        self.assertEqual(result.incident.created_at, self.timestamp(14))
        self.assertTrue(all(item.action is ResponseAction.BLOCK for item in result.response_decisions))
        self.assertTrue(all(item.mode is ExecutionMode.DRY_RUN and not item.executed for item in result.action_records))
        self.assertEqual(scan.extracted_entities[0].value, "bad.example")

    def test_no_ioc_and_provider_failure_are_isolated(self) -> None:
        empty = run_module2_investigation(
            self.scan([]), threat_intelligence_providers=[_Provider()], recorded_at=self.timestamp(14)
        )
        self.assertEqual(empty.indicators, [])
        self.assertEqual(empty.threat_intelligence, [])
        self.assertEqual(empty.response_decisions, [])
        self.assertEqual(empty.action_records, [])
        self.assertEqual(empty.evidence_pack.enriched_threat_result.status, ProviderStatus.UNAVAILABLE)

        isolated = run_module2_investigation(
            self.scan(), threat_intelligence_providers=[_Provider(fail=True), _Provider()], recorded_at=self.timestamp(14)
        )
        self.assertEqual(len(isolated.provider_results), 4)
        self.assertTrue(any(item.status is ProviderStatus.ERROR for item in isolated.provider_results))
        self.assertTrue(all(item.reputation is Reputation.MALICIOUS for item in isolated.threat_intelligence))

    def test_existing_incident_is_reused_and_mismatch_is_rejected(self) -> None:
        scan = self.scan()
        indicator = Indicator.model_validate({
            "indicator_id": "a5816e23-1735-4d55-a7dc-d6749105e660", "type": "domain",
            "value": "bad.example", "source": "scan_result",
        })
        evidence = build_evidence_pack(scan, [indicator], [], collected_at=self.timestamp(14))
        incident = update_incident_status(
            create_incident(evidence, created_at=self.timestamp(14)), IncidentStatus.INVESTIGATING,
            updated_at=self.timestamp(15),
        )
        result = run_module2_investigation(scan, threat_intelligence_providers=[_Provider()], incident=incident)
        self.assertEqual(result.incident.incident_id, incident.incident_id)
        self.assertEqual(result.incident.status, IncidentStatus.INVESTIGATING)
        mismatched = incident.model_copy(update={"scan_id": UUID("4e658c53-9c1c-4b79-9ad3-8a2c4e4192cf")})
        with self.assertRaises(ValueError):
            run_module2_investigation(scan, threat_intelligence_providers=[_Provider()], incident=mismatched)


if __name__ == "__main__":
    unittest.main()
