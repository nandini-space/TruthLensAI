"""Tests for the thin, network-isolated Module 2 HTTP boundary."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient

from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.main import app
from backend.models.schemas import (
    DetectionSignal,
    ExtractedEntity,
    InputReference,
    Modality,
    Provenance,
    ScanResult,
    Severity,
)
from backend.module2.orchestrator import run_module2_investigation


class _MaliciousProvider:
    source = "test_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class Module2ApiTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    def setUp(self) -> None:
        self.client = TestClient(app)

    def scan(self) -> ScanResult:
        timestamp = datetime(2026, 9, 22, 12, tzinfo=timezone.utc)
        return ScanResult(
            scan_id=self.scan_id,
            modality=Modality.URL,
            timestamp=timestamp,
            risk_score=90,
            severity=Severity.HIGH,
            confidence=0.9,
            threat_type="credential_phishing",
            signals=[DetectionSignal(name="lookalike", value="bad.example", source="detector")],
            explanation="Existing evidence.",
            extracted_entities=[ExtractedEntity(entity_type="domain", value="bad.example")],
            recommendation="Do not visit.",
            provenance=Provenance(source="upload", detector_id="detector", processed_at=timestamp),
            input_reference=InputReference(reference_uri="storage://input"),
        )

    def response_result(self):
        return run_module2_investigation(
            self.scan(),
            threat_intelligence_providers=[_MaliciousProvider()],
            recorded_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
            generated_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc),
        )

    def test_success_delegates_and_preserves_module2_contract(self) -> None:
        expected = self.response_result()
        with patch("backend.api.module2.run_module2_investigation", return_value=expected) as run:
            response = self.client.post("/api/module2/investigate", json=self.scan().model_dump(mode="json"))

        self.assertEqual(response.status_code, 200)
        run.assert_called_once()
        payload = response.json()
        self.assertEqual(
            set(payload),
            {
                "scan_result", "indicators", "provider_results", "threat_intelligence",
                "enriched_threat_result", "evidence_pack", "incident", "forensic_report",
                "stix_bundle", "response_decisions", "action_records",
            },
        )
        self.assertEqual(payload["scan_result"]["scan_id"], str(self.scan_id))

    def test_invalid_scan_uses_normal_validation_without_calling_orchestrator(self) -> None:
        invalid = self.scan().model_dump(mode="json")
        invalid["risk_score"] = 101
        with patch("backend.api.module2.run_module2_investigation") as run:
            response = self.client.post("/api/module2/investigate", json=invalid)

        self.assertEqual(response.status_code, 422)
        self.assertIn("detail", response.json())
        run.assert_not_called()

    def test_structural_orchestrator_error_is_non_success_and_sanitized(self) -> None:
        with patch(
            "backend.api.module2.run_module2_investigation",
            side_effect=ValueError("internal VIRUSTOTAL_API_KEY=not-for-client"),
        ):
            response = self.client.post("/api/module2/investigate", json=self.scan().model_dump(mode="json"))

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"], "Module 2 investigation could not be completed.")
        self.assertNotIn("VIRUSTOTAL_API_KEY", response.text)

    def test_dry_run_values_are_returned_unchanged_without_external_calls(self) -> None:
        expected = self.response_result()
        with patch("backend.api.module2.run_module2_investigation", return_value=expected) as run:
            response = self.client.post("/api/module2/investigate", json=self.scan().model_dump(mode="json"))

        run.assert_called_once()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["response_decisions"][0]["action"], "block")
        action_record = response.json()["action_records"][0]
        self.assertEqual(action_record["mode"], "dry_run")
        self.assertFalse(action_record["executed"])

    def test_existing_health_endpoint_is_unchanged(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "service": "TruthLensAI"})

    def test_openapi_documents_existing_module2_error_responses(self) -> None:
        paths = self.client.get("/openapi.json").json()["paths"]
        self.assertTrue({"409", "422", "500", "503"}.issubset(
            paths["/api/module2/investigate"]["post"]["responses"]
        ))
        self.assertIn("503", paths["/api/module2/investigations"]["get"]["responses"])
        self.assertTrue({"404", "503"}.issubset(
            paths["/api/module2/investigations/{scan_id}"]["get"]["responses"]
        ))


if __name__ == "__main__":
    unittest.main()
