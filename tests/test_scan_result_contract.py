"""Focused tests for the canonical Module 1 to Module 2 contract."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from pydantic import ValidationError

from backend.models.schemas import (
    DetectionSignal,
    ExtractedEntity,
    InputReference,
    Modality,
    Provenance,
    ScanResult,
    Severity,
)


class ScanResultContractTests(unittest.TestCase):
    def valid_result(self, modality: Modality = Modality.TEXT) -> ScanResult:
        return ScanResult(
            scan_id="b6e1ee03-0062-4ef1-a08e-a17b5e01ffde",
            modality=modality,
            timestamp=datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc),
            risk_score=82.5,
            severity=Severity.HIGH,
            confidence=0.94,
            threat_type="credential_phishing",
            signals=[
                DetectionSignal(
                    name="credential-harvesting-language",
                    value="Password reset required immediately",
                    source="text-classifier",
                    confidence=0.91,
                    metadata={"matched_pattern": "urgent credential request"},
                )
            ],
            explanation="The message combines urgency with a credential request.",
            extracted_entities=[
                ExtractedEntity(
                    entity_type="url",
                    value="https://secure.example.test/reset",
                    normalized_value="https://secure.example.test/reset",
                    confidence=0.99,
                )
            ],
            recommendation="Do not open the link; verify the request independently.",
            provenance=Provenance(
                source="web-upload",
                detector_id="multimodal-detector",
                detector_version="1.0.0",
                processed_at=datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc),
            ),
            input_reference=InputReference(
                original_content="Reset your password using this link.",
                media_type="text/plain",
            ),
        )

    def test_valid_result_can_be_created(self) -> None:
        result = self.valid_result()
        self.assertEqual(result.severity, Severity.HIGH)
        self.assertEqual(result.risk_score, 82.5)

    def test_required_validation_works(self) -> None:
        with self.assertRaises(ValidationError):
            ScanResult()

    def test_invalid_modality_is_rejected(self) -> None:
        payload = self.valid_result().model_dump()
        payload["modality"] = "document"
        with self.assertRaises(ValidationError):
            ScanResult.model_validate(payload)

    def test_invalid_risk_score_is_rejected(self) -> None:
        payload = self.valid_result().model_dump()
        payload["risk_score"] = 101
        with self.assertRaises(ValidationError):
            ScanResult.model_validate(payload)

    def test_invalid_confidence_is_rejected(self) -> None:
        payload = self.valid_result().model_dump()
        payload["confidence"] = 1.01
        with self.assertRaises(ValidationError):
            ScanResult.model_validate(payload)

    def test_severity_does_not_accept_incident_status(self) -> None:
        payload = self.valid_result().model_dump()
        payload["severity"] = "open"
        with self.assertRaises(ValidationError):
            ScanResult.model_validate(payload)

    def test_structured_signals_and_entities_are_represented(self) -> None:
        result = self.valid_result()
        self.assertEqual(result.signals[0].name, "credential-harvesting-language")
        self.assertEqual(result.extracted_entities[0].entity_type, "url")

    def test_all_supported_modalities_are_represented(self) -> None:
        for modality in Modality:
            with self.subTest(modality=modality):
                result = self.valid_result(modality)
                self.assertEqual(result.modality, modality)

    def test_scan_id_is_stable_through_json_serialization(self) -> None:
        result = self.valid_result()
        restored = ScanResult.model_validate_json(result.model_dump_json())
        self.assertIsInstance(restored.scan_id, UUID)
        self.assertEqual(restored.scan_id, result.scan_id)


if __name__ == "__main__":
    unittest.main()
