"""Tests for conservative IOC extraction from the canonical ScanResult contract."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from backend.intelligence.ioc_extractor import extract_indicators
from backend.intelligence.models import IndicatorType
from backend.models.schemas import (
    ExtractedEntity,
    InputReference,
    Modality,
    Provenance,
    ScanResult,
    Severity,
)


class IOCExtractorTests(unittest.TestCase):
    def scan_with(self, *entities: ExtractedEntity) -> ScanResult:
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        return ScanResult(
            scan_id=UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde"),
            modality=Modality.TEXT,
            timestamp=now,
            risk_score=50,
            severity=Severity.MEDIUM,
            confidence=0.8,
            threat_type="suspicious_content",
            signals=[],
            explanation="Test scan.",
            extracted_entities=list(entities),
            recommendation="Review the entities.",
            provenance=Provenance(
                source="test",
                detector_id="test-detector",
                processed_at=now,
            ),
            input_reference=InputReference(original_content="Test input."),
        )

    @staticmethod
    def entity(entity_type: str, value: str) -> ExtractedEntity:
        return ExtractedEntity(entity_type=entity_type, value=value, confidence=0.9)

    def test_supported_types_are_extracted_and_normalized(self) -> None:
        sha512 = "A" * 128
        indicators = extract_indicators(
            self.scan_with(
                self.entity("ip", "8.8.8.8"),
                self.entity("domain", "Example.COM"),
                self.entity("url", "https://Example.COM:8080/path?q=Test."),
                self.entity("email", "USER@Example.COM"),
                self.entity("hash", "A" * 32),
                self.entity("hash", "B" * 40),
                self.entity("hash", "C" * 64),
                self.entity("hash", sha512),
                self.entity("phone", "+91 9876543210"),
            )
        )
        self.assertEqual(
            [indicator.type for indicator in indicators],
            [
                IndicatorType.IP,
                IndicatorType.DOMAIN,
                IndicatorType.URL,
                IndicatorType.EMAIL,
                IndicatorType.HASH,
                IndicatorType.HASH,
                IndicatorType.HASH,
                IndicatorType.HASH,
                IndicatorType.PHONE,
            ],
        )
        self.assertEqual(indicators[1].value, "example.com")
        self.assertEqual(indicators[2].value, "https://example.com:8080/path?q=Test")
        self.assertEqual(indicators[3].value, "user@example.com")
        self.assertEqual(indicators[4].value, "a" * 32)
        self.assertEqual(indicators[8].value, "+919876543210")
        self.assertTrue(all(indicator.source == "scan_result" for indicator in indicators))

    def test_normalized_values_are_deduplicated_with_stable_ids(self) -> None:
        first = extract_indicators(
            self.scan_with(
                self.entity("domain", "Example.COM"),
                self.entity("domain", "example.com"),
                self.entity("email", "USER@Example.COM"),
                self.entity("email", "user@example.com"),
            )
        )
        second = extract_indicators(self.scan_with(self.entity("domain", "EXAMPLE.COM")))
        self.assertEqual([(item.type, item.value) for item in first], [
            (IndicatorType.DOMAIN, "example.com"),
            (IndicatorType.EMAIL, "user@example.com"),
        ])
        self.assertEqual(first[0].indicator_id, second[0].indicator_id)

    def test_non_indicators_and_malformed_values_are_skipped(self) -> None:
        indicators = extract_indicators(
            self.scan_with(
                self.entity("person", "John Smith"),
                self.entity("text", "Hello world"),
                self.entity("number", "2026"),
                self.entity("phone", "12345"),
                self.entity("domain", "not.a_domain"),
                self.entity("url", "https://"),
                self.entity("email", "user@@example.com"),
                self.entity("hash", "A" * 33),
                self.entity("ip", "999.1.1.1"),
            )
        )
        self.assertEqual(indicators, [])

    def test_specific_url_and_email_classification_take_precedence(self) -> None:
        indicators = extract_indicators(
            self.scan_with(
                self.entity("entity", "https://Example.COM/login."),
                self.entity("entity", "USER@Example.COM"),
            )
        )
        self.assertEqual([indicator.type for indicator in indicators], [IndicatorType.URL, IndicatorType.EMAIL])
        self.assertEqual(indicators[0].value, "https://example.com/login")
        self.assertEqual(indicators[1].value, "user@example.com")

    def test_indicator_context_preserves_entity_information(self) -> None:
        entity = ExtractedEntity(
            entity_type="domain",
            value="Example.COM",
            normalized_value="example.com",
            confidence=0.7,
            metadata={"position": 12},
        )
        indicator = extract_indicators(self.scan_with(entity))[0]
        self.assertEqual(indicator.confidence, 0.7)
        self.assertEqual(indicator.context["entity_type"], "domain")
        self.assertEqual(indicator.context["entity_metadata"], {"position": 12})


if __name__ == "__main__":
    unittest.main()
