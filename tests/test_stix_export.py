"""Tests for STIX 2.1 export without external side effects."""

from __future__ import annotations

import json
import re
import unittest
from datetime import datetime, timezone
from uuid import UUID

from stix2 import parse
from stix2.v21 import Bundle

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
from backend.reports.forensic import build_forensic_report
from backend.reports.stix import export_stix_bundle


class StixExportTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    @staticmethod
    def timestamp(hour: int = 12) -> datetime:
        return datetime(2026, 9, 22, hour, 0, tzinfo=timezone.utc)

    def evidence_pack(self):
        scan = ScanResult(
            scan_id=self.scan_id,
            modality=Modality.URL,
            timestamp=self.timestamp(),
            risk_score=88,
            severity=Severity.HIGH,
            confidence=0.93,
            threat_type="credential_phishing",
            signals=[DetectionSignal(name="lookalike", value="acme-login.test", source="url-detector")],
            explanation="The URL imitates a known login domain.",
            extracted_entities=[ExtractedEntity(entity_type="domain", value="acme-login.test")],
            recommendation="Do not visit the URL.",
            provenance=Provenance(source="web-upload", detector_id="detector", processed_at=self.timestamp()),
            input_reference=InputReference(reference_uri="storage://scans/input-1"),
        )
        specifications = [
            (IndicatorType.IP, "198.51.100.10", Reputation.MALICIOUS),
            (IndicatorType.DOMAIN, "acme-login.test", Reputation.SUSPICIOUS),
            (IndicatorType.URL, "https://acme-login.test/sign-in", Reputation.MALICIOUS),
            (IndicatorType.EMAIL, "support@acme-login.test", Reputation.SUSPICIOUS),
            (IndicatorType.HASH, "a" * 64, Reputation.MALICIOUS),
            (IndicatorType.PHONE, "+15551234567", Reputation.MALICIOUS),
            (IndicatorType.OTHER, "unstructured-observable", Reputation.UNAVAILABLE),
        ]
        indicators = [
            Indicator(
                indicator_id=UUID(int=index + 1),
                type=kind,
                value=value,
                source="scan_result",
                confidence=0.8,
            )
            for index, (kind, value, _) in enumerate(specifications)
        ]
        intelligence = [
            ThreatIntelResult(
                indicator=indicator,
                reputation=reputation,
                confidence=0.9,
                source="provider-a",
                queried_at=self.timestamp(13),
                status=(ProviderStatus.UNAVAILABLE if reputation is Reputation.UNAVAILABLE else ProviderStatus.SUCCESS),
            )
            for indicator, (_, _, reputation) in zip(indicators, specifications, strict=True)
        ]
        return build_evidence_pack(scan, indicators, intelligence, collected_at=self.timestamp(13))

    def test_bundle_is_valid_and_maps_supported_indicator_patterns(self) -> None:
        evidence = self.evidence_pack()
        bundle = export_stix_bundle(evidence)

        self.assertIsInstance(bundle, Bundle)
        payload = json.loads(bundle.serialize())
        parsed = parse(bundle.serialize())
        self.assertEqual(parsed.type, "bundle")
        object_ids = [item["id"] for item in payload["objects"]]
        self.assertEqual(len(object_ids), len(set(object_ids)))
        self.assertTrue(all(re.fullmatch(r"[a-z-]+--[0-9a-f-]{36}", object_id) for object_id in object_ids))
        patterns = {item["pattern"] for item in payload["objects"] if item["type"] == "indicator"}
        self.assertEqual(
            patterns,
            {
                "[ipv4-addr:value = '198.51.100.10']",
                "[domain-name:value = 'acme-login.test']",
                "[url:value = 'https://acme-login.test/sign-in']",
                "[email-addr:value = 'support@acme-login.test']",
                f"[file:hashes.'SHA-256' = '{'a' * 64}']",
            },
        )
        self.assertFalse(any("15551234567" in pattern or "unstructured" in pattern for pattern in patterns))

    def test_incident_report_and_relationships_preserve_context(self) -> None:
        evidence = self.evidence_pack()
        incident = create_incident(evidence, created_at=self.timestamp(14))
        report = build_forensic_report(incident, evidence, generated_at=self.timestamp(15))
        bundle = export_stix_bundle(evidence, incident, report)
        objects = json.loads(bundle.serialize())["objects"]

        stix_incident = next(item for item in objects if item["type"] == "incident")
        self.assertIn("truthlensai:status:open", stix_incident["labels"])
        self.assertEqual(stix_incident["external_references"][0]["external_id"], str(incident.incident_id))
        self.assertEqual(len([item for item in objects if item["type"] == "relationship"]), 5)
        self.assertEqual(len([item for item in objects if item["type"] == "report"]), 1)
        self.assertIn("truthlensai:provider:provider-a", next(item for item in objects if item["type"] == "indicator")["labels"])

    def test_invalid_relationship_is_rejected_and_sources_are_unchanged(self) -> None:
        evidence = self.evidence_pack()
        incident = create_incident(evidence, created_at=self.timestamp(14))
        other_evidence = self.evidence_pack().model_copy(
            update={"evidence_id": UUID("4e658c53-9c1c-4b79-9ad3-8a2c4e4192cf")}
        )
        with self.assertRaises(ValueError):
            export_stix_bundle(other_evidence, incident)

        bundle = export_stix_bundle(evidence, incident)
        first_indicator = next(item for item in bundle.objects if item.type == "indicator")
        first_indicator._inner["name"] = "changed"
        self.assertEqual(evidence.enriched_threat_result.indicators[0].value, "198.51.100.10")
        self.assertEqual(incident.status.value, "open")


if __name__ == "__main__":
    unittest.main()
