"""Network-free contract tests for the canonical Module 1 to Module 2 handoff."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.main import app
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from tests.fixtures.module1_scan_results import MODULE1_SCAN_FIXTURES, malicious_ip_scan, malicious_url_scan, no_extractable_ioc_scan


class _OfflineMaliciousProvider:
    """Deterministic provider stub; it never performs an external request."""

    source = "integration_fixture_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class Module1Module2IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def invoke(self, scan) -> tuple[Module2Result, dict[str, object]]:
        expected = run_module2_investigation(
            scan,
            threat_intelligence_providers=[_OfflineMaliciousProvider()],
            recorded_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
            generated_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc),
        )
        with patch("backend.api.module2.run_module2_investigation", return_value=expected) as run:
            response = self.client.post("/api/module2/investigate", json=scan.model_dump(mode="json"))
        self.assertEqual(response.status_code, 200)
        run.assert_called_once()
        return expected, response.json()

    def assert_detection_contract_is_preserved(self, scan, payload: dict[str, object]) -> None:
        expected = scan.model_dump(mode="json")
        self.assertEqual(payload["scan_result"], expected)
        self.assertEqual(payload["evidence_pack"]["scan_result"], expected)

    def assert_scan_identity_propagates(self, scan, payload: dict[str, object]) -> None:
        scan_id = str(scan.scan_id)
        self.assertEqual(payload["scan_result"]["scan_id"], scan_id)
        self.assertEqual(payload["enriched_threat_result"]["scan_id"], scan_id)
        self.assertEqual(payload["evidence_pack"]["scan_id"], scan_id)
        self.assertEqual(payload["incident"]["scan_id"], scan_id)
        self.assertEqual(payload["forensic_report"]["scan_id"], scan_id)
        self.assertEqual(payload["forensic_report"]["evidence_pack"]["scan_id"], scan_id)
        self.assertEqual(payload["forensic_report"]["incident"]["scan_id"], scan_id)
        for decision in payload["response_decisions"]:
            self.assertEqual(decision["scan_id"], scan_id)
        for record in payload["action_records"]:
            self.assertEqual(record["scan_id"], scan_id)

    def test_all_canonical_fixtures_cross_the_api_without_contract_drift(self) -> None:
        for name, factory in MODULE1_SCAN_FIXTURES.items():
            with self.subTest(fixture=name):
                scan = factory()
                _, payload = self.invoke(scan)
                self.assert_detection_contract_is_preserved(scan, payload)
                self.assert_scan_identity_propagates(scan, payload)

    def test_malicious_url_reaches_existing_ioc_and_intelligence_pipeline(self) -> None:
        expected, payload = self.invoke(malicious_url_scan())
        self.assertEqual([(item.type.value, item.value) for item in expected.indicators], [("url", "https://secure-login.example.test/account?next=home")])
        self.assertEqual([(item["type"], item["value"]) for item in payload["indicators"]], [("url", "https://secure-login.example.test/account?next=home")])
        self.assertEqual(payload["provider_results"][0]["indicator"]["value"], payload["indicators"][0]["value"])
        self.assertEqual(payload["threat_intelligence"][0]["indicator"]["type"], "url")
        self.assertIn("enriched_threat_result", payload)
        self.assertIn("evidence_pack", payload)

    def test_malicious_ip_reaches_aggregation_with_one_scan_identity(self) -> None:
        scan = malicious_ip_scan()
        expected, payload = self.invoke(scan)
        self.assertEqual([(item.type.value, item.value) for item in expected.indicators], [("ip", "198.51.100.42")])
        self.assertEqual(payload["threat_intelligence"][0]["indicator"]["value"], "198.51.100.42")
        self.assert_scan_identity_propagates(scan, payload)
        self.assertEqual(payload["evidence_pack"]["evidence_id"], payload["incident"]["evidence_reference"])

    def test_no_extractable_ioc_still_produces_evidence_without_actions(self) -> None:
        _, payload = self.invoke(no_extractable_ioc_scan())
        self.assertEqual(payload["indicators"], [])
        self.assertEqual(payload["provider_results"], [])
        self.assertEqual(payload["threat_intelligence"], [])
        self.assertEqual(payload["response_decisions"], [])
        self.assertEqual(payload["action_records"], [])
        self.assertIn("evidence_pack", payload)


if __name__ == "__main__":
    unittest.main()
