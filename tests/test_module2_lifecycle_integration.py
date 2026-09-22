"""Offline end-to-end verification for the Module 2 investigation lifecycle."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient

from backend.api.module2 import get_module2_repository
from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.main import app
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from backend.module2.repository import InMemoryModule2Repository, Module2RepositoryError
from tests.fixtures.module1_scan_results import malicious_url_scan


class _OfflineMaliciousProvider:
    source = "lifecycle_offline_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class _OfflineFailingProvider:
    source = "lifecycle_failing_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        raise RuntimeError("offline provider failure")


class _FailingSaveRepository(InMemoryModule2Repository):
    def save(self, result: Module2Result) -> Module2Result:
        raise Module2RepositoryError("raw persistence detail must not escape")


class Module2LifecycleIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.repository = InMemoryModule2Repository()
        app.dependency_overrides[get_module2_repository] = lambda: self.repository
        self.captured_results: list[Module2Result] = []

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    @staticmethod
    def scan(scan_id: UUID) -> object:
        return malicious_url_scan().model_copy(update={"scan_id": scan_id})

    def post_offline(
        self,
        scan,
        *,
        collected_at: datetime,
        provider: object | None = None,
    ):
        provider = provider or _OfflineMaliciousProvider()

        def investigate_offline(scan_result, *, repository):
            result = run_module2_investigation(
                scan_result,
                threat_intelligence_providers=[provider],
                recorded_at=collected_at,
                generated_at=collected_at + timedelta(minutes=1),
                repository=repository,
            )
            self.captured_results.append(result)
            return result

        with patch("backend.api.module2.run_module2_investigation", side_effect=investigate_offline):
            return self.client.post("/api/module2/investigate", json=scan.model_dump(mode="json"))

    def assert_identity_chain(self, result: Module2Result) -> None:
        scan_id = result.scan_result.scan_id
        self.assertEqual(result.enriched_threat_result.scan_id, scan_id)
        self.assertEqual(result.evidence_pack.scan_id, scan_id)
        self.assertEqual(result.evidence_pack.scan_result.scan_id, scan_id)
        self.assertEqual(result.incident.scan_id, scan_id)
        self.assertEqual(result.forensic_report.scan_id, scan_id)
        self.assertEqual(result.forensic_report.incident_id, result.incident.incident_id)
        self.assertEqual(result.forensic_report.evidence_pack.evidence_id, result.evidence_pack.evidence_id)
        self.assertEqual(result.forensic_report.incident.incident_id, result.incident.incident_id)
        for decision in result.response_decisions:
            self.assertEqual(decision.scan_id, scan_id)
            self.assertEqual(decision.evidence_id, result.evidence_pack.evidence_id)
        for record in result.action_records:
            self.assertEqual(record.scan_id, scan_id)
            self.assertEqual(record.incident_id, result.incident.incident_id)

    def test_post_persist_get_one_and_history_preserve_complete_lifecycle(self) -> None:
        first_scan = self.scan(UUID("00000000-0000-0000-0000-000000000101"))
        second_scan = self.scan(UUID("00000000-0000-0000-0000-000000000102"))
        first_time = datetime(2026, 9, 22, 14, tzinfo=timezone.utc)
        second_time = first_time + timedelta(hours=1)

        first_post = self.post_offline(first_scan, collected_at=first_time)
        second_post = self.post_offline(second_scan, collected_at=second_time)

        self.assertEqual(first_post.status_code, 200)
        self.assertEqual(second_post.status_code, 200)
        first_payload = first_post.json()
        self.assertEqual(first_payload["scan_result"], first_scan.model_dump(mode="json"))
        self.assertTrue(first_payload["indicators"])
        self.assertTrue(first_payload["threat_intelligence"])
        self.assertIn("evidence_id", first_payload["evidence_pack"])
        self.assertIn("incident_id", first_payload["incident"])
        self.assertIn("report_id", first_payload["forensic_report"])
        self.assertEqual(first_payload["stix_bundle"]["type"], "bundle")
        self.assertTrue(first_payload["response_decisions"])
        self.assertTrue(first_payload["action_records"])

        first_persisted = self.repository.get_by_scan_id(first_scan.scan_id)
        second_persisted = self.repository.get_by_scan_id(second_scan.scan_id)
        self.assertIsNotNone(first_persisted)
        self.assertIsNotNone(second_persisted)
        self.assert_identity_chain(first_persisted)
        self.assert_identity_chain(second_persisted)
        self.assertEqual(first_persisted.stix_bundle.serialize(), self.captured_results[0].stix_bundle.serialize())
        self.assertEqual(first_persisted.action_records[0].action_id, self.captured_results[0].action_records[0].action_id)
        self.assertEqual(first_persisted.threat_intelligence, self.captured_results[0].threat_intelligence)

        one = self.client.get(f"/api/module2/investigations/{first_scan.scan_id}")
        history = self.client.get("/api/module2/investigations?limit=2")
        self.assertEqual(one.status_code, 200)
        self.assertEqual(history.status_code, 200)
        self.assertEqual(one.json(), first_payload)
        self.assertEqual(history.json()["limit"], 2)
        self.assertEqual(history.json()["offset"], 0)
        self.assertEqual(history.json()["count"], 2)
        self.assertEqual(
            [item["scan_result"]["scan_id"] for item in history.json()["items"]],
            [str(second_scan.scan_id), str(first_scan.scan_id)],
        )
        self.assertEqual(history.json()["items"][1], first_payload)

    def test_snapshots_and_read_only_endpoints_cannot_change_persisted_results(self) -> None:
        scan = self.scan(UUID("00000000-0000-0000-0000-000000000103"))
        response = self.post_offline(scan, collected_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc))
        self.assertEqual(response.status_code, 200)
        original = self.captured_results[0]
        original.scan_result.explanation = "original mutation"
        original.action_records[0].reason = "original mutation"

        with (
            patch("backend.api.module2.run_module2_investigation") as investigate,
            patch.object(self.repository, "save", wraps=self.repository.save) as save,
        ):
            self.assertEqual(self.client.get(f"/api/module2/investigations/{scan.scan_id}").status_code, 200)
            self.assertEqual(self.client.get("/api/module2/investigations").status_code, 200)
        investigate.assert_not_called()
        save.assert_not_called()

        retrieved = self.repository.get_by_scan_id(scan.scan_id)
        listed = self.repository.list_investigations()[0]
        retrieved.scan_result.explanation = "retrieval mutation"
        listed.action_records[0].reason = "history mutation"
        persisted = self.repository.get_by_scan_id(scan.scan_id)
        self.assertNotIn("mutation", persisted.scan_result.explanation)
        self.assertNotIn("mutation", persisted.action_records[0].reason)

    def test_provider_failure_is_isolated_and_never_becomes_benign(self) -> None:
        scan = self.scan(UUID("00000000-0000-0000-0000-000000000104"))
        response = self.post_offline(
            scan,
            collected_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
            provider=_OfflineFailingProvider(),
        )

        self.assertEqual(response.status_code, 200)
        persisted = self.repository.get_by_scan_id(scan.scan_id)
        self.assertTrue(persisted.provider_results)
        self.assertTrue(all(result.reputation != Reputation.BENIGN for result in persisted.provider_results))
        self.assertTrue(all(result.reputation != Reputation.BENIGN for result in persisted.threat_intelligence))

    def test_persistence_failure_and_duplicate_are_sanitized_without_overwrite(self) -> None:
        scan = self.scan(UUID("00000000-0000-0000-0000-000000000105"))
        app.dependency_overrides[get_module2_repository] = _FailingSaveRepository
        failed = self.post_offline(scan, collected_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc))
        self.assertEqual(failed.status_code, 503)
        self.assertNotIn("raw persistence", failed.text)

        app.dependency_overrides[get_module2_repository] = lambda: self.repository
        first = self.post_offline(scan, collected_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc))
        original = self.repository.get_by_scan_id(scan.scan_id)
        duplicate = self.post_offline(scan, collected_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc))
        self.assertEqual(first.status_code, 200)
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(duplicate.json()["detail"], "An investigation already exists for this scan.")
        self.assertEqual(
            self.repository.get_by_scan_id(scan.scan_id).stix_bundle.serialize(),
            original.stix_bundle.serialize(),
        )


if __name__ == "__main__":
    unittest.main()
