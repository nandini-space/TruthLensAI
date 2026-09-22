"""Focused read-only API tests for persisted Module 2 investigations."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient

from backend.api.module2 import get_module2_repository
from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.main import app
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from backend.module2.repository import InMemoryModule2Repository, Module2RepositoryError
from tests.fixtures.module1_scan_results import malicious_url_scan


class _OfflineProvider:
    source = "retrieval_api_test_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class _FailingRepository:
    def get_by_scan_id(self, scan_id: UUID) -> Module2Result | None:
        raise Module2RepositoryError("raw database credentials must not escape")


class Module2RetrievalApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.repository = InMemoryModule2Repository()
        self.result = run_module2_investigation(
            malicious_url_scan(),
            threat_intelligence_providers=[_OfflineProvider()],
            recorded_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
            generated_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc),
        )
        self.repository.save(self.result)
        app.dependency_overrides[get_module2_repository] = lambda: self.repository

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_retrieves_complete_persisted_result_without_pipeline_or_writes(self) -> None:
        scan_id = self.result.scan_result.scan_id
        with (
            patch("backend.api.module2.run_module2_investigation") as investigate,
            patch.object(self.repository, "save", wraps=self.repository.save) as save,
        ):
            response = self.client.get(f"/api/module2/investigations/{scan_id}")

        self.assertEqual(response.status_code, 200)
        investigate.assert_not_called()
        save.assert_not_called()
        payload = response.json()
        self.assertEqual(payload["scan_result"]["scan_id"], str(scan_id))
        self.assertEqual(payload["evidence_pack"]["evidence_id"], str(self.result.evidence_pack.evidence_id))
        self.assertEqual(payload["incident"]["incident_id"], str(self.result.incident.incident_id))
        self.assertEqual(payload["forensic_report"]["report_id"], str(self.result.forensic_report.report_id))
        self.assertEqual(payload["action_records"][0]["action_id"], str(self.result.action_records[0].action_id))
        self.assertEqual(payload["stix_bundle"]["type"], "bundle")

    def test_missing_investigation_returns_sanitized_not_found(self) -> None:
        response = self.client.get("/api/module2/investigations/00000000-0000-0000-0000-000000000001")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Module 2 investigation was not found.")

    def test_invalid_scan_id_uses_fastapi_validation_without_repository_lookup(self) -> None:
        with patch.object(self.repository, "get_by_scan_id", wraps=self.repository.get_by_scan_id) as retrieve:
            response = self.client.get("/api/module2/investigations/not-a-uuid")

        self.assertEqual(response.status_code, 422)
        retrieve.assert_not_called()

    def test_repository_failure_returns_sanitized_service_unavailable(self) -> None:
        app.dependency_overrides[get_module2_repository] = _FailingRepository
        response = self.client.get(f"/api/module2/investigations/{self.result.scan_result.scan_id}")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "Module 2 persistence is currently unavailable.")
        self.assertNotIn("credentials", response.text)


if __name__ == "__main__":
    unittest.main()
