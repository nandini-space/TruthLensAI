"""Focused read-only pagination tests for Module 2 investigation history."""

from __future__ import annotations

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


class _OfflineProvider:
    source = "listing_api_test_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class _FailingRepository:
    def list_investigations(self, *, limit: int, offset: int) -> list[Module2Result]:
        raise Module2RepositoryError("raw database detail must not escape")


class Module2ListingApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.repository = InMemoryModule2Repository()
        app.dependency_overrides[get_module2_repository] = lambda: self.repository

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def add_results(self, count: int) -> list[Module2Result]:
        base_time = datetime(2026, 9, 22, 14, tzinfo=timezone.utc)
        results = []
        for index in range(count):
            scan = malicious_url_scan().model_copy(
                update={"scan_id": UUID(int=index + 1)}
            )
            result = run_module2_investigation(
                scan,
                threat_intelligence_providers=[_OfflineProvider()],
                recorded_at=base_time + timedelta(minutes=index),
                generated_at=base_time + timedelta(minutes=index),
            )
            self.repository.save(result)
            results.append(result)
        return results

    def test_empty_history_uses_default_page_envelope(self) -> None:
        response = self.client.get("/api/module2/investigations")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"items": [], "limit": 20, "offset": 0, "count": 0})

    def test_default_limit_custom_limit_offset_and_combined_pagination(self) -> None:
        results = self.add_results(25)
        expected_ids = [str(result.scan_result.scan_id) for result in reversed(results)]

        default_page = self.client.get("/api/module2/investigations")
        custom_page = self.client.get("/api/module2/investigations?limit=2")
        offset_page = self.client.get("/api/module2/investigations?offset=2")
        combined_page = self.client.get("/api/module2/investigations?limit=2&offset=2")

        self.assertEqual(default_page.status_code, 200)
        self.assertEqual(default_page.json()["limit"], 20)
        self.assertEqual(default_page.json()["count"], 20)
        self.assertEqual(
            [item["scan_result"]["scan_id"] for item in default_page.json()["items"]],
            expected_ids[:20],
        )
        self.assertEqual(
            [item["scan_result"]["scan_id"] for item in custom_page.json()["items"]],
            expected_ids[:2],
        )
        self.assertEqual(offset_page.json()["count"], 20)
        self.assertEqual(
            [item["scan_result"]["scan_id"] for item in offset_page.json()["items"]],
            expected_ids[2:22],
        )
        self.assertEqual(
            [item["scan_result"]["scan_id"] for item in combined_page.json()["items"]],
            expected_ids[2:4],
        )

    def test_nested_identities_and_read_only_boundary_are_preserved(self) -> None:
        result = self.add_results(1)[0]
        with (
            patch("backend.api.module2.run_module2_investigation") as investigate,
            patch.object(self.repository, "save", wraps=self.repository.save) as save,
        ):
            response = self.client.get("/api/module2/investigations")

        self.assertEqual(response.status_code, 200)
        investigate.assert_not_called()
        save.assert_not_called()
        item = response.json()["items"][0]
        self.assertEqual(item["scan_result"]["scan_id"], str(result.scan_result.scan_id))
        self.assertEqual(item["evidence_pack"]["evidence_id"], str(result.evidence_pack.evidence_id))
        self.assertEqual(item["incident"]["incident_id"], str(result.incident.incident_id))
        self.assertEqual(item["forensic_report"]["report_id"], str(result.forensic_report.report_id))

    def test_invalid_pagination_is_rejected_before_repository_lookup(self) -> None:
        with patch.object(self.repository, "list_investigations", wraps=self.repository.list_investigations) as listed:
            responses = [
                self.client.get("/api/module2/investigations?limit=0"),
                self.client.get("/api/module2/investigations?limit=101"),
                self.client.get("/api/module2/investigations?offset=-1"),
            ]

        self.assertTrue(all(response.status_code == 422 for response in responses))
        listed.assert_not_called()

    def test_repository_failure_is_sanitized(self) -> None:
        app.dependency_overrides[get_module2_repository] = _FailingRepository
        response = self.client.get("/api/module2/investigations")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "Module 2 persistence is currently unavailable.")
        self.assertNotIn("database", response.text)


if __name__ == "__main__":
    unittest.main()
