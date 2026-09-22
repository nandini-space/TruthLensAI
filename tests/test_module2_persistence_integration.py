"""Focused tests for optional repository persistence in the Module 2 flow."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api.module2 import get_module2_repository
from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.main import app
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from backend.module2.repository import (
    DuplicateInvestigationError,
    InMemoryModule2Repository,
    Module2RepositoryError,
)
from tests.fixtures.module1_scan_results import malicious_url_scan


class _OfflineProvider:
    source = "persistence_integration_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class _FailingRepository:
    def __init__(self) -> None:
        self.received: Module2Result | None = None

    def save(self, result: Module2Result) -> Module2Result:
        self.received = result
        raise Module2RepositoryError("database details must not escape")


class Module2PersistenceIntegrationTests(unittest.TestCase):
    @staticmethod
    def investigate(*, repository=None) -> Module2Result:
        return run_module2_investigation(
            malicious_url_scan(),
            threat_intelligence_providers=[_OfflineProvider()],
            recorded_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
            generated_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc),
            repository=repository,
        )

    def setUp(self) -> None:
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_completed_result_is_saved_once_after_all_artifacts_exist(self) -> None:
        repository = InMemoryModule2Repository()
        result = self.investigate(repository=repository)
        persisted = repository.get_by_scan_id(result.scan_result.scan_id)

        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.model_dump(exclude={"stix_bundle"}), result.model_dump(exclude={"stix_bundle"}))
        self.assertEqual(persisted.stix_bundle.serialize(), result.stix_bundle.serialize())
        self.assertEqual(len(persisted.action_records), len(result.response_decisions))

    def test_repository_failure_is_propagated_after_receiving_final_result(self) -> None:
        repository = _FailingRepository()
        with self.assertRaises(Module2RepositoryError):
            self.investigate(repository=repository)

        self.assertIsNotNone(repository.received)
        self.assertIsNotNone(repository.received.forensic_report)
        self.assertIsNotNone(repository.received.stix_bundle)
        self.assertEqual(len(repository.received.action_records), 1)

    def test_api_forwards_injected_repository_to_orchestrator(self) -> None:
        repository = InMemoryModule2Repository()
        expected = self.investigate()
        app.dependency_overrides[get_module2_repository] = lambda: repository
        with patch("backend.api.module2.run_module2_investigation", return_value=expected) as run:
            response = self.client.post(
                "/api/module2/investigate", json=malicious_url_scan().model_dump(mode="json")
            )

        self.assertEqual(response.status_code, 200)
        self.assertIs(run.call_args.kwargs["repository"], repository)

    def test_api_returns_sanitized_conflict_for_duplicate_investigation(self) -> None:
        app.dependency_overrides[get_module2_repository] = InMemoryModule2Repository
        with patch(
            "backend.api.module2.run_module2_investigation",
            side_effect=DuplicateInvestigationError("raw database duplicate key"),
        ):
            response = self.client.post(
                "/api/module2/investigate", json=malicious_url_scan().model_dump(mode="json")
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"], "An investigation already exists for this scan.")
        self.assertNotIn("database", response.text)


if __name__ == "__main__":
    unittest.main()
