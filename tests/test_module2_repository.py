"""Deterministic tests for the provider-neutral Module 2 repository boundary."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from backend.module2.repository import DuplicateInvestigationError, InMemoryModule2Repository
from tests.fixtures.module1_scan_results import malicious_url_scan


class _OfflineProvider:
    source = "repository_test_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class Module2RepositoryTests(unittest.TestCase):
    @staticmethod
    def result(
        scan_id: UUID | None = None,
        collected_at: datetime | None = None,
    ) -> Module2Result:
        scan = malicious_url_scan()
        if scan_id is not None:
            scan = scan.model_copy(update={"scan_id": scan_id})
        return run_module2_investigation(
            scan,
            threat_intelligence_providers=[_OfflineProvider()],
            recorded_at=collected_at or datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
            generated_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc),
        )

    def test_save_and_retrieve_preserve_existing_nested_identities(self) -> None:
        result = self.result()
        repository = InMemoryModule2Repository()
        saved = repository.save(result)
        retrieved = repository.get_by_scan_id(result.scan_result.scan_id)

        self.assertIsNot(saved, result)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.scan_result.scan_id, result.scan_result.scan_id)
        self.assertEqual(retrieved.evidence_pack.evidence_id, result.evidence_pack.evidence_id)
        self.assertEqual(retrieved.incident.incident_id, result.incident.incident_id)
        self.assertEqual(retrieved.forensic_report.report_id, result.forensic_report.report_id)
        self.assertEqual(retrieved.action_records[0].action_id, result.action_records[0].action_id)
        self.assertEqual(
            repository.get_by_incident_id(result.incident.incident_id).scan_result.scan_id,
            result.scan_result.scan_id,
        )

    def test_missing_and_duplicate_saves_have_deterministic_behavior(self) -> None:
        repository = InMemoryModule2Repository()
        self.assertIsNone(repository.get_by_scan_id(UUID("00000000-0000-0000-0000-000000000001")))
        result = self.result()
        repository.save(result)
        with self.assertRaises(DuplicateInvestigationError):
            repository.save(result)

    def test_save_and_retrieval_snapshots_do_not_share_mutable_state(self) -> None:
        result = self.result()
        repository = InMemoryModule2Repository()
        repository.save(result)
        result.scan_result.explanation = "caller mutation"
        result.action_records[0].reason = "caller mutation"
        first = repository.get_by_scan_id(malicious_url_scan().scan_id)
        first.scan_result.explanation = "retrieved mutation"
        first.action_records[0].reason = "retrieved mutation"
        second = repository.get_by_scan_id(malicious_url_scan().scan_id)

        self.assertNotEqual(second.scan_result.explanation, "caller mutation")
        self.assertNotEqual(second.scan_result.explanation, "retrieved mutation")
        self.assertNotEqual(second.action_records[0].reason, "caller mutation")
        self.assertNotEqual(second.action_records[0].reason, "retrieved mutation")

    def test_inconsistent_identity_and_invalid_lookup_identity_are_rejected(self) -> None:
        result = self.result()
        inconsistent = result.model_copy(
            update={"incident": result.incident.model_copy(update={"scan_id": UUID("00000000-0000-0000-0000-000000000002")})}
        )
        repository = InMemoryModule2Repository()
        with self.assertRaises(ValueError):
            repository.save(inconsistent)
        with self.assertRaises(TypeError):
            repository.get_by_scan_id(str(result.scan_result.scan_id))

    def test_list_is_bounded_ordered_and_returns_independent_snapshots(self) -> None:
        repository = InMemoryModule2Repository()
        older = self.result(
            UUID("00000000-0000-0000-0000-000000000001"),
            datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
        )
        tied_lower = self.result(
            UUID("00000000-0000-0000-0000-000000000002"),
            datetime(2026, 9, 22, 16, tzinfo=timezone.utc),
        )
        tied_higher = self.result(
            UUID("00000000-0000-0000-0000-000000000003"),
            datetime(2026, 9, 22, 16, tzinfo=timezone.utc),
        )
        for result in (older, tied_lower, tied_higher):
            repository.save(result)

        self.assertEqual(repository.list_investigations(), [tied_higher, tied_lower, older])
        self.assertEqual(repository.list_investigations(limit=1), [tied_higher])
        self.assertEqual(repository.list_investigations(offset=1), [tied_lower, older])
        self.assertEqual(repository.list_investigations(limit=1, offset=1), [tied_lower])
        first = repository.list_investigations(limit=1)[0]
        first.scan_result.explanation = "mutated result"
        self.assertNotEqual(
            repository.list_investigations(limit=1)[0].scan_result.explanation,
            "mutated result",
        )

    def test_list_empty_and_invalid_pagination_are_rejected(self) -> None:
        repository = InMemoryModule2Repository()
        self.assertEqual(repository.list_investigations(), [])
        for kwargs in ({"limit": 0}, {"limit": 101}, {"offset": -1}):
            with self.assertRaises(ValueError):
                repository.list_investigations(**kwargs)


if __name__ == "__main__":
    unittest.main()
