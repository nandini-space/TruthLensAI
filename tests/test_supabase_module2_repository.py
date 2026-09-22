"""Fake-client tests for Supabase-backed Module 2 persistence."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest
from uuid import UUID

from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from backend.module2.repository import (
    DuplicateInvestigationError,
    Module2RepositoryError,
    SupabaseModule2Repository,
)
from tests.fixtures.module1_scan_results import malicious_url_scan


class _Response:
    def __init__(self, data) -> None:
        self.data = data


class _ClientError(Exception):
    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class _Query:
    def __init__(self, client) -> None:
        self.client = client
        self.operation = "select"
        self.record = None
        self.column = None
        self.value = None
        self.orderings = []
        self.page = None

    def insert(self, record):
        self.operation, self.record = "insert", deepcopy(record)
        return self

    def select(self, _columns):
        return self

    def eq(self, column, value):
        self.column, self.value = column, value
        return self

    def limit(self, _count):
        return self

    def order(self, column, desc=False):
        self.orderings.append((column, desc))
        return self

    def range(self, start, end):
        self.page = (start, end)
        return self

    def execute(self):
        if self.client.fail:
            raise _ClientError("service unavailable")
        if self.operation == "insert":
            if any(row["scan_id"] == self.record["scan_id"] for row in self.client.rows):
                raise _ClientError("duplicate key value violates unique constraint", "23505")
            self.client.rows.append(deepcopy(self.record))
            return _Response([deepcopy(self.record)])
        rows = [
            deepcopy(row) for row in self.client.rows
            if self.column is None or row.get(self.column) == self.value
        ]
        for column, desc in reversed(self.orderings):
            rows.sort(key=lambda row: row[column], reverse=desc)
        if self.page is not None:
            start, end = self.page
            rows = rows[start : end + 1]
        elif self.column is not None:
            rows = rows[:1]
        return _Response([{"payload": row["payload"]} for row in rows])


class _FakeSupabaseClient:
    def __init__(self) -> None:
        self.rows = []
        self.fail = False

    def table(self, table_name):
        if table_name != "module2_investigations":
            raise AssertionError("unexpected table")
        return _Query(self)


class _OfflineProvider:
    source = "supabase_repository_test_provider"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class SupabaseModule2RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = _FakeSupabaseClient()
        self.repository = SupabaseModule2Repository(self.client)

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

    def test_save_and_retrieve_round_trip_preserves_complete_result(self) -> None:
        result = self.result()
        self.repository.save(result)
        retrieved = self.repository.get_by_scan_id(result.scan_result.scan_id)

        self.assertEqual(retrieved.scan_result.scan_id, result.scan_result.scan_id)
        self.assertEqual(retrieved.scan_result.timestamp, result.scan_result.timestamp)
        self.assertEqual(retrieved.incident.incident_id, result.incident.incident_id)
        self.assertEqual(retrieved.evidence_pack.evidence_id, result.evidence_pack.evidence_id)
        self.assertEqual(retrieved.forensic_report.report_id, result.forensic_report.report_id)
        self.assertEqual(retrieved.action_records[0].action_id, result.action_records[0].action_id)
        self.assertEqual(retrieved.stix_bundle.serialize(), result.stix_bundle.serialize())
        self.assertEqual(
            self.repository.get_by_incident_id(result.incident.incident_id).scan_result.scan_id,
            result.scan_result.scan_id,
        )

    def test_missing_duplicate_and_client_failures_are_repository_level_outcomes(self) -> None:
        result = self.result()
        self.assertIsNone(self.repository.get_by_scan_id(result.scan_result.scan_id))
        self.repository.save(result)
        with self.assertRaises(DuplicateInvestigationError):
            self.repository.save(result)
        self.client.fail = True
        with self.assertRaises(Module2RepositoryError) as error:
            self.repository.get_by_scan_id(result.scan_result.scan_id)
        self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", str(error.exception))

    def test_saved_payload_and_retrieved_results_are_independent_snapshots(self) -> None:
        result = self.result()
        self.repository.save(result)
        result.scan_result.explanation = "caller mutation"
        result.action_records[0].reason = "caller mutation"
        first = self.repository.get_by_scan_id(malicious_url_scan().scan_id)
        first.scan_result.explanation = "retrieved mutation"
        first.action_records[0].reason = "retrieved mutation"
        second = self.repository.get_by_scan_id(malicious_url_scan().scan_id)

        self.assertNotIn("mutation", second.scan_result.explanation)
        self.assertNotIn("mutation", second.action_records[0].reason)

    def test_inconsistent_result_is_rejected_before_any_client_call(self) -> None:
        result = self.result()
        inconsistent = result.model_copy(
            update={
                "incident": result.incident.model_copy(
                    update={"scan_id": UUID("00000000-0000-0000-0000-000000000002")}
                )
            }
        )
        with self.assertRaises(ValueError):
            self.repository.save(inconsistent)
        self.assertEqual(self.client.rows, [])

    def test_list_uses_database_ordering_and_range(self) -> None:
        older = self.result(
            UUID("00000000-0000-0000-0000-000000000001"),
            datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
        )
        newer = self.result(
            UUID("00000000-0000-0000-0000-000000000002"),
            datetime(2026, 9, 22, 16, tzinfo=timezone.utc),
        )
        self.repository.save(older)
        self.repository.save(newer)

        listed = self.repository.list_investigations(limit=1, offset=1)

        self.assertEqual([result.scan_result.scan_id for result in listed], [older.scan_result.scan_id])
        self.assertEqual(self.client.rows[0]["collected_at"], older.evidence_pack.collected_at.isoformat())
        self.client.fail = True
        with self.assertRaises(Module2RepositoryError):
            self.repository.list_investigations()


if __name__ == "__main__":
    unittest.main()
