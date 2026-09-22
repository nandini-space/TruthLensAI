"""Offline adversarial tests for Module 2 failure and safety boundaries."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.api.module2 import get_module2_repository
from backend.intelligence.models import Indicator, ProviderStatus, Reputation, ThreatIntelResult
from backend.main import app
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from backend.module2.repository import InMemoryModule2Repository
from backend.response.blocker import DryRunIOCBlocker
from backend.response.models import ExecutionMode, ResponseAction
from tests.fixtures.module1_scan_results import malicious_url_scan


class _SuccessProvider:
    source = "hardening_success"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.MALICIOUS,
            source=self.source,
            queried_at=datetime(2026, 9, 22, 13, tzinfo=timezone.utc),
            status=ProviderStatus.SUCCESS,
        )


class _FailingProvider:
    source = "hardening_failure"

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        raise TimeoutError("VIRUSTOTAL_API_KEY=secret-value")


class _MalformedProvider:
    source = "hardening_malformed"

    def lookup(self, indicator: Indicator):
        return object()


class _UnexpectedRepository:
    def save(self, result: Module2Result) -> Module2Result:
        raise RuntimeError("postgresql://user:password@host/private-path")

    def get_by_scan_id(self, scan_id: UUID) -> Module2Result | None:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY=secret-value")

    def list_investigations(self, *, limit: int, offset: int) -> list[Module2Result]:
        raise RuntimeError("select * from private_table")


class _MismatchedRepository:
    def __init__(self, result: Module2Result) -> None:
        self.result = result

    def get_by_scan_id(self, scan_id: UUID) -> Module2Result:
        return self.result


class Module2HardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app, raise_server_exceptions=False)
        self.repository = InMemoryModule2Repository()
        app.dependency_overrides[get_module2_repository] = lambda: self.repository

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    @staticmethod
    def result(*, providers=None) -> Module2Result:
        return run_module2_investigation(
            malicious_url_scan(),
            threat_intelligence_providers=providers or [_SuccessProvider()],
            recorded_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
            generated_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc),
        )

    def test_input_validation_rejects_malformed_and_hostile_payloads(self) -> None:
        valid = malicious_url_scan().model_dump(mode="json")
        invalid_payloads = [
            {},
            {**valid, "scan_id": "not-a-uuid"},
            {**valid, "modality": "binary"},
            {**valid, "severity": "urgent"},
            {**valid, "risk_score": -1},
            {**valid, "risk_score": 101},
            {**valid, "confidence": -0.1},
            {**valid, "confidence": 1.1},
            {**valid, "timestamp": "not-a-time"},
            {**valid, "signals": [{"name": "only-name"}]},
            {**valid, "extracted_entities": [{"entity_type": "domain"}]},
            {**valid, "provenance": {"source": "x"}},
            {**valid, "input_reference": {}},
            {**valid, "risk_score": "not-a-number"},
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                response = self.client.post("/api/module2/investigate", json=payload)
                self.assertEqual(response.status_code, 422)
                self.assertNotIn("Traceback", response.text)
                self.assertNotIn("backend.", response.text)

        malformed_json = self.client.post(
            "/api/module2/investigate",
            content=b'{"scan_id":',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(malformed_json.status_code, 422)
        oversized = {**valid, "input_reference": {"original_content": "x" * 100_001}}
        self.assertEqual(self.client.post("/api/module2/investigate", json=oversized).status_code, 422)

    def test_provider_failures_and_malformed_results_are_isolated_non_benign(self) -> None:
        result = self.result(providers=[_SuccessProvider(), _FailingProvider(), _MalformedProvider()])

        self.assertEqual(result.scan_result.scan_id, malicious_url_scan().scan_id)
        self.assertTrue(any(item.source == "hardening_success" for item in result.provider_results))
        failures = [item for item in result.provider_results if item.source != "hardening_success"]
        self.assertTrue(failures)
        self.assertTrue(all(item.reputation is not Reputation.BENIGN for item in failures))
        self.assertTrue(all(item.reputation is not Reputation.BENIGN for item in result.threat_intelligence))
        template = result.provider_results[0].model_dump()
        template.update({"status": ProviderStatus.ERROR, "reputation": Reputation.BENIGN})
        with self.assertRaises(ValidationError):
            ThreatIntelResult.model_validate(template)

    def test_persistence_and_retrieval_unexpected_failures_are_sanitized(self) -> None:
        result = self.result()
        app.dependency_overrides[get_module2_repository] = _UnexpectedRepository
        def investigate_with_failing_save(scan_result, *, repository):
            return run_module2_investigation(
                scan_result,
                threat_intelligence_providers=[_SuccessProvider()],
                recorded_at=datetime(2026, 9, 22, 14, tzinfo=timezone.utc),
                generated_at=datetime(2026, 9, 22, 15, tzinfo=timezone.utc),
                repository=repository,
            )

        with patch(
            "backend.api.module2.run_module2_investigation",
            side_effect=investigate_with_failing_save,
        ):
            post = self.client.post("/api/module2/investigate", json=malicious_url_scan().model_dump(mode="json"))
        one = self.client.get(f"/api/module2/investigations/{result.scan_result.scan_id}")
        history = self.client.get("/api/module2/investigations")

        self.assertEqual(post.status_code, 500)
        self.assertEqual(one.status_code, 503)
        self.assertEqual(history.status_code, 503)
        for response in (post, one, history):
            self.assertNotIn("secret-value", response.text)
            self.assertNotIn("private_table", response.text)
            self.assertNotIn("Traceback", response.text)

    def test_wrong_scan_identity_from_repository_fails_closed(self) -> None:
        result = self.result()
        wrong_id = UUID("00000000-0000-0000-0000-000000000222")
        app.dependency_overrides[get_module2_repository] = lambda: _MismatchedRepository(result)

        response = self.client.get(f"/api/module2/investigations/{wrong_id}")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "Module 2 persistence is currently unavailable.")

    def test_internally_inconsistent_repository_result_fails_closed(self) -> None:
        result = self.result()
        inconsistent = result.model_copy(
            update={
                "incident": result.incident.model_copy(
                    update={"scan_id": UUID("00000000-0000-0000-0000-000000000223")}
                )
            }
        )
        app.dependency_overrides[get_module2_repository] = lambda: _MismatchedRepository(inconsistent)

        response = self.client.get(f"/api/module2/investigations/{result.scan_result.scan_id}")

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("inconsistent", response.text)

    def test_stix_response_and_snapshot_safety_remain_conservative(self) -> None:
        result = self.result()
        self.repository.save(result)
        stix = result.stix_bundle.serialize()
        self.assertIn("ipv4-addr", stix) if any(
            indicator.type.value == "ip" for indicator in result.indicators
        ) else self.assertIn("bundle", stix)
        self.assertNotIn("VIRUSTOTAL_API_KEY", stix)
        result.scan_result.explanation = "caller mutation"
        retrieved = self.repository.get_by_scan_id(result.scan_result.scan_id)
        retrieved.evidence_pack.scan_result.explanation = "retrieval mutation"
        self.assertNotIn("mutation", self.repository.get_by_scan_id(result.scan_result.scan_id).scan_result.explanation)

    def test_response_actions_remain_dry_run_and_never_executed(self) -> None:
        result = self.result()
        self.assertTrue(result.response_decisions)
        for decision in result.response_decisions:
            block_result = DryRunIOCBlocker().block(decision)
            self.assertEqual(block_result.mode, ExecutionMode.DRY_RUN)
            self.assertFalse(block_result.executed)
            self.assertEqual(block_result.would_block, decision.action is ResponseAction.BLOCK)

    def test_read_only_endpoints_do_not_invoke_investigation_or_save(self) -> None:
        result = self.result()
        self.repository.save(result)
        with (
            patch("backend.api.module2.run_module2_investigation") as investigate,
            patch.object(self.repository, "save", wraps=self.repository.save) as save,
        ):
            one = self.client.get(f"/api/module2/investigations/{result.scan_result.scan_id}")
            history = self.client.get("/api/module2/investigations")

        self.assertEqual(one.status_code, 200)
        self.assertEqual(history.status_code, 200)
        investigate.assert_not_called()
        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
