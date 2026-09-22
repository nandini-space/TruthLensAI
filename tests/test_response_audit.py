"""Tests for in-memory Task 12 response audit records."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import UUID

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
from backend.response.audit import ActionRecordStatus, build_action_record, build_action_records
from backend.response.blocker import DryRunIOCBlocker
from backend.response.decision import decide_response
from backend.response.models import ExecutionMode, ResponseAction


class ResponseAuditTests(unittest.TestCase):
    scan_id = UUID("b6e1ee03-0062-4ef1-a08e-a17b5e01ffde")

    @staticmethod
    def timestamp(hour: int = 12) -> datetime:
        return datetime(2026, 9, 22, hour, 0, tzinfo=timezone.utc)

    def decision(self, reputation: Reputation = Reputation.MALICIOUS):
        scan = ScanResult(
            scan_id=self.scan_id,
            modality=Modality.URL,
            timestamp=self.timestamp(),
            risk_score=90,
            severity=Severity.HIGH,
            confidence=0.9,
            threat_type="credential_phishing",
            signals=[DetectionSignal(name="lookalike", value="bad.example", source="url-detector")],
            explanation="Existing evidence.",
            extracted_entities=[ExtractedEntity(entity_type="domain", value="bad.example")],
            recommendation="Do not visit.",
            provenance=Provenance(source="upload", detector_id="detector", processed_at=self.timestamp()),
            input_reference=InputReference(reference_uri="storage://input"),
        )
        indicator = Indicator(
            indicator_id=UUID("a5816e23-1735-4d55-a7dc-d6749105e660"),
            type=IndicatorType.DOMAIN,
            value="bad.example",
            source="scan_result",
            context={"source": "entity"},
        )
        intelligence = ThreatIntelResult(
            indicator=indicator,
            reputation=reputation,
            source="threat_intelligence_aggregator",
            queried_at=self.timestamp(13),
            status=ProviderStatus.SUCCESS,
        )
        evidence = build_evidence_pack(scan, [indicator], [intelligence], collected_at=self.timestamp(13))
        return evidence, decide_response(evidence)[0]

    def test_block_decision_becomes_non_executed_dry_run_record(self) -> None:
        evidence, decision = self.decision()
        result = DryRunIOCBlocker().block(decision)
        record = build_action_record(
            decision, block_result=result, recorded_at=self.timestamp(14)
        )
        self.assertEqual(record.action, ResponseAction.BLOCK)
        self.assertEqual(record.mode, ExecutionMode.DRY_RUN)
        self.assertTrue(record.would_execute)
        self.assertFalse(record.executed)
        self.assertEqual(record.status, ActionRecordStatus.NOT_EXECUTED)
        self.assertEqual(record.indicator, evidence.enriched_threat_result.indicators[0])

    def test_no_action_timestamp_and_immutability(self) -> None:
        _, decision = self.decision(Reputation.SUSPICIOUS)
        record = build_action_record(decision)
        self.assertEqual(record.action, ResponseAction.NO_ACTION)
        self.assertFalse(record.would_execute)
        self.assertFalse(record.executed)
        self.assertEqual(record.status, ActionRecordStatus.SKIPPED)
        self.assertEqual(record.timestamp.tzinfo, timezone.utc)
        injected = self.timestamp(14).astimezone(timezone(timedelta(hours=5, minutes=30)))
        normalized = build_action_record(decision, recorded_at=injected)
        self.assertEqual(normalized.timestamp, self.timestamp(14))
        record.indicator.context["source"] = "changed"
        self.assertEqual(decision.indicator.context["source"], "entity")

    def test_incident_identity_and_batch_ordering(self) -> None:
        evidence, block = self.decision()
        _, no_action = self.decision(Reputation.BENIGN)
        incident = create_incident(evidence, created_at=self.timestamp(14))
        linked = build_action_record(block, incident=incident, recorded_at=self.timestamp(15))
        self.assertEqual(linked.incident_id, incident.incident_id)
        self.assertEqual(linked.scan_id, incident.scan_id)
        records = build_action_records([block, no_action], incident=incident, recorded_at=self.timestamp(16))
        self.assertEqual([record.action for record in records], [ResponseAction.BLOCK, ResponseAction.NO_ACTION])
        self.assertTrue(all(record.timestamp == self.timestamp(16) for record in records))
        self.assertTrue(all(not record.executed for record in records))

    def test_mismatched_incident_is_rejected(self) -> None:
        evidence, decision = self.decision()
        incident = create_incident(evidence, created_at=self.timestamp(14)).model_copy(
            update={"scan_id": UUID("4e658c53-9c1c-4b79-9ad3-8a2c4e4192cf")}
        )
        with self.assertRaises(ValueError):
            build_action_record(decision, incident=incident)
        self.assertEqual(decision.scan_id, self.scan_id)


if __name__ == "__main__":
    unittest.main()
