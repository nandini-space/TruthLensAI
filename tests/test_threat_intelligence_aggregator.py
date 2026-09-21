"""Offline tests for deterministic provider-neutral intelligence aggregation."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

from backend.intelligence.aggregator import aggregate_threat_intelligence
from backend.intelligence.models import (
    Indicator,
    IndicatorType,
    ProviderStatus,
    Reputation,
    ThreatIntelFinding,
    ThreatIntelResult,
)


class ThreatIntelligenceAggregatorTests(unittest.TestCase):
    def indicator(self, indicator_type: IndicatorType, value: str, suffix: int = 1) -> Indicator:
        return Indicator(
            indicator_id=UUID(f"a5816e23-1735-4d55-a7dc-d6749105e6{suffix:02d}"),
            type=indicator_type,
            value=value,
            source="test",
        )

    @staticmethod
    def now() -> datetime:
        return datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    def result(
        self,
        indicator: Indicator,
        source: str,
        reputation: Reputation,
        status: ProviderStatus = ProviderStatus.SUCCESS,
        finding: str = "provider evidence",
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=reputation,
            source=source,
            queried_at=self.now(),
            status=status,
            findings=[
                ThreatIntelFinding(
                    source=source,
                    category="test_evidence",
                    description=finding,
                )
            ],
        )

    def test_single_and_multiple_provider_results(self) -> None:
        indicator = self.indicator(IndicatorType.DOMAIN, "example.test")
        one = aggregate_threat_intelligence(
            [indicator], [self.result(indicator, "provider-a", Reputation.MALICIOUS)]
        )
        multiple = aggregate_threat_intelligence(
            [indicator],
            [
                self.result(indicator, "provider-a", Reputation.MALICIOUS),
                self.result(
                    indicator,
                    "provider-b",
                    Reputation.UNAVAILABLE,
                    ProviderStatus.UNAVAILABLE,
                ),
            ],
        )
        self.assertEqual(one[0].reputation, Reputation.MALICIOUS)
        self.assertEqual(multiple[0].reputation, Reputation.MALICIOUS)
        self.assertEqual(multiple[0].metadata["provider_result_count"], 2)

    def test_multiple_and_different_type_indicators_remain_separate(self) -> None:
        domain = self.indicator(IndicatorType.DOMAIN, "example.test", 1)
        ip = self.indicator(IndicatorType.IP, "8.8.8.8", 2)
        email_same_value = self.indicator(IndicatorType.EMAIL, "example.test", 3)
        output = aggregate_threat_intelligence(
            [domain, ip, email_same_value],
            [
                self.result(domain, "provider-a", Reputation.BENIGN),
                self.result(ip, "provider-a", Reputation.SUSPICIOUS),
                self.result(email_same_value, "provider-b", Reputation.UNKNOWN),
            ],
        )
        self.assertEqual([(item.indicator.type, item.reputation) for item in output], [
            (IndicatorType.DOMAIN, Reputation.BENIGN),
            (IndicatorType.IP, Reputation.SUSPICIOUS),
            (IndicatorType.EMAIL, Reputation.UNKNOWN),
        ])

    def test_reputation_precedence_and_non_benign_absence(self) -> None:
        indicator = self.indicator(IndicatorType.DOMAIN, "example.test")
        cases = [
            ([Reputation.MALICIOUS, Reputation.BENIGN], Reputation.MALICIOUS),
            ([Reputation.SUSPICIOUS, Reputation.BENIGN], Reputation.SUSPICIOUS),
            ([Reputation.MALICIOUS, Reputation.SUSPICIOUS], Reputation.MALICIOUS),
            ([Reputation.BENIGN], Reputation.BENIGN),
            ([Reputation.UNKNOWN], Reputation.UNKNOWN),
        ]
        for reputations, expected in cases:
            with self.subTest(reputations=reputations):
                results = [
                    self.result(indicator, f"provider-{index}", reputation)
                    for index, reputation in enumerate(reputations)
                ]
                output = aggregate_threat_intelligence([indicator], results)[0]
                self.assertEqual(output.reputation, expected)

        no_results = aggregate_threat_intelligence([indicator], [])[0]
        all_unavailable = aggregate_threat_intelligence(
            [indicator],
            [
                self.result(
                    indicator,
                    "provider-a",
                    Reputation.UNAVAILABLE,
                    ProviderStatus.UNAVAILABLE,
                )
            ],
        )[0]
        self.assertEqual(no_results.reputation, Reputation.UNAVAILABLE)
        self.assertEqual(all_unavailable.reputation, Reputation.UNAVAILABLE)
        self.assertNotEqual(no_results.reputation, Reputation.BENIGN)

    def test_conflicts_preserve_provider_evidence(self) -> None:
        indicator = self.indicator(IndicatorType.DOMAIN, "example.test")
        output = aggregate_threat_intelligence(
            [indicator],
            [
                self.result(indicator, "provider-a", Reputation.MALICIOUS, finding="malicious report"),
                self.result(indicator, "provider-b", Reputation.BENIGN, finding="benign report"),
            ],
        )[0]
        self.assertEqual(output.reputation, Reputation.MALICIOUS)
        self.assertTrue(any(finding.category == "reputation_conflict" for finding in output.findings))
        self.assertEqual(
            {finding.source for finding in output.findings},
            {"provider-a", "provider-b", "threat_intelligence_aggregator"},
        )

    def test_duplicates_and_unmatched_results_are_handled_deterministically(self) -> None:
        indicator = self.indicator(IndicatorType.DOMAIN, "example.test")
        duplicate_indicator = self.indicator(IndicatorType.DOMAIN, "example.test", 4)
        unmatched = self.indicator(IndicatorType.IP, "8.8.8.8", 2)
        duplicate_result = self.result(indicator, "provider-a", Reputation.SUSPICIOUS)
        output = aggregate_threat_intelligence(
            [indicator, duplicate_indicator],
            [
                duplicate_result,
                duplicate_result.model_copy(),
                self.result(unmatched, "provider-b", Reputation.MALICIOUS),
            ],
        )
        self.assertEqual(len(output), 1)
        self.assertEqual(output[0].metadata["provider_result_count"], 1)
        self.assertEqual(len(output[0].findings), 2)

        repeated_finding_result = duplicate_result.model_copy(
            update={"findings": [duplicate_result.findings[0], duplicate_result.findings[0]]}
        )
        deduplicated_findings = aggregate_threat_intelligence(
            [indicator], [repeated_finding_result]
        )[0]
        self.assertEqual(len(deduplicated_findings.findings), 2)

    def test_empty_inputs_and_serialization(self) -> None:
        indicator = self.indicator(IndicatorType.DOMAIN, "example.test")
        unmatched = self.result(indicator, "provider-a", Reputation.MALICIOUS)
        self.assertEqual(aggregate_threat_intelligence([], [unmatched]), [])

        output = aggregate_threat_intelligence(
            [indicator], [self.result(indicator, "provider-a", Reputation.SUSPICIOUS)]
        )
        restored = ThreatIntelResult.model_validate_json(output[0].model_dump_json())
        self.assertEqual(restored.reputation, Reputation.SUSPICIOUS)
        self.assertEqual(restored.indicator, indicator)


if __name__ == "__main__":
    unittest.main()
