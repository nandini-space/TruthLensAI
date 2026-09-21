"""Offline tests for the unconfigured community-intelligence provider boundary."""

from __future__ import annotations

import unittest
from uuid import UUID

from backend.intelligence.community import CommunityIntelProvider
from backend.intelligence.models import (
    Indicator,
    IndicatorType,
    ProviderStatus,
    Reputation,
    ThreatIntelResult,
)


class CommunityIntelProviderTests(unittest.TestCase):
    def indicator(self, indicator_type: IndicatorType) -> Indicator:
        return Indicator(
            indicator_id=UUID("a5816e23-1735-4d55-a7dc-d6749105e660"),
            type=indicator_type,
            value="example.test",
            source="test",
        )

    def test_provider_constructs_and_returns_unavailable_result(self) -> None:
        result = CommunityIntelProvider().lookup(self.indicator(IndicatorType.DOMAIN))
        self.assertEqual(result.source, "community_intelligence")
        self.assertEqual(result.status, ProviderStatus.UNAVAILABLE)
        self.assertEqual(result.reputation, Reputation.UNAVAILABLE)
        self.assertEqual(result.findings[0].category, "source_not_configured")

    def test_all_indicator_types_are_safely_unavailable_without_a_source(self) -> None:
        provider = CommunityIntelProvider()
        for indicator_type in IndicatorType:
            with self.subTest(indicator_type=indicator_type):
                result = provider.lookup(self.indicator(indicator_type))
                self.assertEqual(result.status, ProviderStatus.UNAVAILABLE)
                self.assertEqual(result.reputation, Reputation.UNAVAILABLE)
                self.assertNotEqual(result.reputation, Reputation.BENIGN)

    def test_provider_result_serializes_without_provider_specific_data(self) -> None:
        result = CommunityIntelProvider().lookup(self.indicator(IndicatorType.IP))
        restored = ThreatIntelResult.model_validate_json(result.model_dump_json())
        self.assertEqual(restored.indicator, result.indicator)
        self.assertEqual(restored.metadata, {"reason": "source_not_configured"})


if __name__ == "__main__":
    unittest.main()
