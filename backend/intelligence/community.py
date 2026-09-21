"""Community-intelligence provider boundary pending a configured concrete source."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.intelligence.models import (
    Indicator,
    ProviderStatus,
    Reputation,
    ThreatIntelFinding,
    ThreatIntelResult,
)


_SOURCE = "community_intelligence"


class CommunityIntelProvider:
    """Return a safe neutral result until TruthLensAI configures a community source.

    No community provider, endpoint, or credential has been specified in this
    repository. This boundary intentionally performs no network activity; a
    later configured adapter can preserve this ``lookup`` interface.
    """

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        """Represent unavailable community enrichment without implying safety."""

        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.UNAVAILABLE,
            source=_SOURCE,
            queried_at=datetime.now(timezone.utc),
            status=ProviderStatus.UNAVAILABLE,
            findings=[
                ThreatIntelFinding(
                    source=_SOURCE,
                    category="source_not_configured",
                    description=(
                        "No concrete community-intelligence provider is configured."
                    ),
                )
            ],
            metadata={"reason": "source_not_configured"},
        )
