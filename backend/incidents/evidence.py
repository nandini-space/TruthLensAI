"""Side-effect-free construction of evidence snapshots from detection and enrichment."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from backend.incidents.models import EvidencePack
from backend.intelligence.models import (
    EnrichedThreatResult,
    Indicator,
    ProviderStatus,
    ThreatIntelResult,
)
from backend.models.schemas import ScanResult


def build_evidence_pack(
    scan_result: ScanResult,
    indicators: list[Indicator],
    threat_intelligence: list[ThreatIntelResult],
    *,
    collected_at: datetime | None = None,
) -> EvidencePack:
    """Create an immutable-by-copy evidence snapshot without invoking providers.

    The existing contracts do not attach a scan ID to indicators or intelligence
    results, so they are retained exactly as supplied while the nested scan and
    enrichment contracts enforce the single scan identity.
    """

    timestamp = _utc_collection_time(collected_at)
    scan_snapshot = scan_result.model_copy(deep=True)
    indicator_snapshot = [indicator.model_copy(deep=True) for indicator in indicators]
    intelligence_snapshot = [result.model_copy(deep=True) for result in threat_intelligence]
    enrichment = EnrichedThreatResult(
        scan_id=scan_snapshot.scan_id,
        scan_result=scan_snapshot,
        indicators=indicator_snapshot,
        threat_intelligence=intelligence_snapshot,
        status=_enrichment_status(intelligence_snapshot),
        enriched_at=timestamp,
        provider_sources=_provider_sources(intelligence_snapshot),
    )
    return EvidencePack(
        evidence_id=uuid5(NAMESPACE_URL, f"truthlensai:evidence:{scan_snapshot.scan_id}"),
        scan_id=scan_snapshot.scan_id,
        scan_result=scan_snapshot,
        enriched_threat_result=enrichment,
        collected_at=timestamp,
    )


def _utc_collection_time(collected_at: datetime | None) -> datetime:
    if collected_at is None:
        return datetime.now(timezone.utc)
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError("collected_at must be timezone-aware")
    return collected_at.astimezone(timezone.utc)


def _enrichment_status(results: list[ThreatIntelResult]) -> ProviderStatus:
    statuses = {result.status for result in results}
    if ProviderStatus.SUCCESS in statuses:
        return ProviderStatus.SUCCESS
    if ProviderStatus.PARTIAL in statuses:
        return ProviderStatus.PARTIAL
    if statuses == {ProviderStatus.UNAVAILABLE} or not statuses:
        return ProviderStatus.UNAVAILABLE
    return ProviderStatus.ERROR


def _provider_sources(results: list[ThreatIntelResult]) -> list[str]:
    return list(dict.fromkeys(result.source for result in results))
