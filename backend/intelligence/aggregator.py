"""Deterministic aggregation of provider-neutral threat intelligence results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from backend.intelligence.models import (
    Indicator,
    ProviderStatus,
    Reputation,
    ThreatIntelFinding,
    ThreatIntelResult,
)


_SOURCE = "threat_intelligence_aggregator"
_USABLE_STATUSES = {ProviderStatus.SUCCESS, ProviderStatus.PARTIAL}
_EVIDENCE_REPUTATIONS = {
    Reputation.MALICIOUS,
    Reputation.SUSPICIOUS,
    Reputation.BENIGN,
}


def aggregate_threat_intelligence(
    indicators: list[Indicator], provider_results: list[ThreatIntelResult]
) -> list[ThreatIntelResult]:
    """Aggregate supplied provider results into one result per input indicator.

    Results with no matching input indicator are ignored. This function does not
    invoke providers, alter input contracts, or use provider-specific behavior.
    """

    unique_indicators: dict[tuple[str, str], Indicator] = {}
    for indicator in indicators:
        unique_indicators.setdefault(_indicator_key(indicator), indicator)

    grouped: dict[tuple[str, str], list[ThreatIntelResult]] = {
        key: [] for key in unique_indicators
    }
    for result in _deduplicate_results(provider_results):
        key = _indicator_key(result.indicator)
        if key in grouped:
            grouped[key].append(result)

    return [
        _aggregate_indicator(indicator, grouped[key])
        for key, indicator in unique_indicators.items()
    ]


def _indicator_key(indicator: Indicator) -> tuple[str, str]:
    """Use the Task 3-normalized type/value identity without crossing types."""

    return indicator.type.value, indicator.value


def _deduplicate_results(results: list[ThreatIntelResult]) -> list[ThreatIntelResult]:
    unique: list[ThreatIntelResult] = []
    seen: set[str] = set()
    for result in results:
        identity = json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        if identity not in seen:
            seen.add(identity)
            unique.append(result)
    return unique


def _aggregate_indicator(
    indicator: Indicator, results: list[ThreatIntelResult]
) -> ThreatIntelResult:
    queried_at = max((result.queried_at for result in results), default=datetime.now(timezone.utc))
    status = _aggregate_status(results)
    reputation = _aggregate_reputation(results)
    findings = _aggregate_findings(results)
    if not results:
        findings.append(
            ThreatIntelFinding(
                source=_SOURCE,
                category="no_provider_results",
                description="No provider intelligence results were supplied for this indicator.",
            )
        )
    elif _has_reputation_conflict(results):
        findings.append(
            ThreatIntelFinding(
                source=_SOURCE,
                category="reputation_conflict",
                description="Usable providers reported conflicting non-neutral reputations.",
                metadata={"reputations": sorted(_usable_evidence_reputations(results))},
            )
        )

    return ThreatIntelResult(
        indicator=indicator,
        reputation=reputation,
        source=_SOURCE,
        queried_at=queried_at,
        status=status,
        findings=findings,
        metadata={
            "provider_result_count": len(results),
            "provider_sources": [result.source for result in results],
            "provider_statuses": [result.status.value for result in results],
            "provider_reputations": [result.reputation.value for result in results],
        },
    )


def _aggregate_status(results: list[ThreatIntelResult]) -> ProviderStatus:
    statuses = {result.status for result in results}
    if ProviderStatus.SUCCESS in statuses:
        return ProviderStatus.SUCCESS
    if ProviderStatus.PARTIAL in statuses:
        return ProviderStatus.PARTIAL
    if statuses == {ProviderStatus.UNAVAILABLE} or not statuses:
        return ProviderStatus.UNAVAILABLE
    return ProviderStatus.ERROR


def _aggregate_reputation(results: list[ThreatIntelResult]) -> Reputation:
    usable_results = [result for result in results if result.status in _USABLE_STATUSES]
    usable_reputations = {result.reputation for result in usable_results}
    if Reputation.MALICIOUS in usable_reputations:
        return Reputation.MALICIOUS
    if Reputation.SUSPICIOUS in usable_reputations:
        return Reputation.SUSPICIOUS
    if Reputation.BENIGN in usable_reputations:
        return Reputation.BENIGN
    if usable_results:
        return Reputation.UNKNOWN
    return Reputation.UNAVAILABLE


def _aggregate_findings(results: list[ThreatIntelResult]) -> list[ThreatIntelFinding]:
    findings: list[ThreatIntelFinding] = []
    seen: set[str] = set()
    for result in results:
        summary = ThreatIntelFinding(
            source=result.source,
            category="provider_result_summary",
            description=(
                f"Provider reported {result.reputation.value} reputation "
                f"with {result.status.value} status."
            ),
            metadata={
                "reputation": result.reputation.value,
                "status": result.status.value,
                "provider_reference": result.provider_reference,
            },
        )
        for finding in [summary, *result.findings]:
            identity = json.dumps(
                finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            )
            if identity not in seen:
                seen.add(identity)
                findings.append(finding)
    return findings


def _usable_evidence_reputations(results: list[ThreatIntelResult]) -> set[str]:
    return {
        result.reputation.value
        for result in results
        if result.status in _USABLE_STATUSES and result.reputation in _EVIDENCE_REPUTATIONS
    }


def _has_reputation_conflict(results: list[ThreatIntelResult]) -> bool:
    return len(_usable_evidence_reputations(results)) > 1
