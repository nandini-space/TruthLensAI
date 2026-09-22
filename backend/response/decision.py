"""Conservative policy decisions from existing threat-intelligence evidence."""

from __future__ import annotations

from collections import defaultdict

from backend.incidents.models import EvidencePack, Incident
from backend.intelligence.models import Indicator, IndicatorType, Reputation, ThreatIntelResult
from backend.response.models import ExecutionMode, ResponseAction, ResponseDecision


_AGGREGATOR_SOURCE = "threat_intelligence_aggregator"
_BLOCKABLE_TYPES = {
    IndicatorType.IP,
    IndicatorType.DOMAIN,
    IndicatorType.URL,
    IndicatorType.HASH,
}


def decide_response(
    evidence_pack: EvidencePack, incident: Incident | None = None
) -> list[ResponseDecision]:
    """Make deterministic dry-run decisions without performing any response action."""

    evidence = _validated_evidence_snapshot(evidence_pack)
    incident_snapshot = _validated_incident_snapshot(incident) if incident else None
    _validate_incident_relationship(evidence, incident_snapshot)
    results = _results_by_indicator(evidence.enriched_threat_result.threat_intelligence)

    decisions: list[ResponseDecision] = []
    seen: set[tuple[IndicatorType, str]] = set()
    for indicator in evidence.enriched_threat_result.indicators:
        key = (indicator.type, indicator.value)
        if key in seen:
            continue
        seen.add(key)
        decisions.append(
            _decision_for_indicator(
                indicator,
                results[key],
                evidence,
                incident_snapshot,
            )
        )
    return decisions


def _validated_evidence_snapshot(evidence_pack: EvidencePack) -> EvidencePack:
    if not isinstance(evidence_pack, EvidencePack):
        raise TypeError("evidence_pack must be an EvidencePack")
    return EvidencePack.model_validate(evidence_pack.model_dump()).model_copy(deep=True)


def _validated_incident_snapshot(incident: Incident) -> Incident:
    if not isinstance(incident, Incident):
        raise TypeError("incident must be an Incident")
    return Incident.model_validate(incident.model_dump()).model_copy(deep=True)


def _validate_incident_relationship(evidence: EvidencePack, incident: Incident | None) -> None:
    if incident is None:
        return
    if incident.scan_id != evidence.scan_id:
        raise ValueError("incident.scan_id must match evidence_pack.scan_id")
    if incident.evidence_pack is not None and incident.evidence_pack.evidence_id != evidence.evidence_id:
        raise ValueError("incident.evidence_pack must match the supplied evidence_pack")
    if incident.evidence_reference is not None and incident.evidence_reference != str(evidence.evidence_id):
        raise ValueError("incident.evidence_reference must match evidence_pack.evidence_id")


def _results_by_indicator(
    results: list[ThreatIntelResult],
) -> dict[tuple[IndicatorType, str], list[ThreatIntelResult]]:
    grouped: dict[tuple[IndicatorType, str], list[ThreatIntelResult]] = defaultdict(list)
    for result in results:
        grouped[(result.indicator.type, result.indicator.value)].append(result)
    return grouped


def _decision_for_indicator(
    indicator: Indicator,
    results: list[ThreatIntelResult],
    evidence: EvidencePack,
    incident: Incident | None,
) -> ResponseDecision:
    action = ResponseAction.NO_ACTION
    reputation: Reputation | None = None
    if indicator.type not in _BLOCKABLE_TYPES:
        reason = f"Indicator type {indicator.type.value} is not supported for blocking."
    else:
        selected, reason = _select_intelligence(results)
        if selected is not None:
            reputation = selected.reputation
            if selected.reputation is Reputation.MALICIOUS:
                action = ResponseAction.BLOCK
                reason = "Existing threat intelligence explicitly reports malicious reputation."
            else:
                reason = (
                    f"Threat intelligence reputation is {selected.reputation.value}, "
                    "not malicious."
                )
    return ResponseDecision(
        indicator_id=indicator.indicator_id,
        indicator_type=indicator.type,
        indicator_value=indicator.value,
        indicator=indicator.model_copy(deep=True),
        action=action,
        reason=reason,
        reputation=reputation,
        evidence_id=evidence.evidence_id,
        scan_id=evidence.scan_id,
        incident_id=incident.incident_id if incident else None,
        mode=ExecutionMode.DRY_RUN,
    )


def _select_intelligence(
    results: list[ThreatIntelResult],
) -> tuple[ThreatIntelResult | None, str]:
    aggregated = [result for result in results if result.source == _AGGREGATOR_SOURCE]
    if len(aggregated) == 1:
        return aggregated[0], "Using the existing aggregated threat-intelligence result."
    if len(aggregated) > 1:
        return None, "Multiple aggregated intelligence results make the response ineligible."
    if not results:
        return None, "No threat-intelligence result is available for this indicator."
    if len(results) > 1:
        return None, "Multiple provider results require an aggregated intelligence result."
    return results[0], "Using the sole available threat-intelligence result."
