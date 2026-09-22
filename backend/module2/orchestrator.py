"""Side-effect-free coordination of existing Module 2 components."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol, Sequence

from pydantic import Field

from backend.incidents.evidence import build_evidence_pack
from backend.incidents.manager import create_incident
from backend.incidents.models import EvidencePack, Incident
from backend.intelligence.aggregator import aggregate_threat_intelligence
from backend.intelligence.community import CommunityIntelProvider
from backend.intelligence.ioc_extractor import extract_indicators
from backend.intelligence.models import (
    EnrichedThreatResult,
    Indicator,
    ProviderStatus,
    Reputation,
    ThreatIntelFinding,
    ThreatIntelResult,
)
from backend.intelligence.virustotal import VirusTotalProvider
from backend.models.schemas import ContractModel, ScanResult
from backend.reports.forensic import build_forensic_report
from backend.reports.models import ForensicReport
from backend.reports.stix import export_stix_bundle
from backend.response.audit import ActionRecord, build_action_records
from backend.response.blocker import DryRunIOCBlocker
from backend.response.decision import decide_response
from backend.response.models import ResponseDecision


class ThreatIntelligenceProvider(Protocol):
    """Provider boundary consumed by the orchestrator."""

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        """Return provider-neutral intelligence for one indicator."""


class Module2Result(ContractModel):
    """Independent snapshot of every major Module 2 pipeline output."""

    scan_result: ScanResult
    indicators: list[Indicator] = Field(default_factory=list)
    provider_results: list[ThreatIntelResult] = Field(default_factory=list)
    threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)
    enriched_threat_result: EnrichedThreatResult
    evidence_pack: EvidencePack
    incident: Incident
    forensic_report: ForensicReport
    stix_bundle: Any
    response_decisions: list[ResponseDecision] = Field(default_factory=list)
    action_records: list[ActionRecord] = Field(default_factory=list)


def run_module2_investigation(
    scan_result: ScanResult,
    *,
    threat_intelligence_providers: Sequence[ThreatIntelligenceProvider] | None = None,
    incident: Incident | None = None,
    recorded_at=None,
    generated_at=None,
) -> Module2Result:
    """Run the established Module 2 workflow without adding policy or side effects."""

    scan_snapshot = _validated_scan_snapshot(scan_result)
    indicators = extract_indicators(scan_snapshot)
    providers = (
        list(threat_intelligence_providers)
        if threat_intelligence_providers is not None
        else [VirusTotalProvider(), CommunityIntelProvider()]
    )
    provider_results = _lookup_providers(indicators, providers)
    aggregated = aggregate_threat_intelligence(indicators, provider_results)
    evidence = build_evidence_pack(
        scan_snapshot, indicators, aggregated, collected_at=recorded_at
    )
    incident_snapshot = _resolve_incident(incident, evidence, recorded_at)
    report = build_forensic_report(incident_snapshot, evidence, generated_at=generated_at)
    bundle = export_stix_bundle(evidence, incident_snapshot, report)
    decisions = decide_response(evidence, incident_snapshot)
    # The blocker is intentionally invoked only in dry-run mode; it has no side effects.
    for decision in decisions:
        DryRunIOCBlocker().block(decision)
    records = build_action_records(
        decisions, incident=incident_snapshot, recorded_at=recorded_at
    )
    return Module2Result(
        scan_result=scan_snapshot,
        indicators=indicators,
        provider_results=provider_results,
        threat_intelligence=aggregated,
        enriched_threat_result=evidence.enriched_threat_result,
        evidence_pack=evidence,
        incident=incident_snapshot,
        forensic_report=report,
        stix_bundle=bundle,
        response_decisions=decisions,
        action_records=records,
    )


def _validated_scan_snapshot(scan_result: ScanResult) -> ScanResult:
    if not isinstance(scan_result, ScanResult):
        raise TypeError("scan_result must be a ScanResult")
    return ScanResult.model_validate(scan_result.model_dump()).model_copy(deep=True)


def _lookup_providers(
    indicators: list[Indicator], providers: Sequence[ThreatIntelligenceProvider]
) -> list[ThreatIntelResult]:
    results: list[ThreatIntelResult] = []
    for indicator in indicators:
        for provider in providers:
            try:
                result = provider.lookup(indicator)
                if not isinstance(result, ThreatIntelResult):
                    raise TypeError("provider lookup must return a ThreatIntelResult")
            except Exception as error:
                results.append(_provider_failure_result(indicator, provider, error))
            else:
                results.append(result.model_copy(deep=True))
    return results


def _provider_failure_result(
    indicator: Indicator, provider: object, error: Exception
) -> ThreatIntelResult:
    source = getattr(provider, "source", provider.__class__.__name__.lower())
    source = source if isinstance(source, str) and source.strip() else "unknown_provider"
    return ThreatIntelResult(
        indicator=indicator.model_copy(deep=True),
        reputation=Reputation.UNAVAILABLE,
        source=source,
        queried_at=datetime.now(timezone.utc),
        status=ProviderStatus.ERROR,
        findings=[
            ThreatIntelFinding(
                source=source,
                category="provider_exception",
                description=f"Provider lookup failed with {error.__class__.__name__}.",
            )
        ],
    )


def _resolve_incident(
    supplied: Incident | None, evidence: EvidencePack, created_at
) -> Incident:
    if supplied is None:
        return create_incident(evidence, created_at=created_at)
    if not isinstance(supplied, Incident):
        raise TypeError("incident must be an Incident")
    snapshot = Incident.model_validate(supplied.model_dump()).model_copy(deep=True)
    if snapshot.scan_id != evidence.scan_id:
        raise ValueError("incident.scan_id must match evidence_pack.scan_id")
    if snapshot.evidence_pack is not None and snapshot.evidence_pack.evidence_id != evidence.evidence_id:
        raise ValueError("incident.evidence_pack must match the generated evidence_pack")
    if snapshot.evidence_reference is not None and snapshot.evidence_reference != str(evidence.evidence_id):
        raise ValueError("incident.evidence_reference must match evidence_pack.evidence_id")
    return snapshot
