"""Pure STIX 2.1 export for TruthLensAI investigation snapshots."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone

from stix2.v21 import Bundle, ExternalReference, Incident as StixIncident
from stix2.v21 import Indicator as StixIndicator
from stix2.v21 import Relationship, Report as StixReport

from backend.incidents.models import EvidencePack, Incident
from backend.intelligence.models import Indicator, IndicatorType, Reputation, ThreatIntelResult
from backend.reports.models import ForensicReport


_ADVERSE_REPUTATIONS = {Reputation.MALICIOUS, Reputation.SUSPICIOUS}
_REPUTATION_ORDER = {Reputation.MALICIOUS: 0, Reputation.SUSPICIOUS: 1}
_HASH_ALGORITHMS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}


def export_stix_bundle(
    evidence_pack: EvidencePack,
    incident: Incident | None = None,
    forensic_report: ForensicReport | None = None,
) -> Bundle:
    """Export validated investigation data as a STIX 2.1 bundle.

    Only indicators supported by STIX patterns and marked malicious or suspicious
    by supplied intelligence become STIX Indicator objects. Other source data is
    deliberately left in the TruthLensAI contracts rather than misrepresented.
    """

    evidence = _validated_evidence_snapshot(evidence_pack)
    incident_snapshot = _validated_incident_snapshot(incident) if incident else None
    report_snapshot = _validated_report_snapshot(forensic_report) if forensic_report else None
    _validate_related_objects(evidence, incident_snapshot, report_snapshot)

    timestamp = _utc_timestamp(evidence.collected_at, field_name="evidence_pack.collected_at")
    intelligence = _intelligence_by_indicator(evidence.enriched_threat_result.threat_intelligence)
    objects: list[object] = []
    indicators: list[StixIndicator] = []
    for indicator in evidence.enriched_threat_result.indicators:
        pattern = _stix_pattern(indicator)
        results = _adverse_results(intelligence[_indicator_key(indicator)])
        if pattern is None or not results:
            continue
        stix_indicator = _build_indicator(indicator, results, pattern, timestamp)
        indicators.append(stix_indicator)
        objects.append(stix_indicator)

    stix_incident: StixIncident | None = None
    if incident_snapshot is not None:
        stix_incident = _build_incident(incident_snapshot)
        objects.append(stix_incident)
        objects.extend(
            Relationship(
                source_ref=stix_incident.id,
                relationship_type="related-to",
                target_ref=stix_indicator.id,
                created=_utc_timestamp(incident_snapshot.created_at, field_name="incident.created_at"),
                modified=_utc_timestamp(incident_snapshot.updated_at, field_name="incident.updated_at"),
            )
            for stix_indicator in indicators
        )

    if report_snapshot is not None:
        report_references = [indicator.id for indicator in indicators]
        if stix_incident is not None:
            report_references.append(stix_incident.id)
        if report_references:
            objects.append(_build_report(report_snapshot, report_references))

    return Bundle(*objects)


def _validated_evidence_snapshot(evidence_pack: EvidencePack) -> EvidencePack:
    if not isinstance(evidence_pack, EvidencePack):
        raise TypeError("evidence_pack must be an EvidencePack")
    return EvidencePack.model_validate(evidence_pack.model_dump()).model_copy(deep=True)


def _validated_incident_snapshot(incident: Incident) -> Incident:
    if not isinstance(incident, Incident):
        raise TypeError("incident must be an Incident")
    return Incident.model_validate(incident.model_dump()).model_copy(deep=True)


def _validated_report_snapshot(report: ForensicReport) -> ForensicReport:
    if not isinstance(report, ForensicReport):
        raise TypeError("forensic_report must be a ForensicReport")
    return ForensicReport.model_validate(report.model_dump()).model_copy(deep=True)


def _validate_related_objects(
    evidence: EvidencePack,
    incident: Incident | None,
    report: ForensicReport | None,
) -> None:
    if incident is not None and incident.scan_id != evidence.scan_id:
        raise ValueError("incident.scan_id must match evidence_pack.scan_id")
    if incident is not None and incident.evidence_pack is not None:
        if incident.evidence_pack.evidence_id != evidence.evidence_id:
            raise ValueError("incident.evidence_pack must match the supplied evidence_pack")
    if incident is not None and incident.evidence_reference is not None:
        if incident.evidence_reference != str(evidence.evidence_id):
            raise ValueError("incident.evidence_reference must match evidence_pack.evidence_id")
    if report is not None and report.evidence_pack.evidence_id != evidence.evidence_id:
        raise ValueError("forensic_report.evidence_pack must match the supplied evidence_pack")
    if report is not None and report.scan_id != evidence.scan_id:
        raise ValueError("forensic_report.scan_id must match evidence_pack.scan_id")
    if report is not None and incident is not None and report.incident_id != incident.incident_id:
        raise ValueError("forensic_report.incident_id must match incident.incident_id")


def _intelligence_by_indicator(
    results: list[ThreatIntelResult],
) -> dict[tuple[IndicatorType, str], list[ThreatIntelResult]]:
    grouped: dict[tuple[IndicatorType, str], list[ThreatIntelResult]] = defaultdict(list)
    for result in results:
        grouped[_indicator_key(result.indicator)].append(result)
    return grouped


def _indicator_key(indicator: Indicator) -> tuple[IndicatorType, str]:
    return (indicator.type, indicator.value)


def _adverse_results(results: list[ThreatIntelResult]) -> list[ThreatIntelResult]:
    return sorted(
        (result for result in results if result.reputation in _ADVERSE_REPUTATIONS),
        key=lambda result: (_REPUTATION_ORDER[result.reputation], result.source),
    )


def _stix_pattern(indicator: Indicator) -> str | None:
    value = _escape_pattern_value(indicator.value)
    if indicator.type is IndicatorType.IP:
        try:
            if ipaddress.ip_address(indicator.value).version != 4:
                return None
        except ValueError:
            return None
        return f"[ipv4-addr:value = '{value}']"
    if indicator.type is IndicatorType.DOMAIN:
        return f"[domain-name:value = '{value}']"
    if indicator.type is IndicatorType.URL:
        return f"[url:value = '{value}']"
    if indicator.type is IndicatorType.EMAIL:
        return f"[email-addr:value = '{value}']"
    if indicator.type is IndicatorType.HASH:
        algorithm = _hash_algorithm(indicator.value)
        if algorithm is not None:
            return f"[file:hashes.'{algorithm}' = '{value}']"
    return None


def _hash_algorithm(value: str) -> str | None:
    if re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        return None
    return _HASH_ALGORITHMS.get(len(value))


def _escape_pattern_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _build_indicator(
    indicator: Indicator,
    results: list[ThreatIntelResult],
    pattern: str,
    timestamp: datetime,
) -> StixIndicator:
    strongest = results[0]
    confidences = [result.confidence for result in results if result.confidence is not None]
    if indicator.confidence is not None:
        confidences.append(indicator.confidence)
    labels = [
        "malicious-activity",
        "truthlensai",
        f"truthlensai:indicator-type:{indicator.type.value}",
        f"truthlensai:reputation:{strongest.reputation.value}",
    ]
    labels.extend(f"truthlensai:provider:{result.source}" for result in results)
    description = (
        "TruthLensAI exported this indicator from provider-neutral intelligence: "
        + "; ".join(
            f"{result.source} reported {result.reputation.value} ({result.status.value})"
            for result in results
        )
        + "."
    )
    kwargs: dict[str, object] = {
        "name": f"TruthLensAI {strongest.reputation.value} {indicator.type.value} indicator",
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "created": timestamp,
        "modified": timestamp,
        "labels": list(dict.fromkeys(labels)),
    }
    if confidences:
        kwargs["confidence"] = round(max(confidences) * 100)
    return StixIndicator(**kwargs)


def _build_incident(incident: Incident) -> StixIncident:
    created = _utc_timestamp(incident.created_at, field_name="incident.created_at")
    modified = _utc_timestamp(incident.updated_at, field_name="incident.updated_at")
    return StixIncident(
        name=f"TruthLensAI {incident.threat_type} incident",
        description=(
            f"TruthLensAI incident {incident.incident_id} with {incident.severity.value} "
            f"severity and risk score {incident.risk_score}."
        ),
        labels=[
            "truthlensai",
            f"truthlensai:status:{incident.status.value}",
            f"truthlensai:severity:{incident.severity.value}",
            f"truthlensai:threat-type:{incident.threat_type}",
        ],
        confidence=round(incident.confidence * 100),
        external_references=[
            ExternalReference(source_name="TruthLensAI", external_id=str(incident.incident_id))
        ],
        created=created,
        modified=modified,
    )


def _build_report(report: ForensicReport, object_refs: list[str]) -> StixReport:
    timestamp = _utc_timestamp(report.generated_at, field_name="forensic_report.generated_at")
    return StixReport(
        name=f"TruthLensAI forensic report: {report.threat_type}",
        description=report.analysis,
        report_types=["threat-report"],
        published=timestamp,
        created=timestamp,
        modified=timestamp,
        labels=["truthlensai", f"truthlensai:severity:{report.severity.value}"],
        confidence=round(report.confidence * 100),
        external_references=[
            ExternalReference(source_name="TruthLensAI", external_id=str(report.report_id))
        ],
        object_refs=object_refs,
    )


def _utc_timestamp(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)
