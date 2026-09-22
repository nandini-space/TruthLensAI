"""Deterministic fusion of authoritative modality results without re-detection."""

from __future__ import annotations

from typing import Iterable

from .config import MultimodalFusionConfig, TextRiskConfig
from .schemas import ExtractedEntities, InputType, ScanResult, Severity, Signal, ThreatType


class MultimodalFusion:
    """Uses the strongest result as a base; only distinct corroborating modalities add a cap."""
    def __init__(self, config: MultimodalFusionConfig | None = None) -> None:
        self._config = config or MultimodalFusionConfig()
        # Use the same risk thresholds that deterministic text assessments use.
        self._severity_config = TextRiskConfig()

    def fuse(self, results: Iterable[ScanResult]) -> ScanResult:
        children = [item for item in results if isinstance(item, ScanResult)]
        assessed = [item for item in children if item.risk_score is not None and item.metadata.get("assessment_status") != "not_implemented"]
        if not assessed:
            return self._unknown(children)
        strongest = max(assessed, key=lambda item: ((item.risk_score or 0), item.confidence or 0, len(item.signals)))
        distinct = self._distinct_supporters(assessed, strongest)
        bonus = min(self._config.max_corroboration_bonus, self._config.corroboration_bonus_per_modality * len(distinct))
        score = min(100.0, (strongest.risk_score or 0) + bonus)
        confidence = min(1.0, (strongest.confidence or 0) + self._config.confidence_bonus_per_modality * len(distinct))
        signals = self._dedupe_signals(assessed)
        modalities = [item.input_type.value for item in assessed]
        conflicts = sorted({item.threat_type.value for item in assessed if item.threat_type is not strongest.threat_type and (item.risk_score or 0) > 0})
        metadata = {"fusion_status": "completed", "fusion_version": self._config.fusion_version, "fusion_method": "strongest_child_plus_bounded_distinct_corroboration", "contributing_modalities": modalities, "corroborating_modalities": [item.input_type.value for item in distinct], "conflicting_threat_types": conflicts, "deduplicated_evidence_count": sum(len(item.signals) for item in assessed) - len(signals), "children": [{"modality": item.input_type.value, "risk_score": item.risk_score, "severity": item.severity.value, "threat_type": item.threat_type.value, "signals": [signal.code for signal in item.signals]} for item in assessed]}
        return ScanResult(scan_id=strongest.scan_id, input_type=strongest.input_type, risk_score=score, severity=self._severity(score), threat_type=strongest.threat_type, confidence=round(confidence, 2), signals=signals, explanation=self._explanation(strongest, distinct, conflicts), recommendation=strongest.recommendation, entities=self._entities(assessed), metadata=metadata)

    def _distinct_supporters(self, assessed: list[ScanResult], strongest: ScanResult) -> list[ScanResult]:
        base = self._fingerprint(strongest)
        return [item for item in assessed if item is not strongest and item.threat_type is strongest.threat_type and (item.risk_score or 0) > 0 and self._fingerprint(item) != base]

    @staticmethod
    def _fingerprint(result: ScanResult) -> tuple[str, ...]:
        # Video is already internally aggregated; use its outward signals only.
        return tuple(sorted(signal.code.casefold() for signal in result.signals))

    @staticmethod
    def _dedupe_signals(results: list[ScanResult]) -> list[Signal]:
        observed: dict[tuple[str, str], Signal] = {}
        for result in results:
            for signal in result.signals:
                observed.setdefault((signal.code.casefold(), signal.description.casefold()), signal.model_copy(update={"source": result.input_type.value}))
        return list(observed.values())

    @staticmethod
    def _entities(results: list[ScanResult]) -> ExtractedEntities:
        def values(name: str) -> list[str]: return list(dict.fromkeys(value for result in results for value in getattr(result.entities, name)))
        return ExtractedEntities(urls=values("urls"), domains=values("domains"), email_addresses=values("email_addresses"), phone_numbers=values("phone_numbers"), usernames=values("usernames"))

    def _severity(self, score: float) -> Severity:
        if score >= self._severity_config.critical_threshold: return Severity.CRITICAL
        if score >= self._severity_config.high_threshold: return Severity.HIGH
        if score >= self._severity_config.moderate_threshold: return Severity.MODERATE
        return Severity.LOW

    @staticmethod
    def _explanation(strongest: ScanResult, supporters: list[ScanResult], conflicts: list[str]) -> str:
        text = f"{strongest.threat_type.value.capitalize()} assessment is based on strongest {strongest.input_type.value} evidence."
        if supporters: text += " Independent corroboration came from " + ", ".join(item.input_type.value for item in supporters) + "."
        if conflicts: text += " Conflicting classifications were retained in metadata."
        return text

    def _unknown(self, children: list[ScanResult]) -> ScanResult:
        return ScanResult(input_type=InputType.VIDEO, risk_score=None, severity=Severity.UNKNOWN, threat_type=ThreatType.UNKNOWN, confidence=None, explanation="No meaningful assessed evidence was available for multimodal fusion.", recommendation="Treat the content cautiously and verify requests through an independent source.", entities=ExtractedEntities(), metadata={"fusion_status": "no_meaningful_evidence", "fusion_version": self._config.fusion_version, "contributing_modalities": [item.input_type.value for item in children]})
