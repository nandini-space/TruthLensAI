"""Deterministic, local text threat detector."""

from .risk_engine import RiskEngine
from .schemas import InputType, ScanRequest, ScanResult, Signal, ThreatType
from .utils.entity_extraction import extract_entities
from .utils.text_normalization import normalize_text
from .utils.text_signals import detect_signals


class TextDetector:
    def __init__(self, risk_engine: RiskEngine | None = None) -> None:
        self._risk_engine = risk_engine or RiskEngine()

    def detect(self, request: ScanRequest) -> ScanResult:
        if request.input_type is not InputType.TEXT:
            raise ValueError("TextDetector only accepts text input")
        normalized = normalize_text(request.content)
        entities = extract_entities(normalized.normalized)
        signals = detect_signals(normalized.analysis, entities.domains)
        risk_score, severity, threat_type, confidence = self._risk_engine.assess_text(signals)
        return ScanResult(
            scan_id=request.scan_id,
            input_type=request.input_type,
            risk_score=risk_score,
            severity=severity,
            threat_type=threat_type,
            confidence=confidence,
            signals=signals,
            explanation=self._explanation(threat_type, signals),
            recommendation=self._recommendation(threat_type),
            entities=entities,
            metadata={
                "assessment_status": "completed",
                "detector": "deterministic_text_rules_v1",
                "original_content": request.content,
                "normalization": {"unicode": "NFKC", "whitespace_collapsed": True, "casefolded_for_matching": True},
            },
        )

    @staticmethod
    def _explanation(threat_type: ThreatType, signals: list[Signal]) -> str:
        if not signals:
            return "No significant threat indicators were detected."
        names = ", ".join(signal.code.replace("_", " ") for signal in signals)
        return f"Detected {threat_type.value} indicators: {names}."

    @staticmethod
    def _recommendation(threat_type: ThreatType) -> str:
        if threat_type is ThreatType.BENIGN:
            return "No significant threat indicators were detected."
        if threat_type is ThreatType.PHISHING:
            return "Do not click links or provide credentials. Verify the request through the organization's official website or app."
        if threat_type is ThreatType.HARASSMENT:
            return "Do not engage with threats. Preserve the message and use the relevant platform's safety or reporting tools."
        if threat_type is ThreatType.SCAM:
            return "Do not send money or sensitive information. Verify the claim independently before taking action."
        return "Verify the sender independently before taking action."
