"""Deterministic, local URL threat detector with no network access."""

from .risk_engine import RiskEngine
from .config import UrlRiskConfig
from .schemas import ExtractedEntities, InputType, ScanRequest, ScanResult, Severity, Signal, ThreatType
from .utils.url_analysis import detect_url_signals, parse_url


class UrlDetector:
    def __init__(self, risk_engine: RiskEngine | None = None, config: UrlRiskConfig | None = None) -> None:
        self._risk_engine = risk_engine or RiskEngine()
        self._config = config or UrlRiskConfig()

    def detect(self, request: ScanRequest) -> ScanResult:
        if request.input_type is not InputType.URL:
            raise ValueError("UrlDetector only accepts URL input")
        parsed = parse_url(request.content)
        if parsed is None:
            return self._invalid_result(request)
        signals = detect_url_signals(parsed, self._config)
        risk_score, severity, threat_type, confidence = self._risk_engine.assess_url(signals)
        entities = ExtractedEntities(urls=[parsed.original], domains=[parsed.hostname])
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
                "detector": "deterministic_url_rules_v1",
                "original_url": parsed.original,
                "normalized_url": parsed.normalized,
                "url_components": {
                    "scheme": parsed.scheme, "hostname": parsed.hostname, "port": parsed.port,
                    "path": parsed.path, "query": parsed.query, "fragment": parsed.fragment,
                    "username": parsed.username, "is_ip_address": parsed.is_ip_address,
                    "registered_looking_domain": parsed.registered_looking_domain,
                },
            },
        )

    @staticmethod
    def _invalid_result(request: ScanRequest) -> ScanResult:
        signal = Signal(
            code="invalid_url", description="The input could not be parsed as a URL.", source="url_parser",
            details={"evidence": request.content, "strength": 0},
        )
        return ScanResult(
            scan_id=request.scan_id, input_type=request.input_type, risk_score=0, severity=Severity.LOW,
            threat_type=ThreatType.UNKNOWN, confidence=0.2, signals=[signal],
            explanation="The input could not be parsed as a URL.",
            recommendation="Check the link format before opening it.",
            entities=ExtractedEntities(urls=[request.content]),
            metadata={"assessment_status": "invalid_input", "original_url": request.content},
        )

    @staticmethod
    def _explanation(threat_type: ThreatType, signals: list[Signal]) -> str:
        if not signals:
            return "No significant URL threat indicators were detected."
        names = ", ".join(signal.code.replace("_", " ") for signal in signals)
        return f"Detected {threat_type.value} URL characteristics: {names}."

    @staticmethod
    def _recommendation(threat_type: ThreatType) -> str:
        if threat_type is ThreatType.BENIGN:
            return "No significant URL threat indicators were detected."
        if threat_type in {ThreatType.PHISHING, ThreatType.MALICIOUS_URL}:
            return "Do not open the link or enter credentials. Verify the destination through an official source."
        return "Verify the destination before opening the link."
