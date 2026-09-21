"""Transparent risk scoring and classification for deterministic text signals."""

from uuid import UUID

from .config import TextRiskConfig
from .schemas import InputType, ScanResult, Severity, Signal, ThreatType


class RiskEngine:
    """Scores signal combinations while retaining the Stage 1 neutral-result boundary."""

    def __init__(self, text_config: TextRiskConfig | None = None) -> None:
        self._text_config = text_config or TextRiskConfig()

    def unassessed_result(self, *, scan_id: UUID, input_type: InputType) -> ScanResult:
        return ScanResult(
            scan_id=scan_id,
            input_type=input_type,
            risk_score=None,
            severity=Severity.UNKNOWN,
            threat_type=ThreatType.UNKNOWN,
            confidence=None,
            explanation="Detection analysis has not been implemented for this input.",
            recommendation="No automated recommendation is available until analysis is configured.",
            metadata={"assessment_status": "not_implemented"},
        )

    def assess_text(self, signals: list[Signal]) -> tuple[float, Severity, ThreatType, float]:
        """Produce a bounded, explainable assessment from detected signals."""
        codes = {signal.code for signal in signals}
        if not codes:
            return 0.0, Severity.LOW, ThreatType.BENIGN, 0.70

        score = sum(self._text_config.signal_weights.get(code, 0) for code in codes)
        if {"credential_request", "account_verification"} <= codes or {"credential_request", "urgency"} <= codes:
            score += 20
        if {"otp_request", "account_verification"} <= codes:
            score += 18
        if {"prize_claim", "financial_request"} <= codes:
            score += 25
        if {"threat", "secrecy_request"} <= codes:
            score += 15
        if "shortened_url" in codes and ({"credential_request", "otp_request", "sensitive_information_request"} & codes):
            score += 10
        score = float(min(score, 100))

        if score >= self._text_config.critical_threshold:
            severity = Severity.CRITICAL
        elif score >= self._text_config.high_threshold:
            severity = Severity.HIGH
        elif score >= self._text_config.moderate_threshold:
            severity = Severity.MODERATE
        else:
            severity = Severity.LOW

        if "threat" in codes:
            threat_type = ThreatType.HARASSMENT
        elif ({"credential_request", "otp_request"} & codes) and ({"urgency", "account_verification", "shortened_url"} & codes):
            threat_type = ThreatType.PHISHING
        elif {"prize_claim", "financial_request"} <= codes or ({"employment_or_investment_claim", "financial_request"} <= codes):
            threat_type = ThreatType.SCAM
        elif len(codes) >= 3:
            threat_type = ThreatType.SOCIAL_ENGINEERING
        elif score >= self._text_config.moderate_threshold:
            threat_type = ThreatType.SUSPICIOUS
        else:
            threat_type = ThreatType.UNKNOWN

        confidence = min(0.95, 0.40 + score / 200 + min(len(codes), 5) * 0.05)
        return score, severity, threat_type, round(confidence, 2)
