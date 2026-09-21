"""Detection-engine configuration boundary; provider settings are deferred."""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Non-secret configuration owned by the detection pipeline."""

    contract_version: str = "1.0"


@dataclass(frozen=True, slots=True)
class TextRiskConfig:
    """Transparent scoring weights and thresholds for deterministic text analysis."""

    signal_weights: dict[str, int] = field(
        default_factory=lambda: {
            "urgency": 8, "account_verification": 12, "credential_request": 35,
            "otp_request": 35, "financial_request": 22, "prize_claim": 24,
            "impersonation": 10, "threat": 40, "secrecy_request": 10,
            "sensitive_information_request": 30, "pressure": 8,
            "employment_or_investment_claim": 14, "move_platform_request": 8,
            "shortened_url": 8,
        }
    )
    moderate_threshold: int = 15
    high_threshold: int = 40
    critical_threshold: int = 70
