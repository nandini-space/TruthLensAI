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


@dataclass(frozen=True, slots=True)
class UrlRiskConfig:
    """Local URL heuristic weights and conservative parsing thresholds."""

    signal_weights: dict[str, int] = field(
        default_factory=lambda: {
            "ip_address_hostname": 20, "url_shortener": 10, "insecure_scheme": 5,
            "explicit_url_credentials": 40, "excessive_subdomains": 12,
            "uncommon_port": 14, "encoded_url_structure": 12,
            "credential_related_path": 10, "redirect_destination_parameter": 12,
            "credential_query_parameter": 15, "brand_like_hostname": 18,
        }
    )
    shortener_domains: frozenset[str] = frozenset({"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "cutt.ly", "rb.gy"})
    common_ports: frozenset[int] = frozenset({80, 443, 8080, 8443})
    credential_path_terms: frozenset[str] = frozenset({"login", "signin", "verify", "account", "password", "secure", "authentication", "update"})
    redirect_parameter_names: frozenset[str] = frozenset({"redirect", "redirect_uri", "url", "next", "continue", "return"})
    credential_parameter_names: frozenset[str] = frozenset({"password", "passwd", "pwd", "otp", "code", "token"})
    demonstration_brand_terms: frozenset[str] = frozenset({"paypal", "microsoft", "google", "apple", "amazon"})
    max_hostname_labels: int = 4
    encoded_sequence_threshold: int = 3
    moderate_threshold: int = 15
    high_threshold: int = 40
    critical_threshold: int = 70
