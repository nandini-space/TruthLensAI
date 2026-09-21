import unittest

from backend.detection.schemas import InputType, ScanRequest, Severity, ThreatType
from backend.detection.url_detector import UrlDetector


class UrlDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = UrlDetector()

    def scan(self, url: str):
        return self.detector.detect(ScanRequest(input_type=InputType.URL, content=url))

    def codes(self, result) -> set[str]:
        return {signal.code for signal in result.signals}

    def test_benign_https_url(self) -> None:
        result = self.scan("https://www.example.com/products")
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.entities.urls, ["https://www.example.com/products"])
        self.assertIn("www.example.com", result.entities.domains)

    def test_ip_address_hostname_is_suspicious(self) -> None:
        result = self.scan("http://192.168.1.10/login")
        self.assertIn("ip_address_hostname", self.codes(result))
        self.assertGreaterEqual(result.risk_score, 20)
        self.assertEqual(result.threat_type, ThreatType.PHISHING)

    def test_shortened_url_is_not_automatically_malicious(self) -> None:
        result = self.scan("https://bit.ly/example")
        self.assertIn("url_shortener", self.codes(result))
        self.assertNotIn(result.threat_type, {ThreatType.MALICIOUS_URL, ThreatType.PHISHING})

    def test_credential_path_is_contextual(self) -> None:
        result = self.scan("https://example.com/account/verify-password")
        self.assertIn("credential_related_path", self.codes(result))
        self.assertGreater(result.risk_score, 0)
        self.assertNotIn(result.threat_type, {ThreatType.MALICIOUS_URL, ThreatType.PHISHING})

    def test_explicit_credentials_are_high_risk(self) -> None:
        result = self.scan("https://user:password@example.com/login")
        self.assertIn("explicit_url_credentials", self.codes(result))
        self.assertGreaterEqual(result.risk_score, 40)
        self.assertNotEqual(result.threat_type, ThreatType.BENIGN)

    def test_suspicious_combination_is_substantially_elevated(self) -> None:
        result = self.scan("http://user:password@paypal-login.secure-check.example:1337/login%2Fverify?redirect=https%3A%2F%2Fevil.example")
        self.assertTrue({"explicit_url_credentials", "brand_like_hostname", "uncommon_port", "credential_related_path"} <= self.codes(result))
        self.assertGreaterEqual(result.risk_score, 70)
        self.assertIn(result.threat_type, {ThreatType.PHISHING, ThreatType.MALICIOUS_URL})

    def test_legitimate_complex_url_is_not_automatically_malicious(self) -> None:
        result = self.scan("https://docs.example.com/products/item?id=123&utm_source=newsletter")
        self.assertNotIn(result.threat_type, {ThreatType.MALICIOUS_URL, ThreatType.PHISHING})

    def test_single_normal_percent_encoding_is_not_obfuscation(self) -> None:
        result = self.scan("https://example.com/search?q=hello%20world")
        self.assertNotIn("encoded_url_structure", self.codes(result))

    def test_invalid_url_returns_a_safe_typed_result(self) -> None:
        result = self.scan("not a valid url")
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertIn("invalid_url", self.codes(result))

    def test_score_and_confidence_are_bounded(self) -> None:
        for url in ["https://example.com", "https://bit.ly/x", "http://192.168.1.10/login"]:
            result = self.scan(url)
            self.assertGreaterEqual(result.risk_score, 0)
            self.assertLessEqual(result.risk_score, 100)
            self.assertGreaterEqual(result.confidence, 0)
            self.assertLessEqual(result.confidence, 1)

    def test_explanation_names_only_detected_signals(self) -> None:
        result = self.scan("http://192.168.1.10/login")
        for signal in result.signals:
            self.assertIn(signal.code.replace("_", " "), result.explanation)
