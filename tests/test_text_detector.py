import unittest

from backend.detection.schemas import InputType, ScanRequest, Severity, ThreatType
from backend.detection.text_detector import TextDetector


class TextDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = TextDetector()

    def scan(self, content: str):
        return self.detector.detect(ScanRequest(input_type=InputType.TEXT, content=content))

    def codes(self, result) -> set[str]:
        return {signal.code for signal in result.signals}

    def test_benign_message_has_low_risk_and_no_entities(self) -> None:
        result = self.scan("Hi, are we still meeting at 5 PM today?")
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(result.risk_score, 0)
        self.assertFalse(result.signals)
        self.assertEqual(result.entities.model_dump(), {"urls": [], "domains": [], "email_addresses": [], "phone_numbers": [], "usernames": [], "indicators": []})

    def test_credential_phishing_is_classified_from_combined_evidence(self) -> None:
        result = self.scan("Your bank account has been suspended. Verify your password immediately using this link.")
        self.assertTrue({"credential_request", "urgency", "account_verification"} <= self.codes(result))
        self.assertEqual(result.threat_type, ThreatType.PHISHING)
        self.assertGreaterEqual(result.risk_score, 40)

    def test_otp_scam_pattern_is_elevated(self) -> None:
        result = self.scan("Your account will be blocked today. Send the OTP you received to confirm your identity.")
        self.assertTrue({"otp_request", "urgency", "account_verification"} <= self.codes(result))
        self.assertIn(result.threat_type, {ThreatType.PHISHING, ThreatType.SOCIAL_ENGINEERING})
        self.assertGreaterEqual(result.risk_score, 40)

    def test_prize_scam_pattern_is_elevated(self) -> None:
        result = self.scan("Congratulations! You won ₹5,00,000. Pay the processing fee immediately to claim your prize.")
        self.assertTrue({"prize_claim", "financial_request", "urgency"} <= self.codes(result))
        self.assertEqual(result.threat_type, ThreatType.SCAM)
        self.assertGreaterEqual(result.risk_score, 40)

    def test_safe_synthetic_blackmail_pattern_is_harassment(self) -> None:
        result = self.scan("Pay now or we will expose private messages unless you comply.")
        self.assertIn("threat", self.codes(result))
        self.assertEqual(result.threat_type, ThreatType.HARASSMENT)
        self.assertGreaterEqual(result.risk_score, 40)

    def test_ordinary_account_payment_and_verify_words_are_not_malicious(self) -> None:
        result = self.scan("Please verify the payment amount on your account statement before our meeting.")
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(result.risk_score, 0)

    def test_entities_are_extracted_without_external_lookup(self) -> None:
        result = self.scan("Visit https://example.com/login, email help@example.org, or call +91 98765 43210.")
        self.assertEqual(result.entities.urls, ["https://example.com/login"])
        self.assertIn("example.com", result.entities.domains)
        self.assertEqual(result.entities.email_addresses, ["help@example.org"])
        self.assertEqual(result.entities.phone_numbers, ["+91 98765 43210"])

    def test_explanation_only_names_detected_signals(self) -> None:
        result = self.scan("Send the OTP immediately to confirm your identity.")
        for signal in result.signals:
            self.assertIn(signal.code.replace("_", " "), result.explanation)
            self.assertIn("evidence", signal.details)

    def test_score_and_confidence_are_bounded(self) -> None:
        for content in [
            "Hi there.",
            "Send the OTP immediately to confirm your identity.",
            "Congratulations, you won. Pay the processing fee immediately.",
        ]:
            result = self.scan(content)
            self.assertGreaterEqual(result.risk_score, 0)
            self.assertLessEqual(result.risk_score, 100)
            self.assertGreaterEqual(result.confidence, 0)
            self.assertLessEqual(result.confidence, 1)
