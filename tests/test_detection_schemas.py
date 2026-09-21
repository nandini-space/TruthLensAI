import unittest

from pydantic import ValidationError

from backend.detection.schemas import InputType, ScanRequest, ScanResult, Severity, ThreatType


class ScanSchemaTests(unittest.TestCase):
    def test_scan_result_accepts_standard_contract(self) -> None:
        result = ScanResult(
            input_type=InputType.TEXT,
            risk_score=None,
            severity=Severity.UNKNOWN,
            threat_type=ThreatType.UNKNOWN,
            confidence=None,
            explanation="Not assessed.",
            recommendation="No recommendation.",
        )
        self.assertEqual(result.input_type, InputType.TEXT)

    def test_blank_content_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ScanRequest(input_type=InputType.TEXT, content="   ")
