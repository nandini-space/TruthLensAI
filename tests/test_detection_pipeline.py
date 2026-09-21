import unittest

from backend.detection.pipeline import DetectionPipeline
from backend.detection.schemas import InputType, ScanRequest, Severity, ThreatType


class PipelineRoutingTests(unittest.TestCase):
    def test_each_modality_routes_to_a_valid_result(self) -> None:
        pipeline = DetectionPipeline()
        for input_type in InputType:
            with self.subTest(input_type=input_type):
                result = pipeline.scan(ScanRequest(input_type=input_type, content="example"))
                self.assertEqual(result.input_type, input_type)
                if input_type is InputType.TEXT:
                    self.assertEqual(result.threat_type, ThreatType.BENIGN)
                    self.assertEqual(result.severity, Severity.LOW)
                    self.assertEqual(result.metadata["assessment_status"], "completed")
                else:
                    self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
                    self.assertEqual(result.severity, Severity.UNKNOWN)
                    self.assertIsNone(result.risk_score)
                    self.assertEqual(result.metadata["assessment_status"], "not_implemented")
