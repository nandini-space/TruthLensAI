import unittest

from backend.detection.detector import Detector
from backend.detection.pipeline import DetectionPipeline
from backend.detection.schemas import InputType, ScanRequest
from backend.detection.text_detector import TextDetector


class DetectorInterfaceTests(unittest.TestCase):
    def test_registered_detectors_conform_to_detector_protocol(self) -> None:
        pipeline = DetectionPipeline()
        for input_type in InputType:
            with self.subTest(input_type=input_type):
                detector = pipeline.detector_for(input_type)
                self.assertIsInstance(detector, Detector)

    def test_text_detector_returns_a_result(self) -> None:
        self.assertIsNotNone(TextDetector().detect(ScanRequest(input_type=InputType.TEXT, content="example")))
