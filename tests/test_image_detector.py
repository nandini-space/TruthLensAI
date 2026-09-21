import tempfile
import unittest
from pathlib import Path

from PIL import Image

from backend.detection.schemas import InputType, ScanRequest, ThreatType
from backend.detection.text_detector import TextDetector
from backend.detection.utils.image_ocr import OcrResult
from backend.detection.image_detector import ImageDetector


class StubOcr:
    def __init__(self, result: OcrResult) -> None:
        self.result = result
        self.calls = 0

    def extract_text(self, image: object) -> OcrResult:
        self.calls += 1
        return self.result


class ImageDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_image(self, name: str = "sample.png", image_format: str = "PNG") -> str:
        path = self.directory / name
        Image.new("RGB", (320, 120), "white").save(path, format=image_format)
        return str(path)

    def detector_for(self, ocr_result: OcrResult) -> tuple[ImageDetector, StubOcr]:
        ocr = StubOcr(ocr_result)
        return ImageDetector(ocr_engine=ocr), ocr

    def scan(self, detector: ImageDetector, path: str):
        return detector.detect(ScanRequest(input_type=InputType.IMAGE, content=path))

    def test_benign_ocr_text_returns_benign_image_result_with_metadata(self) -> None:
        detector, ocr = self.detector_for(OcrResult(status="success", text="Meeting confirmed for 5 PM today.", confidence=0.91))
        result = self.scan(detector, self.make_image())
        self.assertEqual(result.input_type, InputType.IMAGE)
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(ocr.calls, 1)
        self.assertEqual(result.metadata["image"]["format"], "PNG")
        self.assertEqual(result.metadata["image"]["width"], 320)
        self.assertEqual(result.metadata["image"]["height"], 120)
        self.assertTrue(result.metadata["ocr"]["success"])

    def test_phishing_ocr_text_reuses_text_assessment(self) -> None:
        content = "Your bank account has been suspended. Verify your password immediately."
        detector, _ = self.detector_for(OcrResult(status="success", text=content))
        result = self.scan(detector, self.make_image())
        self.assertEqual(result.input_type, InputType.IMAGE)
        self.assertEqual(result.threat_type, ThreatType.PHISHING)
        self.assertIn("credential_request", {signal.code for signal in result.signals})
        self.assertTrue(result.explanation.startswith("OCR extracted text."))

    def test_ocr_text_url_uses_existing_entity_extraction(self) -> None:
        detector, _ = self.detector_for(OcrResult(status="success", text="Verify at https://example.com/login"))
        result = self.scan(detector, self.make_image())
        self.assertEqual(result.entities.urls, ["https://example.com/login"])
        self.assertIn("example.com", result.entities.domains)

    def test_no_text_is_unknown_not_benign(self) -> None:
        detector, _ = self.detector_for(OcrResult(status="no_text"))
        result = self.scan(detector, self.make_image())
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["assessment_status"], "no_meaningful_text")
        self.assertTrue(result.metadata["ocr"]["attempted"])

    def test_corrupt_image_is_typed_unknown_result(self) -> None:
        path = self.directory / "corrupt.png"
        path.write_bytes(b"not an image")
        detector, _ = self.detector_for(OcrResult(status="success", text="unused"))
        result = self.scan(detector, str(path))
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["assessment_status"], "invalid_input")

    def test_unsupported_format_is_handled_safely(self) -> None:
        detector, _ = self.detector_for(OcrResult(status="success", text="unused"))
        result = self.scan(detector, self.make_image("sample.gif", "GIF"))
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["reason"], "unsupported_image_format")

    def test_ocr_unavailable_is_typed_unknown_result(self) -> None:
        detector, _ = self.detector_for(OcrResult(status="unavailable", error="TesseractNotFoundError"))
        result = self.scan(detector, self.make_image())
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["assessment_status"], "ocr_unavailable")

    def test_text_detector_is_reused_for_ocr_content(self) -> None:
        content = "Send the OTP immediately to confirm your identity."
        detector, _ = self.detector_for(OcrResult(status="success", text=content))
        image_result = self.scan(detector, self.make_image())
        text_result = TextDetector().detect(ScanRequest(input_type=InputType.TEXT, content=content))
        self.assertEqual(image_result.risk_score, text_result.risk_score)
        self.assertEqual(image_result.threat_type, text_result.threat_type)
        self.assertEqual({signal.code for signal in image_result.signals}, {signal.code for signal in text_result.signals})
