"""End-to-end contract validation for Module 1 Stage 10.

Media adapters use deterministic local stubs: Stage 10 verifies routing and
assessment invariants without downloading OCR/STT models or using services.
"""

from __future__ import annotations

import tempfile
import unittest
import wave
from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image

from backend.api.main import create_app
from backend.api.routes.detection import get_pipeline
from backend.detection.ai_analyzer import AIReasoner
from backend.detection.audio_detector import AudioDetector
from backend.detection.config import VideoDetectionConfig
from backend.detection.image_detector import ImageDetector
from backend.detection.multimodal_fusion import MultimodalFusion
from backend.detection.pipeline import DetectionPipeline
from backend.detection.schemas import ExtractedEntities, InputType, ScanRequest, ScanResult, Severity, Signal, ThreatType
from backend.detection.text_detector import TextDetector
from backend.detection.url_detector import UrlDetector
from backend.detection.utils.audio_transcription import TranscriptionResult
from backend.detection.utils.image_ocr import OcrResult
from backend.detection.utils.video_processing import VideoData
from backend.detection.video_detector import VideoDetector
from benchmark.stage10_fixtures import BENIGN_TEXTS, BENIGN_URLS, IMAGE_BENIGN_TEXT, IMAGE_THREAT_TEXT, SUSPICIOUS_URLS, THREAT_TEXTS


class StubOcr:
    def __init__(self, text: str) -> None: self.text = text
    def extract_text(self, image: object) -> OcrResult: return OcrResult(status="success", text=self.text, confidence=1.0)


class StubTranscriber:
    def __init__(self, text: str) -> None: self.text = text
    def transcribe(self, audio: object) -> TranscriptionResult: return TranscriptionResult(status="success", text=self.text, confidence=1.0)


class StubProcessor:
    def __init__(self, path: Path) -> None:
        self.video = VideoData(path, "MP4", 1.0, 64, 64, 1.0, 1, True)
    def inspect(self, path: str, config: VideoDetectionConfig): return self.video, None
    def extract_frames(self, video: VideoData, directory: Path, count: int) -> list[Path]:
        directory.mkdir(parents=True, exist_ok=True)
        paths = [directory / f"frame-{number}.png" for number in range(count)]
        for path in paths: Image.new("RGB", (8, 8), "white").save(path)
        return paths
    def extract_audio(self, video: VideoData, output: Path) -> Path:
        output.write_bytes(b"stub")
        return output


class FailingPipeline:
    def scan(self, request: ScanRequest) -> ScanResult: raise RuntimeError("internal detail must not leak")
    def fuse(self, results: list[ScanResult]) -> ScanResult: raise RuntimeError("internal detail must not leak")


class Stage10ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(self, input_type: InputType, content: str) -> ScanRequest:
        return ScanRequest(input_type=input_type, content=content)

    def assert_contract(self, result: ScanResult) -> None:
        self.assertIn(result.severity, set(Severity))
        self.assertIn(result.threat_type, set(ThreatType))
        if result.risk_score is not None: self.assertGreaterEqual(result.risk_score, 0); self.assertLessEqual(result.risk_score, 100)
        if result.confidence is not None: self.assertGreaterEqual(result.confidence, 0); self.assertLessEqual(result.confidence, 1)
        self.assertTrue(all(signal.code and signal.source and signal.description for signal in result.signals))
        self.assertIsInstance(result.metadata, dict)

    def test_benign_text_and_urls_never_escalate_without_evidence(self) -> None:
        for content in BENIGN_TEXTS:
            result = TextDetector().detect(self.request(InputType.TEXT, content))
            self.assert_contract(result); self.assertNotIn(result.severity, {Severity.HIGH, Severity.CRITICAL})
        for content in BENIGN_URLS:
            result = UrlDetector().detect(self.request(InputType.URL, content))
            self.assert_contract(result); self.assertNotIn(result.severity, {Severity.HIGH, Severity.CRITICAL})

    def test_synthetic_threat_categories_produce_relevant_non_benign_evidence(self) -> None:
        for category, content in THREAT_TEXTS.items():
            result = TextDetector().detect(self.request(InputType.TEXT, content))
            self.assert_contract(result); self.assertNotEqual(result.threat_type, ThreatType.BENIGN, category); self.assertTrue(result.signals, category)
        for content in SUSPICIOUS_URLS:
            result = UrlDetector().detect(self.request(InputType.URL, content))
            self.assert_contract(result); self.assertNotEqual(result.threat_type, ThreatType.BENIGN); self.assertTrue(result.signals)

    def test_url_text_and_fusion_are_reproducible(self) -> None:
        text = THREAT_TEXTS["phishing"]
        url = SUSPICIOUS_URLS[0]
        text_results = [TextDetector().detect(self.request(InputType.TEXT, text)) for _ in range(3)]
        url_results = [UrlDetector().detect(self.request(InputType.URL, url)) for _ in range(3)]
        self.assertTrue(all((r.risk_score, r.threat_type, [s.code for s in r.signals]) == (text_results[0].risk_score, text_results[0].threat_type, [s.code for s in text_results[0].signals]) for r in text_results))
        self.assertTrue(all((r.risk_score, r.threat_type, [s.code for s in r.signals]) == (url_results[0].risk_score, url_results[0].threat_type, [s.code for s in url_results[0].signals]) for r in url_results))
        fused = [MultimodalFusion().fuse([text_results[0], url_results[0]]) for _ in range(3)]
        self.assertTrue(all((r.risk_score, r.threat_type, [s.code for s in r.signals]) == (fused[0].risk_score, fused[0].threat_type, [s.code for s in fused[0].signals]) for r in fused))

    def test_image_and_audio_reuse_text_assessment(self) -> None:
        image = self.directory / "image.png"; Image.new("RGB", (64, 64), "white").save(image)
        audio = self.directory / "audio.wav"
        with wave.open(str(audio), "wb") as opened:
            opened.setnchannels(1); opened.setsampwidth(2); opened.setframerate(8000); opened.writeframes(b"\x00\x00" * 8000)
        benign_image = ImageDetector(ocr_engine=StubOcr(IMAGE_BENIGN_TEXT)).detect(self.request(InputType.IMAGE, str(image)))
        threat_image = ImageDetector(ocr_engine=StubOcr(IMAGE_THREAT_TEXT)).detect(self.request(InputType.IMAGE, str(image)))
        threat_audio = AudioDetector(transcription_engine=StubTranscriber(IMAGE_THREAT_TEXT)).detect(self.request(InputType.AUDIO, str(audio)))
        self.assertEqual(benign_image.threat_type, ThreatType.BENIGN)
        self.assertEqual(threat_image.risk_score, TextDetector().detect(self.request(InputType.TEXT, IMAGE_THREAT_TEXT)).risk_score)
        self.assertEqual(threat_audio.risk_score, threat_image.risk_score)

    def test_video_preserves_child_evidence_and_deduplicates_signals(self) -> None:
        path = self.directory / "video.mp4"; path.write_bytes(b"video")
        image = ImageDetector(ocr_engine=StubOcr(IMAGE_THREAT_TEXT))
        audio = AudioDetector(transcription_engine=StubTranscriber(IMAGE_THREAT_TEXT))
        result = VideoDetector(image_detector=image, audio_detector=audio, processor=StubProcessor(path)).detect(self.request(InputType.VIDEO, str(path)))
        self.assert_contract(result); self.assertEqual(result.metadata["assessment_status"], "completed")
        self.assertEqual(len([signal.code for signal in result.signals]), len(set(signal.code for signal in result.signals)))

    def test_unknown_failures_do_not_become_benign(self) -> None:
        image = self.directory / "bad.png"; image.write_bytes(b"bad")
        audio = self.directory / "bad.wav"; audio.write_bytes(b"bad")
        video = self.directory / "bad.mp4"; video.write_bytes(b"bad")
        for detector, modality, path in ((UrlDetector(), InputType.URL, "not a url"), (ImageDetector(), InputType.IMAGE, str(image)), (AudioDetector(), InputType.AUDIO, str(audio)), (VideoDetector(), InputType.VIDEO, str(video))):
            result = detector.detect(self.request(modality, path))
            self.assertEqual(result.threat_type, ThreatType.UNKNOWN); self.assertNotEqual(result.threat_type, ThreatType.BENIGN)

    def test_ai_reasoning_is_enrichment_only_even_for_hostile_output(self) -> None:
        base = TextDetector().detect(self.request(InputType.TEXT, THREAT_TEXTS["phishing"]))
        class Provider:
            name, model = "local-test", "stub"
            def reason(self, **kwargs): return {"explanation": "safe", "recommendation": "safe", "risk_score": 0, "severity": "low", "threat_type": "benign"}
        result = AIReasoner(provider=Provider()).enrich(base)
        self.assertEqual((result.risk_score, result.severity, result.threat_type), (base.risk_score, base.severity, base.threat_type))
        self.assertEqual(result.metadata["ai_reasoning"]["status"], "completed")

    def test_api_health_input_errors_and_detector_failures_are_safe(self) -> None:
        app = create_app(); app.dependency_overrides[get_pipeline] = lambda: FailingPipeline()
        client = TestClient(app)
        self.assertEqual(client.get("/health").status_code, 200)
        failed = client.post("/scan/text", json={"text": "hello"})
        self.assertEqual(failed.status_code, 500); self.assertNotIn("internal detail", failed.text)
        self.assertEqual(client.post("/scan/text", json={"text": ""}).status_code, 422)
        self.assertEqual(client.post("/scan/image", files={"file": ("bad.gif", b"image", "image/gif")}).status_code, 400)
        self.assertEqual(client.post("/scan/multimodal").status_code, 422)
