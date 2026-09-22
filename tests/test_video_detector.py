import tempfile
import unittest
from pathlib import Path

from backend.detection.config import VideoDetectionConfig
from backend.detection.schemas import ExtractedEntities, InputType, ScanRequest, ScanResult, Severity, Signal, ThreatType
from backend.detection.video_detector import VideoDetector
from backend.detection.utils.video_processing import VideoData


def completed_result(input_type: InputType, score: float, threat: ThreatType, signal: str | None = None) -> ScanResult:
    signals = [] if signal is None else [Signal(code=signal, description=signal, source="stub")]
    return ScanResult(
        input_type=input_type, risk_score=score, severity=Severity.HIGH if score >= 40 else Severity.LOW,
        threat_type=threat, confidence=0.8, signals=signals, explanation="Stub assessment.",
        recommendation="Stub recommendation.", entities=ExtractedEntities(), metadata={"assessment_status": "completed"},
    )


class StubDetector:
    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self.requests: list[ScanRequest] = []

    def detect(self, request: ScanRequest) -> ScanResult:
        self.requests.append(request)
        return self.result


class StubProcessor:
    def __init__(self, video: VideoData | None, error: str | None = None) -> None:
        self.video = video
        self.error = error
        self.frame_count_requested: int | None = None
        self.frames_extracted = 0
        self.audio_extracted = False

    def inspect(self, path: str, config: VideoDetectionConfig):
        return self.video, self.error

    def extract_frames(self, video: VideoData, directory: Path, count: int) -> list[Path]:
        self.frame_count_requested = count
        directory.mkdir(parents=True, exist_ok=True)
        paths = [directory / f"frame_{index}.png" for index in range(count)]
        for path in paths:
            path.write_bytes(b"frame")
        self.frames_extracted = len(paths)
        return paths

    def extract_audio(self, video: VideoData, output_path: Path) -> Path | None:
        self.audio_extracted = True
        output_path.write_bytes(b"audio")
        return output_path


class VideoDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "sample.mp4"
        self.path.write_bytes(b"video")
        self.video = VideoData(self.path, "MP4", 12.0, 1280, 720, 30.0, 360, True)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def detector(self, processor: StubProcessor, image: StubDetector | None = None, audio: StubDetector | None = None, config: VideoDetectionConfig | None = None) -> VideoDetector:
        return VideoDetector(
            image_detector=image or StubDetector(completed_result(InputType.IMAGE, 0, ThreatType.BENIGN)),
            audio_detector=audio or StubDetector(completed_result(InputType.AUDIO, 0, ThreatType.BENIGN)),
            processor=processor,
            config=config,
        )

    def scan(self, detector: VideoDetector):
        return detector.detect(ScanRequest(input_type=InputType.VIDEO, content=str(self.path)))

    def test_valid_video_metadata_and_final_result(self) -> None:
        processor = StubProcessor(self.video)
        result = self.scan(self.detector(processor))
        self.assertEqual(result.input_type, InputType.VIDEO)
        self.assertEqual(result.metadata["video"]["format"], "MP4")
        self.assertEqual(result.metadata["video"]["width"], 1280)
        self.assertTrue(result.metadata["video"]["audio_present"])
        self.assertEqual(result.metadata["assessment_status"], "completed")

    def test_representative_frames_route_to_existing_image_detector(self) -> None:
        processor = StubProcessor(self.video)
        image = StubDetector(completed_result(InputType.IMAGE, 8, ThreatType.UNKNOWN, "urgency"))
        self.scan(self.detector(processor, image=image, config=VideoDetectionConfig(representative_frame_count=3)))
        self.assertEqual(processor.frame_count_requested, 3)
        self.assertEqual(len(image.requests), 3)
        self.assertTrue(all(request.input_type is InputType.IMAGE for request in image.requests))

    def test_audio_is_extracted_and_routed_to_existing_audio_detector(self) -> None:
        processor = StubProcessor(self.video)
        audio = StubDetector(completed_result(InputType.AUDIO, 8, ThreatType.UNKNOWN, "urgency"))
        self.scan(self.detector(processor, audio=audio))
        self.assertTrue(processor.audio_extracted)
        self.assertEqual(len(audio.requests), 1)
        self.assertIs(audio.requests[0].input_type, InputType.AUDIO)

    def test_video_without_audio_continues_gracefully(self) -> None:
        processor = StubProcessor(VideoData(self.path, "MP4", 12.0, 1280, 720, 30.0, 360, False))
        audio = StubDetector(completed_result(InputType.AUDIO, 8, ThreatType.UNKNOWN))
        result = self.scan(self.detector(processor, audio=audio))
        self.assertFalse(processor.audio_extracted)
        self.assertEqual(len(audio.requests), 0)
        self.assertEqual(result.metadata["audio"]["reason"], "no_audio_stream")

    def test_evidence_aggregation_uses_highest_score_and_corroboration(self) -> None:
        processor = StubProcessor(self.video)
        image = StubDetector(completed_result(InputType.IMAGE, 55, ThreatType.PHISHING, "credential_request"))
        audio = StubDetector(completed_result(InputType.AUDIO, 8, ThreatType.UNKNOWN, "urgency"))
        result = self.scan(self.detector(processor, image=image, audio=audio))
        self.assertEqual(result.risk_score, 60)
        self.assertEqual(result.severity, Severity.HIGH)
        self.assertEqual(result.threat_type, ThreatType.PHISHING)
        self.assertTrue(result.metadata["aggregation"]["corroborated"])
        self.assertEqual({signal.code for signal in result.signals}, {"credential_request", "urgency"})

    def test_processing_dependency_unavailable_is_unknown(self) -> None:
        result = self.scan(self.detector(StubProcessor(None, "video_processing_unavailable")))
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["assessment_status"], "invalid_input")
        self.assertEqual(result.metadata["reason"], "video_processing_unavailable")

    def test_corrupt_video_is_unknown(self) -> None:
        corrupt = VideoDetector()
        result = corrupt.detect(ScanRequest(input_type=InputType.VIDEO, content=str(self.path)))
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["reason"], "invalid_or_corrupt_video")

    def test_unsupported_video_is_unknown(self) -> None:
        path = Path(self.tempdir.name) / "sample.ogv"
        path.write_bytes(b"video")
        result = VideoDetector().detect(ScanRequest(input_type=InputType.VIDEO, content=str(path)))
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["reason"], "unsupported_video_format")
