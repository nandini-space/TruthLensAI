import tempfile
import unittest
import wave
from pathlib import Path

from backend.detection.audio_detector import AudioDetector
from backend.detection.pipeline import DetectionPipeline
from backend.detection.schemas import InputType, ScanRequest, ThreatType
from backend.detection.text_detector import TextDetector
from backend.detection.utils.audio_transcription import TranscriptionResult


class StubTranscriber:
    def __init__(self, result: TranscriptionResult) -> None:
        self.result = result
        self.calls = 0

    def transcribe(self, audio: object) -> TranscriptionResult:
        self.calls += 1
        return self.result


class AudioDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_wav(self, name: str = "sample.wav") -> str:
        path = self.directory / name
        with wave.open(str(path), "wb") as opened:
            opened.setnchannels(1)
            opened.setsampwidth(2)
            opened.setframerate(16_000)
            opened.writeframes(b"\x00\x00" * 16_000)
        return str(path)

    def detector_for(self, result: TranscriptionResult) -> tuple[AudioDetector, StubTranscriber]:
        transcriber = StubTranscriber(result)
        return AudioDetector(transcription_engine=transcriber), transcriber

    def scan(self, detector: AudioDetector, path: str):
        return detector.detect(ScanRequest(input_type=InputType.AUDIO, content=path))

    def test_valid_wav_is_transcribed_and_metadata_is_populated(self) -> None:
        detector, transcriber = self.detector_for(TranscriptionResult(status="success", text="Meeting confirmed for 5 PM today.", confidence=0.91))
        result = self.scan(detector, self.make_wav())
        self.assertEqual(transcriber.calls, 1)
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
        self.assertEqual(result.metadata["audio"]["format"], "WAV")
        self.assertEqual(result.metadata["audio"]["sample_rate"], 16_000)
        self.assertEqual(result.metadata["audio"]["channels"], 1)
        self.assertEqual(result.metadata["audio"]["duration_seconds"], 1.0)
        self.assertEqual(result.metadata["transcription"]["confidence"], 0.91)

    def test_corrupt_audio_is_typed_unknown_result(self) -> None:
        path = self.directory / "corrupt.wav"
        path.write_bytes(b"not audio")
        detector, transcriber = self.detector_for(TranscriptionResult(status="success", text="unused"))
        result = self.scan(detector, str(path))
        self.assertEqual(transcriber.calls, 0)
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["assessment_status"], "invalid_input")
        self.assertEqual(result.metadata["reason"], "invalid_or_corrupt_audio")

    def test_unsupported_format_is_handled_safely(self) -> None:
        path = self.directory / "sample.ogg"
        path.write_bytes(b"audio")
        detector, _ = self.detector_for(TranscriptionResult(status="success", text="unused"))
        result = self.scan(detector, str(path))
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["reason"], "unsupported_audio_format")

    def test_transcription_unavailable_is_typed_unknown_result(self) -> None:
        detector, _ = self.detector_for(TranscriptionResult(status="unavailable", error="local_transcription_model_not_configured"))
        result = self.scan(detector, self.make_wav())
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["assessment_status"], "transcription_unavailable")
        self.assertTrue(result.metadata["transcription"]["attempted"])

    def test_no_speech_is_typed_unknown_result(self) -> None:
        detector, _ = self.detector_for(TranscriptionResult(status="no_speech"))
        result = self.scan(detector, self.make_wav())
        self.assertEqual(result.threat_type, ThreatType.UNKNOWN)
        self.assertEqual(result.metadata["assessment_status"], "no_speech")

    def test_phishing_transcript_reuses_text_assessment(self) -> None:
        content = "Your bank account has been suspended. Verify your password immediately."
        detector, _ = self.detector_for(TranscriptionResult(status="success", text=content))
        audio_result = self.scan(detector, self.make_wav())
        text_result = TextDetector().detect(ScanRequest(input_type=InputType.TEXT, content=content))
        self.assertEqual(audio_result.threat_type, ThreatType.PHISHING)
        self.assertEqual(audio_result.risk_score, text_result.risk_score)
        self.assertEqual({item.code for item in audio_result.signals}, {item.code for item in text_result.signals})
        self.assertTrue(audio_result.explanation.startswith("Speech-to-text extracted a transcript."))

    def test_benign_transcript_reuses_text_assessment(self) -> None:
        content = "Meeting confirmed for 5 PM today."
        detector, _ = self.detector_for(TranscriptionResult(status="success", text=content))
        audio_result = self.scan(detector, self.make_wav())
        text_result = TextDetector().detect(ScanRequest(input_type=InputType.TEXT, content=content))
        self.assertEqual(audio_result.threat_type, ThreatType.BENIGN)
        self.assertEqual(audio_result.risk_score, text_result.risk_score)

    def test_pipeline_routes_audio_to_audio_detector(self) -> None:
        detector, _ = self.detector_for(TranscriptionResult(status="success", text="Meeting confirmed for 5 PM today."))
        pipeline = DetectionPipeline(detectors={InputType.AUDIO: detector})
        result = pipeline.scan(ScanRequest(input_type=InputType.AUDIO, content=self.make_wav()))
        self.assertEqual(result.input_type, InputType.AUDIO)
        self.assertEqual(result.threat_type, ThreatType.BENIGN)
