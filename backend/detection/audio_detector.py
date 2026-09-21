"""Local audio detector that transcribes speech then reuses the text detector."""

from .config import AudioDetectionConfig
from .schemas import ExtractedEntities, InputType, ScanRequest, ScanResult, Severity, ThreatType
from .text_detector import TextDetector
from .utils.audio_transcription import (
    AudioData,
    FasterWhisperTranscriber,
    SpeechToTextEngine,
    TranscriptionResult,
    load_audio_metadata,
)


class AudioDetector:
    def __init__(
        self,
        text_detector: TextDetector | None = None,
        transcription_engine: SpeechToTextEngine | None = None,
        config: AudioDetectionConfig | None = None,
    ) -> None:
        self._text_detector = text_detector or TextDetector()
        self._config = config or AudioDetectionConfig()
        self._transcription_engine = transcription_engine or FasterWhisperTranscriber(self._config)

    def detect(self, request: ScanRequest) -> ScanResult:
        if request.input_type is not InputType.AUDIO:
            raise ValueError("AudioDetector only accepts audio input")
        audio, validation_error = load_audio_metadata(request.content, self._config)
        if audio is None:
            return self._unassessed_result(request, "invalid_input", validation_error or "invalid_audio")

        transcription = self._transcription_engine.transcribe(audio)
        metadata = self._audio_metadata(audio, transcription)
        if transcription.status != "success":
            status = "no_speech" if transcription.status == "no_speech" else f"transcription_{transcription.status}"
            return self._unassessed_result(request, status, transcription.error or transcription.status, metadata)

        text_result = self._text_detector.detect(
            ScanRequest(scan_id=request.scan_id, input_type=InputType.TEXT, content=transcription.text)
        )
        metadata.update({"assessment_status": "completed", "transcript_length": len(transcription.text)})
        return text_result.model_copy(
            update={
                "input_type": InputType.AUDIO,
                "explanation": f"Speech-to-text extracted a transcript. {text_result.explanation}",
                "metadata": metadata,
            }
        )

    @staticmethod
    def _audio_metadata(audio: AudioData, transcription: TranscriptionResult) -> dict[str, object]:
        return {
            "detector": "local_speech_to_text_audio_v1",
            "audio": {
                "format": audio.audio_format,
                "duration_seconds": audio.duration_seconds,
                "sample_rate": audio.sample_rate,
                "channels": audio.channels,
                "preprocessing": audio.preprocessing,
            },
            "transcription": {
                "attempted": True,
                "status": transcription.status,
                "success": transcription.status == "success",
                "confidence": transcription.confidence,
            },
        }

    @staticmethod
    def _unassessed_result(
        request: ScanRequest,
        status: str,
        reason: str,
        metadata: dict[str, object] | None = None,
    ) -> ScanResult:
        result_metadata = metadata or {
            "detector": "local_speech_to_text_audio_v1",
            "audio": {"format": None, "duration_seconds": None, "sample_rate": None, "channels": None, "preprocessing": "not_started"},
            "transcription": {"attempted": False, "status": "not_attempted", "success": False, "confidence": None},
        }
        result_metadata.update({"assessment_status": status, "audio_input": request.content, "reason": reason})
        return ScanResult(
            scan_id=request.scan_id,
            input_type=InputType.AUDIO,
            risk_score=None,
            severity=Severity.UNKNOWN,
            threat_type=ThreatType.UNKNOWN,
            confidence=None,
            signals=[],
            explanation="Audio speech could not be assessed, so no threat determination was made.",
            recommendation="Treat the audio cautiously and verify any request through an independent source.",
            entities=ExtractedEntities(),
            metadata=result_metadata,
        )
