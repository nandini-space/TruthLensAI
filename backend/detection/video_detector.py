"""Video orchestration that reuses existing image and audio detectors."""

import tempfile
from pathlib import Path

from .audio_detector import AudioDetector
from .config import TextRiskConfig, VideoDetectionConfig
from .image_detector import ImageDetector
from .schemas import ExtractedEntities, InputType, ScanRequest, ScanResult, Severity, Signal, ThreatType
from .utils.video_processing import PyAvVideoProcessor, VideoData


class VideoDetector:
    def __init__(
        self,
        image_detector: ImageDetector | None = None,
        audio_detector: AudioDetector | None = None,
        processor: PyAvVideoProcessor | None = None,
        config: VideoDetectionConfig | None = None,
    ) -> None:
        self._image_detector = image_detector or ImageDetector()
        self._audio_detector = audio_detector or AudioDetector()
        self._processor = processor or PyAvVideoProcessor()
        self._config = config or VideoDetectionConfig()

    def detect(self, request: ScanRequest) -> ScanResult:
        if request.input_type is not InputType.VIDEO:
            raise ValueError("VideoDetector only accepts video input")
        video, error = self._processor.inspect(request.content, self._config)
        if video is None:
            return self._unknown(request, "invalid_input", error or "invalid_video")

        with tempfile.TemporaryDirectory(prefix="truthlens_video_") as directory:
            temporary = Path(directory)
            try:
                frame_paths = self._processor.extract_frames(video, temporary / "frames", self._config.representative_frame_count)
            except Exception as extraction_error:
                return self._unknown(request, "frame_extraction_failed", type(extraction_error).__name__, video)
            frame_results = [self._image_detector.detect(ScanRequest(input_type=InputType.IMAGE, content=str(path))) for path in frame_paths]

            audio_result = None
            audio_error = None
            if video.audio_present:
                try:
                    audio_path = self._processor.extract_audio(video, temporary / "audio.wav")
                    if audio_path is not None:
                        audio_result = self._audio_detector.detect(ScanRequest(input_type=InputType.AUDIO, content=str(audio_path)))
                except Exception as extraction_error:
                    audio_error = type(extraction_error).__name__
        return self._aggregate(request, video, frame_results, audio_result, audio_error)

    def _aggregate(self, request: ScanRequest, video: VideoData, frames: list[ScanResult], audio: ScanResult | None, audio_error: str | None) -> ScanResult:
        children = [result for result in [*frames, audio] if result is not None and result.metadata.get("assessment_status") == "completed"]
        metadata = {
            "detector": "local_video_orchestrator_v1",
            "video": {
                "format": video.video_format, "duration_seconds": video.duration_seconds,
                "width": video.width, "height": video.height, "fps": video.fps,
                "frame_count": video.frame_count, "audio_present": video.audio_present,
            },
            "frames": [self._child_summary(result) for result in frames],
            "audio": self._child_summary(audio) if audio else {"analyzed": False, "reason": audio_error or ("no_audio_stream" if not video.audio_present else "audio_not_extracted")},
        }
        if not children:
            return self._unknown(request, "no_assessable_evidence", "no_completed_child_analysis", video, metadata)

        highest = max(children, key=lambda result: result.risk_score or 0)
        visual_risk = any((result.risk_score or 0) > 0 for result in frames if result.metadata.get("assessment_status") == "completed")
        audio_risk = audio is not None and audio.metadata.get("assessment_status") == "completed" and (audio.risk_score or 0) > 0
        corroborated = visual_risk and audio_risk
        score = min(100.0, (highest.risk_score or 0) + (self._config.corroboration_bonus if corroborated else 0))
        confidence = min(1.0, (highest.confidence or 0) + (0.05 if corroborated else 0))
        signals = self._unique_signals(children)
        metadata.update({"assessment_status": "completed", "aggregation": {"method": "highest_child_risk_with_corroboration_bonus", "corroborated": corroborated, "corroboration_bonus": self._config.corroboration_bonus if corroborated else 0}})
        return ScanResult(
            scan_id=request.scan_id, input_type=InputType.VIDEO, risk_score=score,
            severity=self._severity(score), threat_type=highest.threat_type, confidence=round(confidence, 2),
            signals=signals, explanation=f"Video analysis combined {len(frames)} frame result(s) and {'an audio result' if audio else 'no audio result'}. {highest.explanation}",
            recommendation=highest.recommendation, entities=self._entities(children), metadata=metadata,
        )

    @staticmethod
    def _child_summary(result: ScanResult | None) -> dict[str, object]:
        if result is None:
            return {"analyzed": False}
        return {"analyzed": True, "assessment_status": result.metadata.get("assessment_status"), "risk_score": result.risk_score, "severity": result.severity.value, "threat_type": result.threat_type.value, "signals": [signal.code for signal in result.signals]}

    @staticmethod
    def _unique_signals(results: list[ScanResult]) -> list[Signal]:
        observed: dict[str, Signal] = {}
        for result in results:
            for signal in result.signals:
                observed.setdefault(signal.code, signal)
        return list(observed.values())

    @staticmethod
    def _entities(results: list[ScanResult]) -> ExtractedEntities:
        def merge(attribute: str) -> list[str]:
            return list(dict.fromkeys(value for result in results for value in getattr(result.entities, attribute)))
        indicators = list({(item.value, item.kind, item.context): item for result in results for item in result.entities.indicators}.values())
        return ExtractedEntities(urls=merge("urls"), domains=merge("domains"), email_addresses=merge("email_addresses"), phone_numbers=merge("phone_numbers"), usernames=merge("usernames"), indicators=indicators)

    @staticmethod
    def _severity(score: float) -> Severity:
        config = TextRiskConfig()
        if score >= config.critical_threshold:
            return Severity.CRITICAL
        if score >= config.high_threshold:
            return Severity.HIGH
        if score >= config.moderate_threshold:
            return Severity.MODERATE
        return Severity.LOW

    @staticmethod
    def _unknown(request: ScanRequest, status: str, reason: str, video: VideoData | None = None, metadata: dict[str, object] | None = None) -> ScanResult:
        result_metadata = metadata or {"detector": "local_video_orchestrator_v1", "video": {"format": video.video_format if video else None, "duration_seconds": video.duration_seconds if video else None, "width": video.width if video else None, "height": video.height if video else None, "fps": video.fps if video else None, "frame_count": video.frame_count if video else None, "audio_present": video.audio_present if video else None}}
        result_metadata.update({"assessment_status": status, "video_input": request.content, "reason": reason})
        return ScanResult(scan_id=request.scan_id, input_type=InputType.VIDEO, risk_score=None, severity=Severity.UNKNOWN, threat_type=ThreatType.UNKNOWN, confidence=None, signals=[], explanation="Video evidence could not be assessed, so no threat determination was made.", recommendation="Treat the video cautiously and verify any request through an independent source.", entities=ExtractedEntities(), metadata=result_metadata)
