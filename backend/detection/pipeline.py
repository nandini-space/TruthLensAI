"""Routing layer between normalized inputs and modality detectors."""

from .audio_detector import AudioDetector
from .ai_analyzer import AIReasoner
from .detector import Detector
from .image_detector import ImageDetector
from .multimodal_fusion import MultimodalFusion
from .schemas import InputType, ScanRequest, ScanResult
from .text_detector import TextDetector
from .url_detector import UrlDetector
from .video_detector import VideoDetector


class DetectionPipeline:
    """Routes each request to the detector registered for its modality."""

    def __init__(self, detectors: dict[InputType, Detector] | None = None, ai_reasoner: AIReasoner | None = None) -> None:
        self._detectors: dict[InputType, Detector] = detectors or {
            InputType.TEXT: TextDetector(),
            InputType.URL: UrlDetector(),
            InputType.IMAGE: ImageDetector(),
            InputType.AUDIO: AudioDetector(),
            InputType.VIDEO: VideoDetector(),
        }
        self._ai_reasoner = ai_reasoner or AIReasoner()
        self._fusion = MultimodalFusion()

    def scan(self, request: ScanRequest) -> ScanResult:
        return self._ai_reasoner.enrich(self.detector_for(request.input_type).detect(request))

    def detector_for(self, input_type: InputType) -> Detector:
        """Return the configured detector for an input modality."""
        try:
            return self._detectors[input_type]
        except KeyError as error:
            raise ValueError(f"No detector is configured for {input_type}") from error

    def fuse(self, results: list[ScanResult]) -> ScanResult:
        """Fuse already-produced detector results, then apply optional AI enrichment."""
        return self._ai_reasoner.enrich(self._fusion.fuse(results))
