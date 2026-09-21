"""Routing layer between normalized inputs and modality detectors."""

from .audio_detector import AudioDetector
from .detector import Detector
from .image_detector import ImageDetector
from .schemas import InputType, ScanRequest, ScanResult
from .text_detector import TextDetector
from .url_detector import UrlDetector
from .video_detector import VideoDetector


class DetectionPipeline:
    """Routes each request to the detector registered for its modality."""

    def __init__(self, detectors: dict[InputType, Detector] | None = None) -> None:
        self._detectors: dict[InputType, Detector] = detectors or {
            InputType.TEXT: TextDetector(),
            InputType.URL: UrlDetector(),
            InputType.IMAGE: ImageDetector(),
            InputType.AUDIO: AudioDetector(),
            InputType.VIDEO: VideoDetector(),
        }

    def scan(self, request: ScanRequest) -> ScanResult:
        return self.detector_for(request.input_type).detect(request)

    def detector_for(self, input_type: InputType) -> Detector:
        """Return the configured detector for an input modality."""
        try:
            return self._detectors[input_type]
        except KeyError as error:
            raise ValueError(f"No detector is configured for {input_type}") from error
