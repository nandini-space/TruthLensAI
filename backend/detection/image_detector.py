"""Local image/screenshot OCR detector that reuses the text detector."""

from .config import ImageDetectionConfig
from .schemas import ExtractedEntities, InputType, ScanRequest, ScanResult, Severity, ThreatType
from .text_detector import TextDetector
from .utils.image_ocr import OcrEngine, OcrResult, TesseractOcrEngine, load_and_preprocess_image


class ImageDetector:
    def __init__(
        self,
        text_detector: TextDetector | None = None,
        ocr_engine: OcrEngine | None = None,
        config: ImageDetectionConfig | None = None,
    ) -> None:
        self._text_detector = text_detector or TextDetector()
        self._ocr_engine = ocr_engine or TesseractOcrEngine()
        self._config = config or ImageDetectionConfig()

    def detect(self, request: ScanRequest) -> ScanResult:
        if request.input_type is not InputType.IMAGE:
            raise ValueError("ImageDetector only accepts image input")
        image_data, validation_error = load_and_preprocess_image(request.content, self._config)
        if image_data is None:
            return self._unassessed_result(request, "invalid_input", validation_error or "invalid_image", ocr_attempted=False)

        ocr_result = self._ocr_engine.extract_text(image_data.image)
        metadata = self._image_metadata(image_data, ocr_result)
        if ocr_result.status != "success":
            status = "no_meaningful_text" if ocr_result.status == "no_text" else f"ocr_{ocr_result.status}"
            return self._unassessed_result(request, status, ocr_result.error or ocr_result.status, metadata=metadata, ocr_attempted=True)

        text_result = self._text_detector.detect(
            ScanRequest(scan_id=request.scan_id, input_type=InputType.TEXT, content=ocr_result.text)
        )
        metadata.update({"assessment_status": "completed", "ocr_text_length": len(ocr_result.text)})
        return text_result.model_copy(
            update={
                "input_type": InputType.IMAGE,
                "explanation": f"OCR extracted text. {text_result.explanation}",
                "metadata": metadata,
            }
        )

    @staticmethod
    def _image_metadata(image_data: object, ocr_result: OcrResult) -> dict[str, object]:
        return {
            "detector": "local_ocr_image_v1",
            "image": {
                "format": image_data.image_format, "width": image_data.width, "height": image_data.height,
                "preprocessing": image_data.preprocessing,
            },
            "ocr": {
                "attempted": True, "status": ocr_result.status,
                "success": ocr_result.status == "success", "confidence": ocr_result.confidence,
            },
        }

    @staticmethod
    def _unassessed_result(
        request: ScanRequest,
        status: str,
        reason: str,
        metadata: dict[str, object] | None = None,
        ocr_attempted: bool = False,
    ) -> ScanResult:
        result_metadata = metadata or {
            "detector": "local_ocr_image_v1",
            "image": {"format": None, "width": None, "height": None, "preprocessing": "not_started"},
            "ocr": {"attempted": ocr_attempted, "status": "not_attempted", "success": False, "confidence": None},
        }
        result_metadata.update({"assessment_status": status, "image_input": request.content, "reason": reason})
        return ScanResult(
            scan_id=request.scan_id, input_type=InputType.IMAGE, risk_score=None, severity=Severity.UNKNOWN,
            threat_type=ThreatType.UNKNOWN, confidence=None, signals=[],
            explanation="Image text could not be assessed, so no threat determination was made.",
            recommendation="Treat the image cautiously and verify any request through an independent source.",
            entities=ExtractedEntities(), metadata=result_metadata,
        )
