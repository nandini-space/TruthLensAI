"""Local image validation, conservative preprocessing, and OCR boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..config import ImageDetectionConfig


@dataclass(frozen=True, slots=True)
class ImageData:
    image: object
    image_format: str
    width: int
    height: int
    preprocessing: str


@dataclass(frozen=True, slots=True)
class OcrResult:
    status: str
    text: str = ""
    confidence: float | None = None
    error: str | None = None


class OcrEngine(Protocol):
    def extract_text(self, image: object) -> OcrResult:
        """Extract text locally without using a cloud service."""


def load_and_preprocess_image(path_value: str, config: ImageDetectionConfig) -> tuple[ImageData | None, str | None]:
    """Validate supported local images and apply a reversible OCR-oriented transform."""
    path = Path(path_value)
    if not path.is_file():
        return None, "image_file_not_found"
    if path.stat().st_size > config.max_file_bytes:
        return None, "image_file_too_large"
    try:
        from PIL import Image, ImageOps

        with Image.open(path) as opened:
            image_format = (opened.format or "").upper()
            if image_format not in config.allowed_formats:
                return None, "unsupported_image_format"
            width, height = opened.size
            if width * height > config.max_pixels:
                return None, "image_dimensions_too_large"
            image = opened.convert("RGB")
        # Grayscale and autocontrast improve OCR for typical screenshots without altering the source file.
        processed = ImageOps.autocontrast(image.convert("L"))
        return ImageData(processed, image_format, width, height, "grayscale_autocontrast"), None
    except (OSError, ValueError):
        return None, "invalid_or_corrupt_image"


class TesseractOcrEngine:
    """Optional local Tesseract adapter; absence is represented as a typed result."""

    def extract_text(self, image: object) -> OcrResult:
        try:
            import pytesseract

            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            tokens = [token.strip() for token in data.get("text", []) if token.strip()]
            confidences = [float(value) for value in data.get("conf", []) if str(value).replace(".", "", 1).isdigit() and float(value) >= 0]
            text = " ".join(tokens)
            if not text:
                return OcrResult(status="no_text")
            confidence = round(sum(confidences) / len(confidences) / 100, 2) if confidences else None
            return OcrResult(status="success", text=text, confidence=confidence)
        except ImportError:
            return OcrResult(status="unavailable", error="pytesseract is not installed")
        except Exception as error:  # The wrapper exposes engine-not-found and image errors as exceptions.
            error_name = type(error).__name__
            status = "unavailable" if error_name == "TesseractNotFoundError" else "failed"
            return OcrResult(status=status, error=error_name)
