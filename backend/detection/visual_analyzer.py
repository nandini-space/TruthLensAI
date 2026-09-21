"""Future extension point for deterministic image-only signals."""

from typing import Protocol

from .schemas import Signal


class VisualSignalAnalyzer(Protocol):
    """Future implementations may return evidence-backed visual signals."""

    def analyze(self, image: object) -> list[Signal]:
        """Analyze an image without changing OCR-derived text assessment behavior."""
