"""Future AI-analysis boundary; no model provider is configured in Stage 1."""

from typing import Protocol

from .schemas import ScanRequest, Signal


class AiAnalyzer(Protocol):
    """Future provider-neutral interface for producing evidence signals."""

    def analyze(self, request: ScanRequest) -> list[Signal]:
        """Return evidence signals without owning final risk classification."""
