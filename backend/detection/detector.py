"""Common detector interface for all input modalities."""

from typing import Protocol, runtime_checkable

from .schemas import ScanRequest, ScanResult


@runtime_checkable
class Detector(Protocol):
    """A modality-specific detector that preserves the common result contract."""

    def detect(self, request: ScanRequest) -> ScanResult:
        """Analyze a normalized request and return a validated result."""
