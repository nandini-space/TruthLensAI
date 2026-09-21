"""URL detector boundary; URL reputation and analysis are intentionally deferred."""

from .risk_engine import RiskEngine
from .schemas import InputType, ScanRequest, ScanResult


class UrlDetector:
    def __init__(self, risk_engine: RiskEngine | None = None) -> None:
        self._risk_engine = risk_engine or RiskEngine()

    def detect(self, request: ScanRequest) -> ScanResult:
        if request.input_type is not InputType.URL:
            raise ValueError("UrlDetector only accepts URL input")
        return self._risk_engine.unassessed_result(scan_id=request.scan_id, input_type=request.input_type)
