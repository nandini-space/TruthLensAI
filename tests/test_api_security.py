"""Focused integration checks for HTTP boundary safeguards."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from backend.api.main import create_app
from backend.api.routes.detection import get_pipeline
from backend.detection.config import ApiConfig
from backend.detection.schemas import InputType, ScanRequest, ScanResult, Severity, ThreatType


class StubPipeline:
    def scan(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            scan_id=request.scan_id, input_type=InputType.TEXT, risk_score=0,
            severity=Severity.LOW, threat_type=ThreatType.BENIGN, confidence=1,
            explanation="No threat signals were detected.", recommendation="No action required.",
        )


class ApiSecurityTests(unittest.TestCase):
    def client(self, config: ApiConfig) -> TestClient:
        app = create_app(config)
        app.dependency_overrides[get_pipeline] = StubPipeline
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app)

    def test_private_url_is_rejected_before_pipeline(self) -> None:
        client = self.client(ApiConfig())
        self.assertEqual(client.post("/scan/url", json={"url": "http://127.0.0.1/admin"}).status_code, 422)
        self.assertEqual(client.post("/scan/url", json={"url": "http://localhost/admin"}).status_code, 422)

    def test_optional_service_key_protects_non_health_routes(self) -> None:
        client = self.client(ApiConfig(api_key="test-key"))
        self.assertEqual(client.get("/health").status_code, 200)
        self.assertEqual(client.post("/scan/text", json={"text": "hello"}).status_code, 401)
        self.assertEqual(client.post("/scan/text", json={"text": "hello"}, headers={"X-TruthLens-API-Key": "test-key"}).status_code, 200)

    def test_rate_limit_and_readiness_are_safe(self) -> None:
        client = self.client(ApiConfig(rate_limit_per_minute=1))
        self.assertEqual(client.get("/ready").json()["api"], "available")
        self.assertEqual(client.post("/scan/text", json={"text": "hello"}).status_code, 200)
        self.assertEqual(client.post("/scan/text", json={"text": "again"}).status_code, 429)


if __name__ == "__main__":
    unittest.main()
