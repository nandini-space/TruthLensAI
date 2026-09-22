"""Unit tests for the Stage 9 HTTP boundary; no real detectors are invoked."""

import os
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.main import create_app
from backend.api.routes.detection import get_pipeline
from backend.detection.schemas import InputType, ScanRequest, ScanResult, Severity, Signal, ThreatType


class StubPipeline:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.requests: list[ScanRequest] = []
        self.upload_paths: list[str] = []

    def scan(self, request: ScanRequest) -> ScanResult:
        if self.fail:
            raise RuntimeError("detector unavailable")
        self.requests.append(request)
        if request.input_type in {InputType.IMAGE, InputType.AUDIO, InputType.VIDEO}:
            self.upload_paths.append(request.content)
            assert Path(request.content).is_file()
        return ScanResult(
            scan_id=request.scan_id, input_type=request.input_type, risk_score=82.0,
            severity=Severity.CRITICAL, threat_type=ThreatType.PHISHING, confidence=0.91,
            signals=[Signal(code="credential_request", description="Credentials requested.", source="stub")],
            explanation="Stub assessment.", recommendation="Verify independently.",
            metadata={"assessment_status": "completed", "detector": "stub"},
        )

    def fuse(self, results: list[ScanResult]) -> ScanResult:
        if self.fail:
            raise RuntimeError("fusion unavailable")
        strongest = results[0]
        return strongest.model_copy(update={"metadata": {"fusion_status": "completed", "fusion_marker": "preserved", "children": len(results)}})


class DetectionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pipeline = StubPipeline()
        self.app = create_app()
        self.app.dependency_overrides[get_pipeline] = lambda: self.pipeline
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.app.dependency_overrides.clear()

    def test_health(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "service": "TruthLensAI Detection API"})

    def test_text_serializes_existing_scan_result_without_changes(self) -> None:
        response = self.client.post("/scan/text", json={"text": "Verify your account"})
        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["risk_score"], 82.0)
        self.assertEqual(payload["threat_type"], "phishing")
        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["confidence"], 0.91)
        self.assertEqual(payload["signals"][0]["code"], "credential_request")
        self.assertIn("scan_id", payload)

    def test_empty_text_and_malformed_url_are_rejected(self) -> None:
        self.assertEqual(self.client.post("/scan/text", json={"text": ""}).status_code, 422)
        self.assertEqual(self.client.post("/scan/url", json={}).status_code, 422)
        self.assertEqual(self.client.post("/scan/url", json={"url": "not a url"}).status_code, 422)

    def test_url_is_routed_to_pipeline(self) -> None:
        response = self.client.post("/scan/url", json={"url": "https://example.com/login"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.pipeline.requests[0].input_type, InputType.URL)

    def test_missing_uploads_are_rejected(self) -> None:
        for endpoint in ("/scan/image", "/scan/audio", "/scan/video"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.client.post(endpoint).status_code, 422)

    def test_unsupported_upload_is_rejected_before_pipeline(self) -> None:
        response = self.client.post("/scan/image", files={"file": ("payload.gif", b"gif", "image/gif")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["error"], "unsupported_file_type")
        self.assertEqual(self.pipeline.requests, [])

    def test_upload_is_cleaned_after_detector_returns(self) -> None:
        response = self.client.post("/scan/audio", files={"file": ("speech.wav", b"wave", "audio/wav")})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.pipeline.upload_paths), 1)
        self.assertFalse(os.path.exists(self.pipeline.upload_paths[0]))

    def test_multimodal_uses_pipeline_fusion_and_preserves_metadata(self) -> None:
        response = self.client.post("/scan/multimodal", data={"text": "verify", "url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(self.pipeline.requests), 2)
        self.assertEqual(payload["metadata"]["fusion_marker"], "preserved")
        self.assertEqual(payload["risk_score"], 82.0)

    def test_empty_multimodal_request_is_rejected(self) -> None:
        response = self.client.post("/scan/multimodal")
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"]["error"], "missing_modalities")

    def test_detector_failure_returns_a_safe_structured_error(self) -> None:
        self.pipeline.fail = True
        response = self.client.post("/scan/text", json={"text": "anything"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"], {"error": "detection_failed", "detail": "The detection service could not process this input."})
