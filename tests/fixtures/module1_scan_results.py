"""Canonical, deterministic examples of Module 1 ``ScanResult`` output."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from backend.models.schemas import (
    DetectionSignal,
    ExtractedEntity,
    InputReference,
    Modality,
    Provenance,
    ScanResult,
    Severity,
)


FIXTURE_TIME = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


def benign_text_scan() -> ScanResult:
    return ScanResult(
        scan_id=UUID("0f6f3917-87ee-45a1-9d96-5f798af5bf31"),
        modality=Modality.TEXT,
        timestamp=FIXTURE_TIME,
        risk_score=4,
        severity=Severity.LOW,
        confidence=0.98,
        threat_type="benign_content",
        signals=[DetectionSignal(name="benign-language", value="routine update", source="text-detector")],
        explanation="The text contains no detected phishing or fraud language.",
        extracted_entities=[ExtractedEntity(entity_type="organization", value="Example Services")],
        recommendation="No action is required.",
        provenance=Provenance(source="text-upload", detector_id="text-detector", processed_at=FIXTURE_TIME),
        input_reference=InputReference(original_content="Your routine service update is complete.", media_type="text/plain"),
    )


def malicious_url_scan() -> ScanResult:
    url = "https://secure-login.example.test/account?next=home"
    return ScanResult(
        scan_id=UUID("38e7ae51-0ef2-4e67-bc12-75fd2bea1afb"),
        modality=Modality.URL,
        timestamp=FIXTURE_TIME,
        risk_score=94,
        severity=Severity.HIGH,
        confidence=0.96,
        threat_type="credential_phishing",
        signals=[DetectionSignal(name="lookalike-domain", value="secure-login.example.test", source="url-detector")],
        explanation="The URL imitates a login page and requests account credentials.",
        extracted_entities=[ExtractedEntity(entity_type="url", value=url, normalized_value=url, confidence=0.99)],
        recommendation="Do not open the URL or submit credentials.",
        provenance=Provenance(source="url-upload", detector_id="url-detector", processed_at=FIXTURE_TIME),
        input_reference=InputReference(reference_uri=url, media_type="text/uri-list"),
    )


def malicious_ip_scan() -> ScanResult:
    ip_address = "198.51.100.42"
    return ScanResult(
        scan_id=UUID("2d3f845d-73a6-4b5d-8e74-6c0a704a2805"),
        modality=Modality.TEXT,
        timestamp=FIXTURE_TIME,
        risk_score=91,
        severity=Severity.HIGH,
        confidence=0.93,
        threat_type="command_and_control",
        signals=[DetectionSignal(name="suspicious-network-observable", value=ip_address, source="text-detector")],
        explanation="The message contains a known suspicious network address.",
        extracted_entities=[ExtractedEntity(entity_type="ip_address", value=ip_address, confidence=0.97)],
        recommendation="Investigate connections to the identified address.",
        provenance=Provenance(source="text-upload", detector_id="text-detector", processed_at=FIXTURE_TIME),
        input_reference=InputReference(original_content=f"Observed outbound connection to {ip_address}.", media_type="text/plain"),
    )


def no_extractable_ioc_scan() -> ScanResult:
    return ScanResult(
        scan_id=UUID("8dfa48b0-6a63-4fae-9a5c-02f7e1d2ee06"),
        modality=Modality.TEXT,
        timestamp=FIXTURE_TIME,
        risk_score=67,
        severity=Severity.MEDIUM,
        confidence=0.82,
        threat_type="social_engineering",
        signals=[DetectionSignal(name="urgent-language", value="act immediately", source="text-detector")],
        explanation="The message uses urgency but contains no extractable observable.",
        extracted_entities=[ExtractedEntity(entity_type="prose", value="Act immediately to avoid interruption.")],
        recommendation="Verify the request through an independent channel.",
        provenance=Provenance(source="text-upload", detector_id="text-detector", processed_at=FIXTURE_TIME),
        input_reference=InputReference(original_content="Act immediately to avoid interruption.", media_type="text/plain"),
    )


MODULE1_SCAN_FIXTURES = {
    "benign_text": benign_text_scan,
    "malicious_url": malicious_url_scan,
    "malicious_ip": malicious_ip_scan,
    "no_extractable_ioc": no_extractable_ioc_scan,
}
