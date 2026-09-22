# TruthLensAI Module 1 — Stage 10 Validation Report

## Test Environment

- Python: 3.13.6
- OS: Windows (workspace environment; detailed system information was unavailable to the non-administrative test session)
- CPU: not available to the test session
- Relevant packages: FastAPI 0.141.1, Pydantic 2.13.5, Pillow 12.3.0, pytest 9.1.1
- Network and external AI/threat-intelligence services: not used

## Regression Results

| Total | Passed | Failed | Skipped |
|------:|-------:|-------:|--------:|
| 80 | 80 | 0 | 0 |

The pre-Stage-10 baseline was 72 passed. Stage 10 adds eight deterministic validation tests. The final run produced four dependency deprecation warnings: FastAPI/Starlette's TestClient compatibility warning, AnyIO's `BlockingPortal` alias warning, and Starlette's deprecated HTTP 422 constant warning. They do not affect scan results.

## Modality Results

| Modality | Tests | Passed | Failed | Notes |
|----------|------:|-------:|-------:|-------|
| Text | 19 | 19 | 0 | Benign, phishing, scam, social-engineering, contracts, and determinism covered. |
| URL | 17 | 17 | 0 | Benign, synthetic suspicious patterns, malformed URL, contracts, and determinism covered. |
| Image/OCR | 9 | 9 | 0 | Deterministic OCR stubs confirm text-detector reuse; invalid/OCR-unavailable paths return UNKNOWN. |
| Audio/STT | 9 | 9 | 0 | Deterministic STT stubs confirm text-detector reuse; invalid/STT-unavailable paths return UNKNOWN. |
| Video | 9 | 9 | 0 | Frame/audio routing, aggregation, deduplication, and unavailable decoder paths covered with local stubs. |
| Multimodal | 10 | 10 | 0 | Bounded corroboration, source attribution, conflicts, deduplication, and reproducibility covered. |
| FastAPI | 7 | 7 | 0 | Health, all scan routes, validation, safe error mapping, and upload cleanup covered. |

Test counts overlap where a test validates an integration boundary across modalities; they are not additive.

## Threat Categories

- Phishing: synthetic account-suspension/password and OTP-style content produces relevant deterministic evidence and a non-benign classification.
- Scam: synthetic prize/payment content produces scam evidence and a non-benign classification.
- Social engineering: synthetic secrecy, pressure, and platform-move content produces relevant evidence and a non-benign classification.
- Suspicious URL: synthetic documentation-range IP, URL credentials, redirect, encoded path, credential path, and brand-like hostname patterns produce URL signals.
- Benign: ordinary messages and HTTPS URLs do not escalate to HIGH or CRITICAL without supporting evidence.

## Error Handling

Empty text and malformed API bodies return validation errors. Malformed URLs, invalid image/audio/video inputs, unavailable OCR/STT/video processing, and no assessable evidence remain structured `UNKNOWN` results rather than being treated as benign. Unsupported uploads are rejected with a 400 response. Detector exceptions are mapped to a structured 500 response without exposing internal exception text. Existing API tests verify temporary upload cleanup.

AI reasoning was verified as enrichment-only: provider output cannot change deterministic risk score, severity, or threat type. Existing AI tests cover unavailable and malformed provider output; the Stage 10 test also covers an otherwise valid provider response that attempts to supply conflicting assessment fields.

## Performance

Ten local samples per deterministic operation, measured with `time.perf_counter` on this environment:

| Operation | Average | Minimum | Maximum |
|-----------|--------:|--------:|--------:|
| Text scan | 0.109 ms | 0.100 ms | 0.144 ms |
| URL scan | 0.074 ms | 0.063 ms | 0.117 ms |
| Multimodal fusion | 0.073 ms | 0.059 ms | 0.149 ms |

Image/OCR, audio/STT, video decode, and live HTTP latency were not benchmarked with production dependencies because this Stage 10 environment intentionally has no configured local OCR/STT model path and does not download models. The deterministic media-routing behavior is covered using local stubs instead. These figures are local observations, not production SLAs.

## Known Limitations

- OCR depends on a locally installed/configured Tesseract executable.
- STT requires a local faster-whisper model path; scan-time model download is deliberately disabled.
- Video processing depends on local decoder support and the availability of assessable frame/audio evidence.
- No AI provider is configured by default; reasoning therefore remains deterministic fallback metadata.
- This validation does not establish production capacity, accuracy across real-world corpora, or service-level latency.

## Final Module Status

Module 1 passed Stage 10 validation in this local environment: the full 80-test suite is green, deterministic benchmark paths executed, API/error paths remain safe, and no core detection behavior was changed. It is suitable for the planned integration work, subject to the local OCR/STT/video and production-readiness limitations above.
