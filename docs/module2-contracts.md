# Module 2 contracts

These are application-level contracts for the stages after the canonical
`backend.models.schemas.ScanResult`. They do not perform extraction, provider
queries, aggregation, persistence, incident operations, or report generation.

## Intelligence and enrichment

`Indicator` is a security-relevant observable that Module 2 has selected for
investigation; it is not automatically every `ScanResult.extracted_entities`
item. Its supported types are `ip`, `domain`, `url`, `hash`, `email`, `phone`,
and `other`.

`ThreatIntelResult` is a provider-neutral result for one indicator. It holds a
normalized reputation (`malicious`, `suspicious`, `benign`, `unknown`, or
`unavailable`), provider status (`success`, `partial`, `unavailable`, or
`error`), structured findings, and optional provider reference/metadata. An
`unavailable` or `error` status is constrained to `unknown` or `unavailable`
reputation, never `benign`.

`EnrichedThreatResult` composes the original `ScanResult` with selected
indicators, normalized intelligence results, enrichment status, timestamps, and
provider sources. Its `scan_id` must equal the nested scan result's ID.

## Evidence, incidents, and reports

`EvidencePack` composes the original `ScanResult` and its
`EnrichedThreatResult`, preserving their signals, entities, input reference,
risk, severity, confidence, explanation, provenance, indicators, and
intelligence without copying those fields.

`Incident` holds a future incident-management snapshot and may compose an
evidence pack or reference persisted evidence. `severity` remains the shared
detection severity (`low`, `medium`, `high`, `critical`); `status` is a distinct
incident lifecycle value (`open`, `investigating`, `resolved`).

`ForensicReport` is a structured future report payload. It references the
incident and evidence pack and contains the report's analysis, recommendation,
structured indicators, signals, and intelligence results. It does not generate
files or perform reporting.

Module 1 only produces `ScanResult`. Module 2 composes it into these contracts
without changing its fields or identity. Module 3 can later consume
`EnrichedThreatResult` without handling provider-specific response schemas.

## IOC extraction

`backend.intelligence.ioc_extractor.extract_indicators(scan_result)` examines
only `ScanResult.extracted_entities` and returns normalized `Indicator` objects.
It supports IPv4 addresses, domains, HTTP(S) URLs, MD5/SHA-1/SHA-256/SHA-512
hexadecimal hashes, email addresses, and conservatively formatted phone numbers.

Domains, emails, and hashes are lowercased. URLs preserve scheme, port, path,
query, and fragment while lowercasing the hostname; clear surrounding sentence
punctuation is removed. Phone formatting is reduced to digits while preserving a
leading `+`. Indicators deduplicate by normalized `(type, value)` in first-seen
order and receive a deterministic UUID based on that normalized observable.

Classification favors URL, email, IPv4, hash, phone, then domain, so a URL or
email is not reduced to a domain. The extractor skips known non-IOC entity types
and requires strict validation, which intentionally favors avoiding false
positives. Extraction supplies no reputation or maliciousness judgment.
