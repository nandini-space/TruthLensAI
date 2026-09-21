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

## VirusTotal provider

`backend.intelligence.virustotal.VirusTotalProvider` performs synchronous
VirusTotal v3 lookups for hash (`/files/{hash}`), domain (`/domains/{domain}`),
IPv4 (`/ip_addresses/{ip}`), and URL (`/urls/{base64url-id}`) indicators. URL
lookups use the base64url encoding of the normalized URL with trailing `=`
padding removed; the provider never submits URLs for scanning.

The provider reads `VIRUSTOTAL_API_KEY` through the existing settings layer, or
accepts a supplied key for application wiring. Email, phone, and other indicators
return `unavailable` without making a request. Missing keys, rate limits,
timeouts, connection failures, and malformed responses are also never benign.

For a successful response, nonzero `malicious` analysis statistics map to
`malicious`, then nonzero `suspicious` maps to `suspicious`. Explicit nonzero
`harmless` evidence with neither maps to `benign`; all-zero statistics map to
`unknown`, not benign. A 404 is a successful lookup with `unknown` reputation;
authentication, request, and server failures use `error` or `unavailable` with
`unavailable` reputation. Only normalized counts, an optional provider reference,
and a structured summary are retained—never the full provider response.

## Community-intelligence provider boundary

No concrete community-intelligence source is currently configured or specified
by this repository. `backend.intelligence.community.CommunityIntelProvider`
therefore exposes the common `lookup(indicator)` interface but makes no HTTP or
external-service call. It returns a provider-neutral `ThreatIntelResult` with
source `community_intelligence`, status `unavailable`, and reputation
`unavailable` for every indicator type.

This explicitly means community enrichment has not been performed; it is never a
benign verdict. A future configured source can replace this safe implementation
behind the same interface, using the existing `ThreatIntelResult` and
`ThreatIntelFinding` contracts without exposing provider-specific payloads.

## Threat-intelligence aggregation

`aggregate_threat_intelligence(indicators, provider_results)` returns one
provider-neutral `ThreatIntelResult` with source `threat_intelligence_aggregator`
for each unique normalized `(indicator type, indicator value)` supplied in
`indicators`. It can be placed directly in `EnrichedThreatResult.threat_intelligence`.
Provider results without a matching input indicator are ignored rather than being
attached arbitrarily.

The aggregate retains each provider result as a provider-status/reputation
summary and preserves its distinct findings. Exact duplicate provider results and
exact duplicate findings are removed using stable JSON representations. When
usable providers report different non-neutral reputations, the aggregate adds a
`reputation_conflict` finding without claiming that either provider is correct.

Among `success` and `partial` provider results, reputation is selected in this
order: `malicious`, `suspicious`, `benign`, then `unknown`. Thus stronger adverse
evidence wins while a benign result is used only when no malicious or suspicious
evidence exists. `unknown` and `unavailable` never produce benign. With no usable
provider result, including no results or all unavailable providers, the aggregate
is `unavailable`; a usable provider result with no usable reputation remains
`unknown`. Aggregate status is `success` if any provider succeeded, otherwise
`partial` if any was partial, `unavailable` when all are unavailable (or none
were supplied), and `error` for remaining all-error/mixed-error cases.

## Evidence packaging

`backend.incidents.evidence.build_evidence_pack(scan_result, indicators,
threat_intelligence)` creates an `EvidencePack` without provider calls, database
access, or extraction. It composes a deep-copied `ScanResult` with a newly built
`EnrichedThreatResult`, preserving original input/reference, risk, severity,
confidence, threat type, signals, explanation, entities, recommendation,
provenance, normalized indicators, and all provider-neutral intelligence
findings exactly as supplied.

The pack's `scan_id` is copied from `ScanResult.scan_id`; the nested contracts
enforce that same identity. The current `Indicator` and `ThreatIntelResult`
contracts carry no scan ID, so no additional identity is invented or rewritten.
Collection time is UTC and timezone-aware (or may be supplied as an aware time
for deterministic use); it is distinct from the original scan timestamp. The
builder deep-copies caller-owned models and lists, so later mutations do not
change the packaged snapshot. It does not reinterpret reputation or severity.

## Incident management

`backend.incidents.manager.create_incident(evidence_pack)` validates and
deep-copies an `EvidencePack`, then creates an `Incident` with the same scan ID,
the evidence ID as `evidence_reference`, and threat type/risk/severity/confidence
from the nested scan result. New incidents always start `open`. The incident ID
is deterministically derived from the evidence ID; no persistence is performed.

`update_incident_status(incident, status)` is a side-effect-free lifecycle
operation. Only `open → investigating` and `investigating → resolved` are valid;
same-state, skipped, and reopening transitions raise `ValueError`. Creation and
update timestamps are timezone-aware UTC and separate from detection/evidence
timestamps. Detection severity remains unchanged and independent of incident
lifecycle status.
