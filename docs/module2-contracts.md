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

## Forensic report generation

`backend.reports.forensic.build_forensic_report(incident, evidence_pack)`
creates a validated, deep-copied `ForensicReport` snapshot. The incident and
evidence must share a scan ID; when the incident has an embedded evidence pack
or evidence reference, it must identify the supplied evidence pack. Mismatches
raise `ValueError` and are never repaired.

The builder preserves the scan's threat/risk/severity/confidence, original input
reference, signals, explanation, recommendation, indicators, and threat
intelligence, including unknown and unavailable results. The incident lifecycle
state is retained in the nested incident without a transition. Report generation
is deterministic, side-effect free, and uses an independent UTC-aware generation
timestamp (optionally supplied for deterministic callers); it performs no
detection, intelligence query, lifecycle update, or response action.

## STIX 2.1 export

`backend.reports.stix.export_stix_bundle(evidence_pack, incident=None,
forensic_report=None)` returns a valid STIX 2.1 bundle using the `stix2`
library. Malicious or suspicious supported indicators map to STIX Indicator
patterns for IPv4 addresses, domains, URLs, email addresses, and valid MD5,
SHA-1, SHA-256, or SHA-512 hashes. Phone and `other` indicators are not
fabricated as unrelated STIX objects; unknown and unavailable intelligence also
does not create a malicious or suspicious STIX Indicator.

When supplied, an Incident becomes a STIX Incident with its TruthLensAI identity
in an external reference and its lifecycle/severity context in labels. It is
linked with `related-to` relationships only to exported indicator objects. A
supplied forensic report becomes a STIX Report that references the exported
objects. Export validates supplied scan/evidence/incident relationships, is
read-only, and performs no network request, detection, lifecycle transition, or
response action.

## IOC response decisions and dry-run blocking

`backend.response.decision.decide_response(evidence_pack, incident=None)`
creates one deterministic `ResponseDecision` per unique normalized indicator.
The only actions are `no_action` and `block`, and every Task 11 decision uses
explicit `dry_run` mode. IP, domain, URL, and hash indicators are eligible only
when existing intelligence explicitly reports `malicious`. Suspicious, benign,
unknown, unavailable, unsupported email/phone/other indicators, and conflicting
unaggregated provider results remain `no_action`; existing aggregator results
are used when present.

`backend.response.blocker.DryRunIOCBlocker` receives an already-created
decision and never makes a policy decision itself. For `block`, it returns
`would_block=true` and `executed=false`; for `no_action`, it returns both as
false. DRY_RUN is not an actual block: this layer makes no firewall, DNS,
endpoint, network, database, or external-service change.

## Response audit / action records

`backend.response.audit.build_action_record(decision, incident=None)` creates
an in-memory `ActionRecord` from a Task 11 `ResponseDecision`, optionally
checking and attaching the matching incident. It deep-copies the decision's
Indicator, action, reason, mode, and scan identity, assigns a UUID action ID,
and records a UTC-aware timestamp. `build_action_records(decisions, ...)`
preserves input order and returns one record per decision.

Action records describe response intent, not execution. A dry-run `block` has
`would_execute=true`, `executed=false`, and `not_executed` status; `no_action`
has `would_execute=false`, `executed=false`, and `skipped` status. Task 12
rejects any record marked executed and makes no persistence, network, firewall,
DNS, endpoint, or external-service change. The record is the in-memory boundary
for a future adapter, which is intentionally not implemented here.

## Module 2 orchestrator

`backend.module2.orchestrator.run_module2_investigation(scan_result, ...)`
coordinates the existing pipeline: ScanResult -> IOC extraction -> injected (or
default configured) providers -> aggregation -> evidence -> incident -> forensic
report -> STIX -> response decisions -> dry-run action records. It returns a
typed `Module2Result` containing each major snapshot, including raw provider
results and aggregated intelligence.

Provider exceptions are isolated as provider-neutral error results so other
providers and indicators continue to aggregation. A supplied incident is reused
only when its scan/evidence identity matches the newly generated evidence; its
lifecycle state is never changed. The orchestrator performs no direct network,
persistence, response, or security action. Provider network behavior remains
inside the pre-existing provider adapters, and all generated action records stay
dry-run with `executed=false`.

## Module 2 API Boundary

`POST /api/module2/investigate` is the in-memory integration boundary for the
Module 2 workflow. It accepts the canonical `ScanResult`, relies on FastAPI and
the existing Pydantic contract for request validation, delegates business logic
to `run_module2_investigation`, and returns the existing `Module2Result`.

```
HTTP Request
    ↓
ScanResult validation
    ↓
Module 2 Orchestrator
    ↓
Module2Result
    ↓
HTTP Response
```

When no persistence configuration is present, the endpoint remains in-memory.
When both existing Supabase settings are configured, it injects the repository
boundary into the orchestrator; the route itself makes no direct database call.
Response actions remain dry-run only; it does not perform a real
security-system action.

`GET /api/module2/investigations/{scan_id}` retrieves an already-persisted
`Module2Result` through that repository boundary. `scan_id` is a required
canonical UUID path parameter. On success it returns the existing complete
`Module2Result`, including its intelligence, evidence, incident, forensic
report, STIX bundle, and response/action-record snapshots. A valid but missing
ID returns HTTP 404 with a small sanitized error response; an invalid UUID is
rejected by the normal FastAPI path-parameter validation response. If
persistence is unconfigured or unavailable, it returns a sanitized HTTP 503.

This retrieval endpoint is strictly read-only: it performs only validation,
repository retrieval, and response serialization. It never re-runs the Module
2 pipeline, calls intelligence providers, extracts IOCs, creates or updates an
incident, generates reports or STIX, makes response decisions, creates action
records, or writes repository state.

`GET /api/module2/investigations` lists existing persisted investigations in a
small pagination envelope: `{ "items": [...], "limit": 20, "offset": 0,
"count": 0 }`. It accepts `limit` (default 20, minimum 1, maximum 100) and
`offset` (default 0, minimum 0); invalid values use FastAPI's normal validation
response. Empty history returns an empty `items` list and `count: 0`.

Pages are ordered by `EvidencePack.collected_at` descending (newest first), then
canonical `scan_id` descending for equal collection times. The repository uses
this ordering and applies `limit`/`offset`; Supabase performs the ordering and
range query in the database. A repository failure returns the same sanitized
HTTP 503 response as single-investigation retrieval. This endpoint is strictly
read-only and does not execute any Module 2 pipeline stage or repository write.
Filtering, search, user-selectable sorting, deletion, and update operations are
not part of this API.

## Verified investigation lifecycle

The offline integration lifecycle is verified as `POST /investigate` → complete
Module 2 investigation → repository persistence → `GET /investigations/{scan_id}`
→ `GET /investigations`. It verifies that canonical scan, evidence, incident,
report, response/action, intelligence, and STIX identities/logical values are
preserved across persistence and both retrieval forms. Repository snapshots keep
later mutations to original, single-retrieval, or history-list values from
altering stored investigations. Both GET endpoints are verified read-only: they
do not invoke investigation, providers, artifact generation, response logic, or
repository writes.

## Module 2 Repository Boundary

`backend.module2.repository.Module2InvestigationRepository` is a provider-neutral
boundary for saving and retrieving completed `Module2Result` snapshots. `save`
rejects duplicate canonical `scan_id` values rather than overwriting an existing
investigation. Lookup by scan ID (or incident ID) returns `None` when no result
is stored. Saved and retrieved values are independent deep-copy snapshots, so
caller mutations cannot affect repository state or later retrievals.

`list_investigations(limit=20, offset=0)` returns a bounded page of the same
independent snapshots, using the documented collection-time/scan-ID ordering.
Both repository implementations reject invalid or unbounded pagination values.

The repository preserves the existing scan, evidence, incident, report, and
action identities and rejects inconsistent result identities. Its
`InMemoryModule2Repository` implementation is deterministic and test-only: it
performs no external calls, database access, filesystem persistence, or
configuration lookup. The optional Supabase implementation uses the same
contract for configured runtime persistence.

## Supabase Repository Implementation

`SupabaseModule2Repository` implements the same repository contract for a
production persistence adapter. It uses the existing `SUPABASE_URL` and
`SUPABASE_SERVICE_ROLE_KEY` only when constructed through `from_environment`;
credentials are never stored in payloads or returned in repository errors. The
client may also be injected for application wiring and tests.

The required `public.module2_investigations` table is defined and evolved by the
`supabase/migrations/` scripts. It stores a
unique canonical `scan_id`, optional unique `incident_id`, and one JSONB
`payload` containing the complete serialized `Module2Result`, plus the existing
evidence collection timestamp used for database-level page ordering. Apply that SQL
through the Supabase SQL editor or the deployment migration workflow before
using this repository.

Serialization preserves the existing nested contracts, UUIDs, timestamps,
enums, response/action records, and the existing STIX bundle. Duplicate insert
failures become `DuplicateInvestigationError`; missing lookups return `None`;
malformed stored data and client failures raise repository-level errors without
revealing credentials. Supabase is not a fallback to the in-memory test store.
The orchestrator and API integrate it only when both required existing
Supabase settings are configured.

## Optional Persistence Integration

`run_module2_investigation(..., repository=...)` accepts the existing
`Module2InvestigationRepository` protocol. Without a repository it retains its
non-persistent behavior. With one, it first completes every investigation stage
and constructs the final `Module2Result`, then saves that complete result once
before returning it. Repository failures propagate; they are never replaced by
a successful result or an in-memory fallback.

The API provides a configured `SupabaseModule2Repository` only when both
existing Supabase settings are present. Duplicate saves become a sanitized HTTP
409 response and repository availability failures a sanitized HTTP 503 response.
The orchestrator remains provider-neutral and has no Supabase dependency.

## Security and Failure Hardening

Module 2 API request validation rejects malformed canonical scan payloads before
investigation. Existing provider failures, exceptions, and malformed provider
returns are isolated into non-benign provider-neutral results, allowing other
providers to contribute. Invalid provider failure/reputation combinations and
cross-artifact identity mismatches fail closed through the existing contracts.

Repository setup, retrieval, listing, unexpected persistence failures, and a
retrieval result with the wrong canonical scan identity return sanitized API
errors without database details or secrets. STIX export remains conservative and
does not serialize provider credentials; response decisions remain dry-run and
their blocker results are never executed. Persisted and retrieved snapshots are
isolated from caller mutation, and both retrieval endpoints remain read-only.
