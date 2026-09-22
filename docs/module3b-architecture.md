# TruthLensAI Module 3B — Investigation Dashboard Architecture

## Scope and constraints

Module 3B is the future investigator-facing UI for incident review, evidence,
threat intelligence, timelines, analytics, forensic reports, and supported
exports. It consumes Module 1 detection output and the existing Module 2
orchestration boundary; it does not repeat detection, IOC extraction,
intelligence aggregation, lifecycle rules, report construction, STIX creation,
or response policy in the browser.

This is an architecture-only stage. No UI, API, or Module 1/2 business logic is
created here.

## Existing frontend architecture

`frontend/` currently contains only `.gitkeep`. There is no Next.js
application, route tree, component library, styling system, API utility, or
observable Module 3A implementation in this working tree. Module 3B must not
assume a framework, styling convention, or reusable component until the Module
3A branch is available.

The proposed structure below is intentionally a target layout for a future
Next.js application, subject to alignment with Module 3A's actual app router,
design system, authentication, and scan-result handoff.

## Existing Module 2 API contract

The only existing Module 2 HTTP endpoint is:

| Method | Path | Request | Response | Current behavior |
|---|---|---|---|---|
| POST | `/api/module2/investigate` | Canonical `backend.models.schemas.ScanResult` | `Module2Result` | Runs the in-memory, side-effect-free Module 2 workflow. |

No incident list, incident lookup, status-update, evidence lookup, analytics,
report download, or standalone STIX-export endpoint exists today.

### Request: canonical Module 1 scan result

`ScanResult` requires `scan_id`, `modality` (`text`, `url`, `image`, `audio`,
`video`), `timestamp`, `risk_score` (0–100), `severity` (`low`, `medium`,
`high`, `critical`), `confidence` (0–1), `threat_type`, `signals`,
`explanation`, `extracted_entities`, `recommendation`, `provenance`, and
`input_reference`. A signal has `name`, `value`, `source`, optional
`confidence`, and JSON `metadata`; an entity has `entity_type`, `value`,
optional `normalized_value`/`confidence`, and `metadata`. `input_reference`
contains textual `original_content` or a `reference_uri`, with optional content
hash and media type.

Module 3B receives this source evidence through the returned nested
`scan_result`; it should not construct or alter Module 1 findings.

### Response: `Module2Result`

The response fields are exactly:

| Field | UI use |
|---|---|
| `scan_result` | Detection summary, source/provenance, signals, entities, recommendation. |
| `indicators` | IOC table: `indicator_id`, `type`, `value`, `source`, optional confidence/context. |
| `provider_results` | Provider-level evidence and availability diagnostics. |
| `threat_intelligence` | Aggregated IOC intelligence, reputation/status/findings/source/reference/metadata. |
| `enriched_threat_result` | Enrichment timestamp, status, provider sources, and composed scan/IOC context. |
| `evidence_pack` | Immutable investigation snapshot: IDs, collected time, scan, and enrichment. |
| `incident` | Incident snapshot and lifecycle display. |
| `forensic_report` | Structured forensic report snapshot. |
| `stix_bundle` | JSON-ready STIX 2.1 bundle returned by the API. |
| `response_decisions` | Deterministic IOC policy recommendations; all current modes are dry run. |
| `action_records` | Non-executed response audit records. |

The API serializes the STIX bundle as JSON. It does not persist any of these
snapshots or perform an external security action.

## Proposed Module 3B routes and components

Future paths, to be placed under Module 3A's actual route convention:

```
frontend/
  app/
    investigations/page.tsx              # Incident Center
    investigations/[incidentId]/page.tsx # Incident Detail shell
    investigations/[incidentId]/evidence/page.tsx
    investigations/[incidentId]/intel/page.tsx
    investigations/[incidentId]/timeline/page.tsx
    investigations/[incidentId]/report/page.tsx
    analytics/page.tsx
  components/investigations/
    IncidentTable.tsx
    IncidentSummary.tsx
    EvidenceViewer.tsx
    IndicatorTable.tsx
    IntelligenceFindings.tsx
    InvestigationTimeline.tsx
    ResponseActions.tsx
    ForensicReportView.tsx
    StixExportPanel.tsx
  lib/
    module2-client.ts
    investigation-view-model.ts
```

`module2-client.ts` initially needs only `investigate(scanResult)`, posting the
canonical Module 1 contract to `/api/module2/investigate`. It must expose
structured validation/network failures to the caller and must not add browser
side provider calls. List/detail client functions are deferred until the API
gaps below are implemented.

## Data flow

```
Module 3A completed ScanResult
  -> POST /api/module2/investigate
  -> Module2Result (one in-memory snapshot)
  -> Module 3B view model
     -> incident / evidence / intelligence / timeline / report / export views
```

The Incident Detail is the shared composition point. It renders the returned
incident with the nested `evidence_pack` and `forensic_report`; its child views
receive references to this same immutable response object. Avoid duplicating
or re-deriving risk, severity, reputation, or actions in separate client state.

## Incident lifecycle display

Display detection severity separately from incident status. The existing
incident statuses are `open`, `investigating`, and `resolved`; valid domain
transitions are only `open → investigating → resolved`. Current Module 2 has a
pure Python transition function but **no HTTP status-update endpoint and no
persistence**. Therefore Module 3B may display the snapshot status and a
disabled/explanatory lifecycle control, but must not claim that a client-side
change updates an incident.

Incident fields: `incident_id`, `scan_id`, `threat_type`, `severity`,
`risk_score`, `confidence`, `status`, `created_at`, `updated_at`, optional
`evidence_pack`, `evidence_reference`, and `resolution_information`.

## Evidence and intelligence views

Evidence Viewer presents `evidence_id`, `scan_id`, `collected_at`, nested
source input/reference, detection signals, extracted entities, provenance,
normalized indicators, and enrichment status. It must respect
`input_reference`: binary media is referenced by URI and is not embedded in the
contract.

Threat Intelligence groups `threat_intelligence` by indicator. Each row shows
the normalized `reputation` (`malicious`, `suspicious`, `benign`, `unknown`, or
`unavailable`), `status` (`success`, `partial`, `unavailable`, `error`),
source, query time, optional confidence/reference, findings, and metadata.
Unavailable/error results are not benign and must be visually distinguished
from a benign reputation. Provider-level details may use `provider_results`;
the aggregate remains the primary investigator summary.

## Investigation timeline and analytics

There is no persisted event stream. A single-result timeline can be derived
without inventing events from existing timestamps: scan `timestamp`/
`provenance.processed_at`, evidence `collected_at`, enrichment `enriched_at`,
incident `created_at`/`updated_at`, report `generated_at`, intelligence
`queried_at`, and action-record `timestamp`. Entries should identify their
source field and omit unavailable timestamps.

Analytics can initially derive only in-memory aggregates over investigation
responses held by the UI session: counts by incident status/severity/threat
type/modality, risk-score distribution, IOC type/reputation/status counts,
provider availability, and dry-run action counts. Cross-session historical
analytics cannot be implemented correctly until persisted incident/report data
and a query endpoint exist.

## Forensic report and export flow

Render `forensic_report` directly: `report_id`, incident/scan IDs, threat and
risk assessment, original input reference, indicators, detected signals,
analysis, intelligence, recommended action, timestamp, and nested evidence/
incident snapshots. A future client-side print/download representation may be
created from this returned structured JSON only after UX decisions.

The response's `stix_bundle` is the sole currently supported export payload.
The UI can offer a download of that returned JSON, clearly labeling it STIX
2.1. It must not generate STIX itself and must not offer unsupported PDF, CSV,
or persistent report-export operations.

Response Decisions and Action Records must show `action`, `reason`, IOC,
reputation, and `mode`. All current records are dry run and `executed=false`;
no control may imply an actual block.

## Module 3A integration points

1. Accept the canonical Module 1 `ScanResult` after a completed scan, using the
   versioned contract in `backend.models.schemas`, not the older internal
   detector-specific response shape.
2. Provide a handoff CTA such as “Investigate” that invokes the sole Module 2
   client function.
3. Reuse Module 3A's eventual layout, tokens, navigation, error boundary,
   loading state, and scan-summary component only after their concrete paths
   and props exist.

## Module 2 dependencies and API gaps

Required later from Module 2; none should be duplicated by Module 3B:

| Needed UI capability | Missing API/persistence requirement |
|---|---|
| Incident Center/history | Persisted incident store plus list/filter/pagination endpoint. |
| Incident Detail by URL | Incident/evidence/report retrieval endpoint keyed by stable ID. |
| Lifecycle actions | Authorized status-transition endpoint using existing transition rules. |
| Evidence viewer after refresh | Persisted evidence storage and retrieval, including safe media-reference access policy. |
| Timeline/history | Persisted investigation/audit event query endpoint. |
| Analytics dashboard | Aggregation endpoint or documented queryable incident dataset. |
| Report regeneration/download | Explicit report generation/retrieval/export endpoints and content-type policy. |
| STIX export after refresh | STIX retrieval/export endpoint tied to persisted evidence/report. |

The current `POST /api/module2/investigate` is appropriate only for a newly
submitted, in-memory investigation. Its default VirusTotal adapter may use a
configured API key; UI integration must handle unavailable/partial enrichment
without treating it as a benign outcome.

## Testing strategy

- Unit-test view-model mapping for every enum, missing optional field, provider
  failure, no-IOC response, and dry-run action state.
- Mock the single HTTP endpoint at the contract boundary; fixture responses must
  come from `Module2Result` serialization, not invented shapes.
- Add component tests for severity vs. incident-status distinction, evidence
  provenance, unavailable intelligence, timeline ordering, and STIX download.
- Add end-to-end tests only once Module 3A establishes a frontend runtime and
  Module 2 provides persistence/list/detail APIs.
- Retain existing backend contract and API tests; this architecture stage makes
  no backend behavior changes.
