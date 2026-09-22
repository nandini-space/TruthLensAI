# TruthLensAI Architecture

## 1. Project purpose

TruthLensAI is an AI-powered platform for assessing potential threats across
text, URLs/domains, images/screenshots, audio/voice, and video. The current
backend implements the canonical Module 1 → Module 2 contract and a
provider-neutral, dry-run investigation workflow; frontend and automation
integration remain future work.

## 2. Workflow

The platform follows a single operational flow:

1. **DETECT** — receive a supported input and identify potential threat signals.
2. **EXPLAIN** — produce an understandable account of detected signals and confidence.
3. **ENRICH** — attach relevant context from approved intelligence sources.
4. **INVESTIGATE** — organize evidence for analyst review and correlation.
5. **RESPOND** — present response-oriented outputs and handoffs.

## 3. Module 1: Multimodal Detection

`backend/detection/` provides modality-specific detection boundaries that
produce the canonical `ScanResult`. Module 2 consumes only that public contract,
not detection internals or storage.

## 4. Module 2: Threat Intelligence + Investigation

`backend/module2/` orchestrates existing intelligence normalization, evidence,
incident, report, STIX, response-audit, and repository components. Provider
adapters are optional and failures stay provider-neutral; response decisions are
strictly dry-run. The API supports investigation creation plus read-only single
and paginated persisted-result retrieval.

## 5. Module 3: Dashboard + Telegram

`frontend/` is reserved for the Next.js security dashboard, while Telegram interaction will be introduced at a later stage through a separate interface boundary. Neither UI is implemented in this project scaffold.

## 6. Shared data contracts

Future modules should exchange explicit, versioned contracts for input metadata, detection findings, explanations, enrichment records, investigation evidence, and response recommendations. Contracts should preserve provenance, timestamps, confidence, and source modality. Concrete schemas are intentionally deferred.

## 7. API boundaries

The FastAPI application exposes `GET /health`, `POST /api/module2/investigate`,
`GET /api/module2/investigations/{scan_id}`, and
`GET /api/module2/investigations`. Routes validate contracts, use the repository
boundary for persistence, and sanitize repository failures.

## 8. Database responsibilities

Supabase is an optional persistence adapter for completed Module 2 snapshots.
The migrations in `supabase/migrations/` define the investigations table with a
unique scan ID, JSONB payload, and collection timestamp for deterministic
history ordering. Tests use only deterministic in-memory or fake clients.
