# TruthLensAI Architecture

## 1. Project purpose

TruthLensAI is a planned AI-powered platform for detecting and responding to potential threats across text, URLs/domains, images/screenshots, audio/voice, and video. This document describes the intended architecture only; no detection engines or external integrations are implemented in this initial scaffold.

## 2. Workflow

The platform follows a single operational flow:

1. **DETECT** — receive a supported input and identify potential threat signals.
2. **EXPLAIN** — produce an understandable account of detected signals and confidence.
3. **ENRICH** — attach relevant context from approved intelligence sources.
4. **INVESTIGATE** — organize evidence for analyst review and correlation.
5. **RESPOND** — present response-oriented outputs and handoffs.

## 3. Module 1: Multimodal Detection

Future detection capabilities belong under `backend/detection/`. This module will provide modality-specific processing boundaries for text, URLs/domains, images/screenshots, audio/voice, and video. OCR, audio transcription, video frame/audio processing, and multimodal fusion are future work and are not implemented.

## 4. Module 2: Threat Intelligence + Investigation

`backend/intelligence/` is reserved for threat-intelligence adapters and normalization. `backend/incidents/` is reserved for future investigation-facing coordination. VirusTotal, community intelligence, STIX 2.1 sharing, and incident logic are deliberately outside the current implementation.

## 5. Module 3: Dashboard + Telegram

`frontend/` is reserved for the Next.js security dashboard, while Telegram interaction will be introduced at a later stage through a separate interface boundary. Neither UI is implemented in this project scaffold.

## 6. Shared data contracts

Future modules should exchange explicit, versioned contracts for input metadata, detection findings, explanations, enrichment records, investigation evidence, and response recommendations. Contracts should preserve provenance, timestamps, confidence, and source modality. Concrete schemas are intentionally deferred.

## 7. API boundaries

The FastAPI application in `backend/` is the service boundary for future clients and automation. At present, it exposes only `GET /health`. Future routes should validate requests, return documented contracts, and keep detection, intelligence, investigation, reporting, and integration concerns within their respective modules.

## 8. Database responsibilities

Supabase is planned as the persistence layer for future application data, including input metadata, findings, analyst-facing evidence, and audit-oriented records. No Supabase client, schema, migrations, or tables are included in this initial structure.
