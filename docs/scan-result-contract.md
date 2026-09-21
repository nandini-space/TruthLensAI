# ScanResult contract

`backend.models.schemas.ScanResult` is the one canonical normalized output from
Module 1 (Multimodal Detection) to Module 2 (Threat Intelligence and
Investigation). Module 1 creates it after detection and explanation; Module 2
imports it and must preserve `scan_id` while enriching it through separate
future contracts.

## Fields and meaning

- `scan_id`: UUID identity for one scan. It remains stable across the pipeline.
- `modality`: one of `text`, `url`, `image`, `audio`, or `video`.
- `timestamp`: when the scan result was created.
- `risk_score`: Module 1 risk assessment on the inclusive 0--100 scale.
- `severity`: `low`, `medium`, `high`, or `critical` detection severity.
- `confidence`: Module 1 confidence on the inclusive 0--1 scale.
- `threat_type`: extensible normalized threat classification.
- `signals`: structured machine-readable detection signals.
- `explanation`: human-readable rationale, separate from `signals`.
- `extracted_entities`: structured entities found by Module 1, before enrichment.
- `recommendation`: Module 1's detection-stage recommended action.
- `provenance`: source/channel, detector ID and version, processing time, and
  optional JSON metadata.
- `input_reference`: either reasonably sized textual `original_content`, or a
  `reference_uri` for the source input. Large/binary image, audio, and video
  content must be referenced, not embedded. `content_hash` may aid correlation.

`severity` is a detection classification only. It must never be used for incident
lifecycle state; future incident states such as open, investigating, and resolved
do not belong in this model.

Module 2 can rely on this contract for scan identity, detection context, source
provenance, and evidence reference. It must not mutate its meaning or add
enrichment, incident, evidence, report, VirusTotal, community-intelligence, or
STIX fields to `ScanResult`.
