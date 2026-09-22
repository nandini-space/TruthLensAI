import type { ScanResult } from "../../lib/module2-types";

// Development-only sample matching backend.models.schemas.ScanResult exactly.
export const demoScanResult: ScanResult = {
  scan_id: "3ec8b7cd-fd13-442b-b624-387c2c3ae1ac", modality: "url", timestamp: "2026-09-22T12:00:00Z",
  risk_score: 84, severity: "high", confidence: 0.88, threat_type: "credential_phishing",
  signals: [{ name: "credential_request", value: "login", source: "demo_detector", confidence: 0.88, metadata: {} }],
  explanation: "Demo scan data for local workspace development.",
  extracted_entities: [{ entity_type: "domain", value: "demo-phish.example", normalized_value: "demo-phish.example", confidence: 0.88, metadata: {} }],
  recommendation: "Do not visit the destination; verify through a trusted channel.",
  provenance: { source: "module3b_demo", detector_id: "demo_only", detector_version: "1.0", processed_at: "2026-09-22T12:00:00Z", metadata: {} },
  input_reference: { reference_uri: "demo://module3b/sample-url", media_type: "text/uri-list" },
};
