/** JSON-compatible metadata carried by Module 1 detection signals and entities. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Input modality supported by the canonical Module 1 scan result contract. */
export type ScanModality = "text" | "url" | "image" | "audio" | "video";

/** Detection severity, not an incident lifecycle status. */
export type ScanSeverity = "low" | "medium" | "high" | "critical";

export interface DetectionSignal {
  name: string;
  value: string;
  source: string;
  confidence: number | null;
  metadata: Record<string, JsonValue>;
}

export interface ExtractedEntity {
  entity_type: string;
  value: string;
  normalized_value: string | null;
  confidence: number | null;
  metadata: Record<string, JsonValue>;
}

/**
 * Frontend representation of the Module 1 canonical detection output.
 * UUID and date-time values are serialized as strings across the HTTP boundary.
 */
export interface ScanResult {
  scan_id: string;
  modality: ScanModality;
  risk_score: number;
  severity: ScanSeverity;
  confidence: number;
  threat_type: string;
  signals: DetectionSignal[];
  explanation: string;
  extracted_entities: ExtractedEntity[];
  recommendation: string;
}
