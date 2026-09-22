/** JSON-compatible metadata carried by Module 1 detection signals and entities. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Input modality supported by the Module 1 HTTP scan result contract. */
export type ScanModality = "text" | "url" | "image" | "audio" | "video";

/** Detection severity returned by Module 1, not an incident lifecycle status. */
export type ScanSeverity = "unknown" | "low" | "moderate" | "high" | "critical";

export interface DetectionSignal {
  code: string;
  description: string;
  source: string;
  details: Record<string, JsonValue>;
}

export interface ExtractedEntity {
  kind: string;
  value: string;
  context: string | null;
}

/**
 * Frontend representation of the existing Module 1 HTTP response.
 * UUID and date-time values are serialized as strings across the HTTP boundary.
 */
export interface ScanResult {
  scan_id: string;
  input_type: ScanModality;
  risk_score: number | null;
  severity: ScanSeverity;
  confidence: number | null;
  threat_type: string;
  signals: DetectionSignal[];
  explanation: string;
  entities: {
    urls: string[];
    domains: string[];
    email_addresses: string[];
    phone_numbers: string[];
    usernames: string[];
    indicators: ExtractedEntity[];
  };
  recommendation: string;
  metadata: Record<string, JsonValue>;
  created_at: string;
}
