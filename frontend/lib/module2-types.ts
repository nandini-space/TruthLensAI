export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export interface ScanResult {
  scan_id: string;
  modality: "text" | "url" | "image" | "audio" | "video";
  timestamp: string;
  risk_score: number;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  threat_type: string;
  signals: Array<{ name: string; value: string; source: string; confidence?: number | null; metadata: Record<string, JsonValue> }>;
  explanation: string;
  extracted_entities: Array<{ entity_type: string; value: string; normalized_value?: string | null; confidence?: number | null; metadata: Record<string, JsonValue> }>;
  recommendation: string;
  provenance: { source: string; detector_id: string; detector_version?: string | null; processed_at: string; metadata: Record<string, JsonValue> };
  input_reference: { original_content?: string | null; reference_uri?: string | null; content_hash?: string | null; media_type?: string | null };
}

export interface Indicator { indicator_id: string; type: string; value: string; source: string; confidence?: number | null; context: Record<string, JsonValue>; }
export interface ThreatIntelResult { indicator: Indicator; reputation: string; confidence?: number | null; source: string; queried_at: string; status: string; findings: Array<{ source: string; category: string; description: string; confidence?: number | null }>; provider_reference?: string | null; metadata: Record<string, JsonValue>; }
export interface Incident { incident_id: string; scan_id: string; threat_type: string; severity: string; risk_score: number; confidence: number; status: "open" | "investigating" | "resolved"; created_at: string; updated_at: string; evidence_reference?: string | null; resolution_information?: string | null; }
export interface EvidencePack { evidence_id: string; scan_id: string; collected_at: string; scan_result: ScanResult; enriched_threat_result: { status: string; provider_sources: string[] }; }
export interface ForensicReport { report_id: string; incident_id: string; scan_id: string; threat_type: string; risk_score: number; severity: string; confidence: number; analysis: string; recommended_action: string; generated_at: string; indicators: Indicator[]; detected_signals: ScanResult["signals"]; }
export interface ResponseDecision { indicator_value: string; indicator_type: string; action: string; reason: string; reputation?: string | null; mode: string; }
export interface ActionRecord { action_id: string; action: string; reason: string; mode: string; would_execute: boolean; executed: boolean; status: string; timestamp: string; indicator: Indicator; }
export interface Module2Result { scan_result: ScanResult; indicators: Indicator[]; provider_results: ThreatIntelResult[]; threat_intelligence: ThreatIntelResult[]; enriched_threat_result: { status: string; provider_sources: string[] }; evidence_pack: EvidencePack; incident: Incident; forensic_report: ForensicReport; stix_bundle: JsonValue; response_decisions: ResponseDecision[]; action_records: ActionRecord[]; }
export interface Module2InvestigationPage { items: Module2Result[]; limit: number; offset: number; count: number; }
