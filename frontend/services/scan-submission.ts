import type { ScanSubmissionDraft } from "@/types/scan-submission";
import type { ScanResult } from "@/types/scan-result";

/**
 * Future boundary for the authoritative Module 1 scan-submission API.
 * No implementation is provided until that endpoint and payload contract exist.
 */
export class ScanSubmissionError extends Error {
  constructor(message: string, readonly status?: number) { super(message); this.name = "ScanSubmissionError"; }
}

const apiBaseUrl = () => (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

function isScanResult(value: unknown): value is ScanResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Partial<ScanResult>;
  return typeof result.scan_id === "string" && typeof result.input_type === "string"
    && typeof result.severity === "string" && typeof result.threat_type === "string"
    && Array.isArray(result.signals) && typeof result.explanation === "string"
    && typeof result.recommendation === "string" && Boolean(result.entities);
}

/** Submit only to documented Module 1 scan endpoints. */
export async function submitScan(draft: ScanSubmissionDraft, fetcher: typeof fetch = fetch): Promise<ScanResult> {
  const endpoint = `/scan/${draft.modality}`;
  const options: RequestInit = { method: "POST" };
  if ("content" in draft) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(draft.modality === "url" ? { url: draft.content } : { text: draft.content });
  } else {
    const body = new FormData();
    body.append("file", draft.file);
    options.body = body;
  }
  let response: Response;
  try { response = await fetcher(`${apiBaseUrl()}${endpoint}`, options); }
  catch { throw new ScanSubmissionError("Unable to reach the detection service. Check the API URL and try again."); }
  const payload: unknown = await response.json().catch(() => undefined);
  if (!response.ok) throw new ScanSubmissionError("Scan failed. Please try again.", response.status);
  if (!isScanResult(payload)) throw new ScanSubmissionError("The detection service returned an unexpected response.", response.status);
  return payload;
}
