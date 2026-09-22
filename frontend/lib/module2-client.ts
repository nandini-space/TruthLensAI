import type { Module2InvestigationPage, Module2Result, ScanResult } from "./module2-types";

export class Module2ApiError extends Error {
  constructor(message: string, readonly status?: number) { super(message); this.name = "Module2ApiError"; }
}

const apiBaseUrl = () => (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

function isModule2Result(value: unknown): value is Module2Result {
  if (!value || typeof value !== "object") return false;
  const result = value as Partial<Module2Result>;
  return Boolean(result.incident && result.evidence_pack && result.forensic_report && Array.isArray(result.threat_intelligence) && Array.isArray(result.response_decisions) && "stix_bundle" in result);
}

function isInvestigationPage(value: unknown): value is Module2InvestigationPage {
  if (!value || typeof value !== "object") return false;
  const page = value as Partial<Module2InvestigationPage>;
  return Array.isArray(page.items) && page.items.every(isModule2Result)
    && typeof page.limit === "number" && typeof page.offset === "number" && typeof page.count === "number";
}

async function getPayload(path: string, fetcher: typeof fetch): Promise<unknown> {
  let response: Response;
  try { response = await fetcher(`${apiBaseUrl()}${path}`); }
  catch { throw new Module2ApiError("Unable to reach the investigation service. Check the API URL and try again."); }
  const payload: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const detail = payload && typeof payload === "object" && "detail" in payload ? String(payload.detail) : "The investigation request failed.";
    throw new Module2ApiError(detail, response.status);
  }
  return payload;
}

export async function listInvestigations(
  { limit = 20, offset = 0 }: { limit?: number; offset?: number } = {},
  fetcher: typeof fetch = fetch,
): Promise<Module2InvestigationPage> {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  const payload = await getPayload(`/api/module2/investigations?${query}`, fetcher);
  if (!isInvestigationPage(payload)) throw new Module2ApiError("The investigation service returned an unexpected list response.");
  return payload;
}

export async function getInvestigation(scanId: string, fetcher: typeof fetch = fetch): Promise<Module2Result> {
  const payload = await getPayload(`/api/module2/investigations/${encodeURIComponent(scanId)}`, fetcher);
  if (!isModule2Result(payload)) throw new Module2ApiError("The investigation service returned an unexpected response.");
  return payload;
}

export async function investigate(scanResult: ScanResult, fetcher: typeof fetch = fetch): Promise<Module2Result> {
  let response: Response;
  try {
    response = await fetcher(`${apiBaseUrl()}/api/module2/investigate`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(scanResult),
    });
  } catch {
    throw new Module2ApiError("Unable to reach the investigation service. Check the API URL and try again.");
  }
  const payload: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const detail = payload && typeof payload === "object" && "detail" in payload ? String(payload.detail) : "The investigation request failed.";
    throw new Module2ApiError(detail, response.status);
  }
  if (!isModule2Result(payload)) throw new Module2ApiError("The investigation service returned an unexpected response.", response.status);
  return payload;
}
