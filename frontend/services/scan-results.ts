import type { ScanResult } from "@/types/scan-result";

/**
 * Future boundary for the authoritative scan-result retrieval API.
 * No implementation is provided until Module 1 publishes a retrieval contract.
 */
export interface ScanResultService {
  getById(scanId: string): Promise<ScanResult | null>;
}
