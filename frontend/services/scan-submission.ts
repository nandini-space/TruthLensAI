import type { ScanSubmissionDraft } from "@/types/scan-submission";

/**
 * Future boundary for the authoritative Module 1 scan-submission API.
 * No implementation is provided until that endpoint and payload contract exist.
 */
export interface ScanSubmissionService {
  submit(draft: ScanSubmissionDraft): Promise<void>;
}
