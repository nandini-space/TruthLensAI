import type { ScanModality } from "./scan-result";

/**
 * Browser-only input state for the New Scan form.
 * This is not an HTTP contract and must be replaced or aligned when Module 1
 * publishes an authoritative submission endpoint.
 */
export type ScanSubmissionDraft =
  | {
      modality: "text" | "url";
      content: string;
    }
  | {
      modality: Exclude<ScanModality, "text" | "url">;
      file: File;
    };
