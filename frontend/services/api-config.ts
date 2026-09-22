/**
 * Central configuration for the future TruthLensAI FastAPI client.
 * Request methods belong in this layer when backend integration begins.
 */
export interface ApiClientConfig {
  baseUrl: string;
}

export const apiClientConfig: ApiClientConfig = {
  baseUrl: process.env.NEXT_PUBLIC_API_BASE_URL ?? "",
};
