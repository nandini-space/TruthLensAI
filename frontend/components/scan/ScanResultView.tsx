import type { ScanResult } from "@/types/scan-result";

import { ExplanationCard } from "./ExplanationCard";
import { ExtractedEntities } from "./ExtractedEntities";
import { RecommendationCard } from "./RecommendationCard";
import { RiskSummary } from "./RiskSummary";
import { ScanResultHeader } from "./ScanResultHeader";
import { ThreatInformation } from "./ThreatInformation";

interface ScanResultViewProps {
  result: ScanResult;
}

/** Pure presentation for a canonical Module 1 ScanResult. */
export function ScanResultView({ result }: ScanResultViewProps) {
  return (
    <article className="mx-auto max-w-5xl space-y-6">
      <ScanResultHeader result={result} />
      <RiskSummary result={result} />
      <ThreatInformation result={result} />
      <ExplanationCard explanation={result.explanation} />
      <ExtractedEntities entities={result.extracted_entities} />
      <RecommendationCard recommendation={result.recommendation} />
    </article>
  );
}
