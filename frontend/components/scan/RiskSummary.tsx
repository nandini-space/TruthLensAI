import type { ScanResult, ScanSeverity } from "@/types/scan-result";

interface RiskSummaryProps {
  result: Pick<ScanResult, "risk_score" | "severity" | "confidence">;
}

const severityStyles: Record<ScanSeverity, string> = {
  low: "bg-emerald-50 text-emerald-800",
  medium: "bg-amber-50 text-amber-800",
  high: "bg-orange-50 text-orange-800",
  critical: "bg-red-50 text-red-800",
};

export function RiskSummary({ result }: RiskSummaryProps) {
  return (
    <section aria-labelledby="risk-summary-heading" className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h3 id="risk-summary-heading" className="text-base font-semibold text-slate-950">
        Risk Summary
      </h3>
      <dl className="mt-4 grid gap-4 sm:grid-cols-3">
        <div>
          <dt className="text-sm text-slate-600">Risk score (0–100)</dt>
          <dd className="mt-1 text-2xl font-semibold text-slate-950">{result.risk_score}</dd>
        </div>
        <div>
          <dt className="text-sm text-slate-600">Severity</dt>
          <dd className="mt-2">
            <span className={`rounded-full px-3 py-1 text-sm font-semibold ${severityStyles[result.severity]}`}>
              {result.severity}
            </span>
          </dd>
        </div>
        <div>
          <dt className="text-sm text-slate-600">Confidence (0–1)</dt>
          <dd className="mt-1 text-2xl font-semibold text-slate-950">{result.confidence}</dd>
        </div>
      </dl>
    </section>
  );
}
