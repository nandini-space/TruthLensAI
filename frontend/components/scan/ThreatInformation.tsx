import type { ScanResult } from "@/types/scan-result";

import { SignalList } from "./SignalList";

interface ThreatInformationProps {
  result: Pick<ScanResult, "threat_type" | "signals">;
}

export function ThreatInformation({ result }: ThreatInformationProps) {
  return (
    <section aria-labelledby="threat-information-heading" className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h3 id="threat-information-heading" className="text-base font-semibold text-slate-950">
        Threat Information
      </h3>
      <div className="mt-4">
        <p className="text-sm text-slate-600">Threat type</p>
        <p className="mt-1 break-words text-lg font-medium text-slate-950">{result.threat_type}</p>
      </div>
      <div className="mt-6">
        <h4 className="text-sm font-semibold text-slate-900">Detected Signals</h4>
        <div className="mt-3">
          <SignalList signals={result.signals} />
        </div>
      </div>
    </section>
  );
}
