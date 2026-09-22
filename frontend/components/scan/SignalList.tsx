import type { DetectionSignal } from "@/types/scan-result";

import { MetadataList } from "./MetadataList";

interface SignalListProps {
  signals: DetectionSignal[];
}

export function SignalList({ signals }: SignalListProps) {
  if (signals.length === 0) {
    return <p className="text-sm text-slate-600">No detection signals were returned.</p>;
  }

  return (
    <ul className="space-y-3">
      {signals.map((signal, index) => (
        <li key={`${signal.code}-${signal.source}-${index}`} className="rounded-lg border border-slate-200 p-4">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-slate-600">Signal</dt>
              <dd className="mt-1 break-words font-medium text-slate-950">{signal.code}</dd>
            </div>
            <div>
              <dt className="text-slate-600">Description</dt>
              <dd className="mt-1 break-words font-medium text-slate-950">{signal.description}</dd>
            </div>
            <div>
              <dt className="text-slate-600">Source</dt>
              <dd className="mt-1 break-words text-slate-800">{signal.source}</dd>
            </div>
          </dl>
          <MetadataList metadata={signal.details} />
        </li>
      ))}
    </ul>
  );
}
