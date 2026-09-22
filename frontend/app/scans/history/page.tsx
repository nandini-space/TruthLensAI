import { ScanHistoryUnavailable } from "@/components/scan/ScanHistoryUnavailable";

export default function ScanHistoryPage() {
  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <header>
        <h2 className="text-2xl font-semibold tracking-tight text-slate-950">Scan History</h2>
        <p className="mt-2 text-sm text-slate-600">
          Review completed TruthLensAI scans when a backend history source is available.
        </p>
      </header>
      <ScanHistoryUnavailable />
    </div>
  );
}
