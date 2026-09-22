import type { ScanResult } from "@/types/scan-result";

interface ScanResultHeaderProps {
  result: Pick<ScanResult, "scan_id" | "modality">;
}

export function ScanResultHeader({ result }: ScanResultHeaderProps) {
  return (
    <header className="space-y-3">
      <p className="text-sm font-medium text-cyan-700">Scan Result</p>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="text-2xl font-semibold tracking-tight text-slate-950">Detection summary</h2>
        <span className="w-fit rounded-full bg-slate-100 px-3 py-1 text-sm font-medium text-slate-700">
          Modality: {result.modality}
        </span>
      </div>
      <p className="break-all text-sm text-slate-600">Scan ID: {result.scan_id}</p>
    </header>
  );
}
