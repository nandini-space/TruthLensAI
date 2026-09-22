import { EmptyState } from "@/components/common/EmptyState";

interface ScanResultUnavailableProps {
  scanId: string;
}

export function ScanResultUnavailable({ scanId }: ScanResultUnavailableProps) {
  return (
    <div className="mx-auto max-w-2xl">
      <p className="mb-2 text-sm font-medium text-cyan-700">Scan Result</p>
      <EmptyState
        title="Scan result unavailable"
        description={
          <>
            <p>This scan result is not available through a configured frontend result source.</p>
            <p className="mt-3 break-all text-slate-600">Requested scan ID: {scanId}</p>
          </>
        }
        actions={[
          { label: "Start a new scan", href: "/scans/new" },
          { label: "View scan history", href: "/scans/history" },
        ]}
      />
    </div>
  );
}
