import { EmptyState } from "@/components/common/EmptyState";

/** Displayed only while no authoritative scan-history source is configured. */
export function ScanHistoryUnavailable() {
  return (
    <EmptyState
      title="Scan history unavailable"
      description="Historical scan data is not currently available through a configured backend history source. Previous scans will appear here once that source is available."
      actions={[{ label: "Start a new scan", href: "/scans/new" }]}
    />
  );
}
