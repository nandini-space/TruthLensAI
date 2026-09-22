/** Dashboard route placeholder. Its UI is intentionally deferred to a later task. */
import { EmptyState } from "@/components/common/EmptyState";

export default function DashboardPage() {
  return (
    <EmptyState
      title="Dashboard unavailable"
      description="Dashboard data will appear when authoritative backend sources are configured."
      actions={[{ label: "Start a new scan", href: "/scans/new" }]}
    />
  );
}
